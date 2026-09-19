"""
worker/runtime.py
External Sentinel Worker Runtime Daemon for EMAILSHIELD INDIA.
Manages daemon lifecycle, lease maintenance loop, OS signal handling,
bounded execution, and graceful shutdown with lease release.

CRITICAL INVARIANT FOR PHASE 6A:
Zero mailbox polling, zero IMAP connections, zero alert dispatching.
Runtime foundation and lease security verification only.
"""

import signal
import sys
import time
from enum import Enum
from typing import Optional, Union

from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.db import WorkerDBClient, MockWorkerDBClient
from worker.lease import WorkerLeaseManager
from worker.logging import get_worker_logger

logger = get_worker_logger("sentinel.worker.runtime")


class DaemonState(Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"


class SentinelWorkerDaemon:
    """
    Core external worker daemon process.
    Operates independently from Streamlit and web servers.
    """
    def __init__(
        self,
        config: WorkerConfig,
        db_client: Optional[Union[WorkerDBClient, MockWorkerDBClient]] = None
    ):
        config.validate_for_runtime()
        self.config = config
        self.identity = WorkerIdentity(config.worker_id)
        
        # Initialize DB client
        if db_client is not None:
            self.db_client = db_client
        else:
            self.db_client = WorkerDBClient(self.config)

        self.lease_manager = WorkerLeaseManager(self.identity, self.db_client)
        self.state = DaemonState.STOPPED
        self._should_stop = False
        self._iteration_count = 0

    @property
    def is_running(self) -> bool:
        return self.state == DaemonState.RUNNING and not self._should_stop

    def register_signal_handlers(self) -> None:
        """Registers OS signal handlers for clean, graceful lease release on shutdown."""
        try:
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (ValueError, AttributeError):
            # Signal handling may not be supported on non-main threads
            pass

    def _handle_signal(self, signum: int, frame: object) -> None:
        logger.info("Received signal %d. Initiating graceful worker shutdown...", signum)
        self.stop()

    def start(self) -> None:
        """Starts worker daemon and establishes database connection."""
        if self.state == DaemonState.RUNNING:
            return

        logger.info("Starting Sentinel Worker Daemon for worker %s...", self.identity.worker_id)
        self.state = DaemonState.STARTING
        self._should_stop = False

        # Connect to DB and verify least-privilege boundary
        self.db_client.connect()
        self.state = DaemonState.RUNNING
        logger.info("Sentinel Worker Daemon is now RUNNING.")

    def stop(self) -> None:
        """Gracefully stops worker daemon, releases lease, and closes connection."""
        if self.state in (DaemonState.STOPPING, DaemonState.STOPPED):
            return

        logger.info("Stopping Sentinel Worker Daemon for worker %s...", self.identity.worker_id)
        self.state = DaemonState.STOPPING
        self._should_stop = True

        # 1. Release active lease and wipe capability token from memory
        try:
            self.lease_manager.release_lease()
        except Exception as e:
            logger.error("Error releasing lease during shutdown: %s", type(e).__name__)

        # 2. Close DB connection
        try:
            self.db_client.close()
        except Exception:
            pass

        self.state = DaemonState.STOPPED
        logger.info("Sentinel Worker Daemon STOPPED cleanly.")

    def step(self) -> bool:
        """
        Executes a single iteration of the worker control loop:
        1. Verifies/acquires lease if unleased or expired.
        2. Renews lease if expiration threshold is approaching.
        3. Phase 6A: Does NOT poll mailboxes or connect to IMAP.
        Returns True if worker holds an active lease.
        """
        self._iteration_count += 1

        if not self.lease_manager.is_active():
            # Attempt to claim lease
            acquired = self.lease_manager.acquire_lease(self.config.lease_duration_seconds)
            if not acquired:
                logger.debug("Lease not acquired on iteration %d.", self._iteration_count)
                return False

        # Check renewal threshold (renew when remaining time < renewal_interval)
        remaining = self.lease_manager.time_until_expiry()
        if remaining < self.config.renewal_interval_seconds:
            logger.info("Lease remaining time (%ds) below threshold (%ds). Renewing...", int(remaining), self.config.renewal_interval_seconds)
            renewed = self.lease_manager.renew_lease(self.config.renewal_extension_seconds)
            if not renewed:
                logger.warning("Lease renewal failed on iteration %d.", self._iteration_count)
                return False

        # Invariant: Phase 6A boundary - zero mailbox polling
        return True

    def run(self, max_iterations: Optional[int] = None, step_sleep_seconds: float = 1.0) -> None:
        """
        Runs the worker execution loop up to max_iterations (or indefinitely).
        Cleanly stops and releases lease upon exit.
        """
        self.register_signal_handlers()
        self.start()

        try:
            iterations = 0
            while self.is_running:
                self.step()
                iterations += 1
                if max_iterations is not None and iterations >= max_iterations:
                    logger.info("Reached maximum iterations (%d). Stopping.", max_iterations)
                    break
                
                # Sleep in short increments for prompt shutdown responsiveness
                slept = 0.0
                while slept < step_sleep_seconds and self.is_running:
                    time.sleep(min(0.2, step_sleep_seconds - slept))
                    slept += 0.2
        finally:
            self.stop()
