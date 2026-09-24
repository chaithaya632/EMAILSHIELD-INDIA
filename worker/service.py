"""
worker/service.py
Production Service Orchestrator for EMAILSHIELD INDIA Sentinel External Worker.

Operational & Security Guarantees:
1. Production Mailbox Polling: DISABLED by default. The worker starts in an idle state.
2. Least-Privilege Role: Connects strictly as sentinel_worker_daemon / sentinel_worker_role.
   Direct table access (SELECT, INSERT, UPDATE, DELETE) is verified as DENIED on startup.
3. Database Interactions: All operations use hardened PostgreSQL stored procedures (RPCs).
4. Lease Lifecycle: Bounded claims, automatic renewals, and guaranteed release on shutdown.
5. OS Signal Handling: Intercepts SIGINT and SIGTERM for graceful shutdown and token invalidation.
6. Best-effort memory cleanup: Clears sensitive capability token and credential references on shutdown.
7. Outbound-Only: Exposes zero public inbound network sockets or HTTP listener endpoints.
"""

import os
import json
import signal
import sys
import time
import uuid
from typing import Optional, Union, Callable, Dict, Any

from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.db import WorkerDBClient, MockWorkerDBClient, LocalWorkerDBClient, RoleVerificationError, TableAccessViolationError
from worker.lease import WorkerLeaseManager
from worker.credentials import WorkerCredentialService
from worker.runtime import DaemonState
from worker.health import WorkerHealthMonitor, WorkerHealthStatus
from worker.logging import get_worker_logger

logger = get_worker_logger("sentinel.worker.service")

RUNTIME_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local")
RUNTIME_STATUS_FILE = os.path.join(RUNTIME_DIR, "sentinel_worker_runtime.json")


def _record_worker_runtime(
    pid: Optional[int],
    worker_id: Optional[str],
    status: str,
    started_at: Optional[float] = None,
) -> None:
    """Atomically records worker process metadata and heartbeat for live runtime verification."""
    try:
        os.makedirs(RUNTIME_DIR, exist_ok=True)
        now = time.time()
        now_str = time.strftime("%H:%M:%S")
        data = {
            "pid": pid,
            "worker_id": str(worker_id) if worker_id else None,
            "status": status,
            "started_at": started_at or now,
            "last_heartbeat": now,
            "last_heartbeat_str": now_str,
        }
        tmp = RUNTIME_STATUS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, RUNTIME_STATUS_FILE)
    except Exception:
        pass


class WorkerService:
    """
    Production-style worker runtime service orchestrator.
    Manages identity, database security, lease loops, health telemetry, and safe idle state.
    """

    def __init__(
        self,
        config: WorkerConfig,
        db_client: Optional[Union[WorkerDBClient, MockWorkerDBClient]] = None,
        poller_factory: Optional[Callable[..., Any]] = None,
        credential_service: Optional[WorkerCredentialService] = None,
        checkpoint_store: Optional[Any] = None,
        forensic_agent: Optional[Any] = None,
        imap_adapter_factory: Optional[Callable[..., Any]] = None,
    ):
        config.validate_for_runtime()
        self.config = config
        self.identity = WorkerIdentity(config.worker_id)

        # Database client
        if db_client is not None:
            self.db_client = db_client
        elif self.config.db_url:
            self.db_client = WorkerDBClient(self.config)
        else:
            self.db_client = LocalWorkerDBClient()

        self.lease_manager = WorkerLeaseManager(self.identity, self.db_client)

        self.health_monitor = WorkerHealthMonitor(self)
        self.poller_factory = poller_factory
        self.credential_service = credential_service
        self.checkpoint_store = checkpoint_store
        self.forensic_agent = forensic_agent
        self.imap_adapter_factory = imap_adapter_factory

        # Initialize credential service from private key if available
        if self.credential_service is None and self.config.private_key_pem:
            try:
                from core.sentinel_crypto import WorkerKeyRing, load_private_key_from_pem
                pk = load_private_key_from_pem(self.config.private_key_pem)
                keyring = WorkerKeyRing(keys={"k1": pk})
                self.credential_service = WorkerCredentialService(self.identity, keyring, self.db_client)
            except Exception as e:
                logger.debug("Credential service auto-initialization deferred: %s", e)

        # Initialize checkpoint store if not provided
        if self.checkpoint_store is None:
            try:
                from worker.checkpoint import CheckpointStore
                self.checkpoint_store = CheckpointStore(self.db_client)
            except Exception:
                pass

        self.state = DaemonState.STOPPED
        self._should_stop = False
        self._iteration_count = 0

    @property
    def is_running(self) -> bool:
        return self.state == DaemonState.RUNNING and not self._should_stop

    def register_signal_handlers(self) -> None:
        """Registers OS signal handlers for graceful shutdown and lease release."""
        try:
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (ValueError, AttributeError):
            # Signal handling may fail on non-main threads or specific Windows environments
            pass

    def _handle_signal(self, signum: int, frame: object) -> None:
        logger.info("Received termination signal %d. Initiating graceful worker shutdown...", signum)
        self.stop()

    def start(self) -> None:
        """
        Starts the worker service.
        1. Connects to database.
        2. Verifies authorized session role (sentinel_worker_daemon / sentinel_worker_role).
        3. Verifies direct table privilege denial.
        4. Transitions to RUNNING state.
        5. Defaults to IDLE with production polling strictly DISABLED.
        """
        if self.state == DaemonState.RUNNING:
            return

        logger.info("Starting Sentinel Worker Service for worker %s...", self.identity.worker_id)
        self.state = DaemonState.STARTING
        self._should_stop = False

        # 1. Connect to database
        self.db_client.connect()

        # 2. Verify database role authorization
        sess_user, curr_user, _ = self.db_client.verify_session_identity()
        logger.info("Database role verified: session_user=%s, current_user=%s", sess_user, curr_user)

        # 3. Confirm least-privilege table privilege denial
        self.db_client.verify_table_privilege_denial()
        logger.info("Direct table privilege denial verified: worker has 0 direct table privileges.")

        self.state = DaemonState.RUNNING
        self.health_monitor.record_heartbeat()
        self._started_at = time.time()
        _record_worker_runtime(
            pid=os.getpid(),
            worker_id=str(self.identity.worker_id),
            status="RUNNING",
            started_at=self._started_at
        )

        logger.info(
            "Sentinel Worker Service is now RUNNING. "
            "PRODUCTION MAILBOX POLLING: %s, TEST MODE: %s",
            "ENABLED" if self.config.production_polling_enabled else "DISABLED",
            "ENABLED" if self.config.test_mode else "DISABLED"
        )

    def stop(self) -> None:
        """
        Gracefully shuts down the worker service.
        1. Transitions state to STOPPING.
        2. Releases held lease via RPC and clears capability token.
        3. Closes database connection.
        4. Performs best-effort memory cleanup.
        """
        if self.state in (DaemonState.STOPPING, DaemonState.STOPPED):
            return

        logger.info("Stopping Sentinel Worker Service for worker %s...", self.identity.worker_id)
        self.state = DaemonState.STOPPING
        self._should_stop = True

        # 1. Release held worker lease
        try:
            self.lease_manager.release_lease()
            logger.info("Worker lease released successfully.")
        except Exception as err:
            logger.error("Error releasing lease during worker shutdown: %s", type(err).__name__)

        # 2. Close database connection
        try:
            self.db_client.close()
            logger.info("Worker database connection closed.")
        except Exception as err:
            logger.debug("Error closing database connection: %s", err)

        # 3. Best-effort memory cleanup
        self.identity.clear()

        self.state = DaemonState.STOPPED
        _record_worker_runtime(
            pid=None,
            worker_id=str(self.identity.worker_id),
            status="STOPPED",
            started_at=getattr(self, "_started_at", None)
        )
        logger.info("Sentinel Worker Service STOPPED cleanly.")

    def step(self) -> bool:
        """
        Executes a single iteration of the worker control loop:
        1. Verifies/claims lease if unleased or expired.
        2. Renews lease if expiration threshold is approaching.
        3. Emits heartbeat telemetry.
        4. Invariant: Remains IDLE unless explicit test mode or authorized polling is active.
        """
        self._iteration_count += 1

        # 1. Check / acquire lease
        if not self.lease_manager.is_active():
            acquired = self.lease_manager.acquire_lease(self.config.lease_duration_seconds)
            if not acquired:
                logger.debug("Lease not acquired on iteration %d.", self._iteration_count)
                return False

        # 2. Check renewal threshold
        remaining = self.lease_manager.time_until_expiry()
        if remaining < self.config.renewal_interval_seconds:
            logger.info("Renewing lease (remaining: %ds, threshold: %ds)...", int(remaining), self.config.renewal_interval_seconds)
            renewed = self.lease_manager.renew_lease(self.config.renewal_extension_seconds)
            if not renewed:
                logger.warning("Lease renewal failed on iteration %d.", self._iteration_count)
                return False

        # 3. Record heartbeat
        self.health_monitor.record_heartbeat()
        _record_worker_runtime(
            pid=os.getpid(),
            worker_id=str(self.identity.worker_id),
            status="RUNNING",
            started_at=getattr(self, "_started_at", None)
        )


        # 4. Controlled polling dispatch
        if self.config.production_polling_enabled:
            # Per-mailbox authorized polling
            # Invariant: Polling is allowed strictly when:
            # global worker available + user explicitly connects mailbox + mailbox active + valid lease + valid credential
            if not self.lease_manager.is_active():
                logger.debug("Cannot poll: Worker lease is not active.")
                return False

            interval = getattr(self.config, "poll_interval_seconds", 1.0)
            now = time.time()
            last_poll_end = getattr(self, "_last_poll_end_time", 0.0)
            if now - last_poll_end < interval and last_poll_end > 0.0:
                return True

            poll_start = time.time()
            if self.poller_factory:
                try:
                    poller = self.poller_factory()
                    if poller:
                        poller.poll()
                except Exception as err:
                    logger.warning("Poller factory execution error: %s", err)
            elif self.credential_service and self.checkpoint_store:
                try:
                    from worker.poller import MailboxPoller
                    from core.agent import AutonomousForensicAgent
                    from core.classifier import MLClassifier

                    forensic = self.forensic_agent
                    if forensic is None:
                        try:
                            forensic = AutonomousForensicAgent(MLClassifier())
                        except Exception:
                            forensic = None

                    poller = MailboxPoller(
                        config=self.config,
                        identity=self.identity,
                        lease_manager=self.lease_manager,
                        credential_service=self.credential_service,
                        checkpoint_store=self.checkpoint_store,
                        synthetic_server=None,
                        imap_adapter_factory=self.imap_adapter_factory,
                        forensic_agent=forensic
                    )
                    res = poller.poll()
                    logger.info(
                        "Production poll executed: status=%s, processed=%d",
                        res.get("status"), res.get("processed_count", 0)
                    )
                except Exception as poll_err:
                    err_type = type(poll_err).__name__
                    err_msg = str(poll_err)
                    logger.warning("Production mailbox polling encountered error: %s (%s)", err_type, err_msg)
            else:
                logger.debug("Production polling idle: credential service or checkpoint store not initialized.")

            poll_end = time.time()
            poll_duration = poll_end - poll_start
            next_poll = poll_end + interval
            self._last_poll_end_time = poll_end
            self._last_poll_time = poll_start
            logger.info(
                "SAFE_TIMING_TELEMETRY: poll_start_timestamp=%.3f, poll_end_timestamp=%.3f, poll_duration=%.3f, next_poll_timestamp=%.3f",
                poll_start, poll_end, poll_duration, next_poll
            )
        elif self.config.test_mode and self.poller_factory:
            # Controlled synthetic test mode
            interval = getattr(self.config, "poll_interval_seconds", 1.0)
            now = time.time()
            last_poll_end = getattr(self, "_last_poll_end_time", 0.0)
            if now - last_poll_end < interval and last_poll_end > 0.0:
                return True

            poll_start = time.time()
            try:
                poller = self.poller_factory()
                if poller:
                    poller.poll()
            except Exception as err:
                logger.warning("Test mode poll cycle error: %s", err)

            poll_end = time.time()
            poll_duration = poll_end - poll_start
            next_poll = poll_end + interval
            self._last_poll_end_time = poll_end
            self._last_poll_time = poll_start
            logger.info(
                "SAFE_TIMING_TELEMETRY: poll_start_timestamp=%.3f, poll_end_timestamp=%.3f, poll_duration=%.3f, next_poll_timestamp=%.3f",
                poll_start, poll_end, poll_duration, next_poll
            )

        return True

    def run(self, max_iterations: Optional[int] = None, step_sleep_seconds: Optional[float] = None) -> None:
        """Runs the service loop until interrupted or max_iterations reached."""
        if step_sleep_seconds is None:
            interval = getattr(self.config, "poll_interval_seconds", 1.0)
            step_sleep_seconds = min(0.2, interval / 2.0 if interval > 0 else 0.2)
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

    def get_health_status(self) -> WorkerHealthStatus:
        """Returns the current operational health status."""
        return self.health_monitor.get_status()

    @classmethod
    def poll_once(cls, config: Optional[WorkerConfig] = None) -> dict:
        """Execute exactly one poll cycle and exit.

        Designed for scheduled/ephemeral invocation (e.g. cron, Cloud Run Jobs).
        Uses the same config, credential, IMAP, forensic, and checkpoint logic
        as the persistent worker — no code duplication.

        Returns:
            dict with 'status' and 'step_result' keys.
        """
        if config is None:
            config = WorkerConfig.from_env()

        if config.worker_id is None:
            proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            wid_path = os.path.join(proj_root, "data", "local", "sentinel_worker_id.txt")
            if os.path.exists(wid_path):
                try:
                    with open(wid_path, "r", encoding="utf-8") as f:
                        wid_str = f.read().strip()
                    if wid_str:
                        config.worker_id = uuid.UUID(wid_str)
                except Exception:
                    pass
            if config.worker_id is None:
                config.worker_id = uuid.uuid4()

        service = cls(config=config)
        service.start()
        try:
            result = service.step()
            return {"status": "completed", "step_result": result}
        except Exception as err:
            logger.error("poll_once encountered error: %s", err)
            return {"status": "error", "error": str(err)}
        finally:
            service.stop()

    @classmethod
    def run_cli(cls) -> None:
        """CLI entrypoint for running the worker service."""
        try:
            config = WorkerConfig.from_env()
            if config.worker_id is None:
                proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                wid_path = os.path.join(proj_root, "data", "local", "sentinel_worker_id.txt")
                if os.path.exists(wid_path):
                    try:
                        with open(wid_path, "r", encoding="utf-8") as f:
                            wid_str = f.read().strip()
                        if wid_str:
                            config.worker_id = uuid.UUID(wid_str)
                    except Exception:
                        pass
                if config.worker_id is None:
                    from worker.db import LocalWorkerDBClient
                    loc = LocalWorkerDBClient()
                    if loc.workers:
                        first_wid = next(iter(loc.workers.keys()))
                        config.worker_id = uuid.UUID(first_wid)
                    else:
                        new_wid = uuid.uuid4()
                        loc.seed_worker(new_wid, uuid.uuid4(), desired_state="RUNNING")
                        loc._save_to_disk()
                        config.worker_id = new_wid
                        try:
                            os.makedirs("data/local", exist_ok=True)
                            with open("data/local/sentinel_worker_id.txt", "w", encoding="utf-8") as f:
                                f.write(str(new_wid))
                        except Exception:
                            pass
            if "--once" in sys.argv:
                res = cls.poll_once(config)
                print(json.dumps(res))
                return

            service = cls(config)
            service.run()
        except KeyboardInterrupt:
            pass
        except Exception as err:
            logger.critical("Fatal error starting worker service: %s", err)
            sys.exit(1)

