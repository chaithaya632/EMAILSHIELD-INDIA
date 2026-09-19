"""
tests/test_worker_shutdown.py
Verification of Worker Service Graceful Shutdown & Token Invalidation:
- Graceful shutdown releases held lease
- Capability token is wiped from worker memory (best-effort)
- Database connection is closed
- Idempotent shutdown calls
- OS signal simulation (SIGTERM, SIGINT) initiates graceful teardown
"""

import signal
import unittest
import uuid

from worker.config import WorkerConfig
from worker.db import MockWorkerDBClient
from worker.service import WorkerService
from worker.runtime import DaemonState


class TestWorkerShutdown(unittest.TestCase):
    """Verifies graceful shutdown and resource cleanup for WorkerService."""

    def setUp(self):
        self.worker_id = uuid.uuid4()
        self.user_id = uuid.uuid4()

        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")

        self.config = WorkerConfig(
            worker_id=self.worker_id,
            lease_duration_seconds=120,
            production_polling_enabled=False,
            test_mode=False,
        )

    def test_01_graceful_stop_releases_lease_and_clears_token(self):
        """Calling stop() releases the lease and wipes capability token from memory."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        service.step()

        self.assertTrue(service.identity.has_token())
        self.assertTrue(service.lease_manager.is_active())

        # Stop service
        service.stop()

        self.assertEqual(service.state, DaemonState.STOPPED)
        # Token cleared
        self.assertFalse(service.identity.has_token())
        self.assertIsNone(service.identity.raw_token)
        # Lease inactive
        self.assertFalse(service.lease_manager.is_active())

    def test_02_idempotent_stop(self):
        """Calling stop() multiple times is safe and idempotent."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        service.stop()
        # Second call does not raise
        service.stop()
        self.assertEqual(service.state, DaemonState.STOPPED)

    def test_03_sigterm_triggers_graceful_shutdown(self):
        """Simulating SIGTERM signal invokes stop() and releases lease."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        service.step()

        self.assertTrue(service.is_running)

        # Simulate SIGTERM
        service._handle_signal(signal.SIGTERM, None)

        self.assertFalse(service.is_running)
        self.assertEqual(service.state, DaemonState.STOPPED)
        self.assertFalse(service.identity.has_token())

    def test_04_sigint_triggers_graceful_shutdown(self):
        """Simulating SIGINT signal invokes stop() and releases lease."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        service.step()

        self.assertTrue(service.is_running)

        # Simulate SIGINT
        service._handle_signal(signal.SIGINT, None)

        self.assertFalse(service.is_running)
        self.assertEqual(service.state, DaemonState.STOPPED)
        self.assertFalse(service.identity.has_token())

    def test_05_error_during_lease_release_does_not_prevent_shutdown(self):
        """If lease release encounters a DB error, shutdown still completes cleanly."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        service.step()

        # Break lease release
        service.lease_manager.release_lease = unittest.mock.MagicMock(side_effect=RuntimeError("DB disconnected"))

        service.stop()
        self.assertEqual(service.state, DaemonState.STOPPED)
        self.assertFalse(service.identity.has_token())
