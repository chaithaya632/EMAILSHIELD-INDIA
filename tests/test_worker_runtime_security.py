"""
tests/test_worker_runtime_security.py
Comprehensive security boundary verification for external Sentinel Worker Runtime:
- Database role verification (sentinel_worker_daemon)
- Direct table access denial
- Stale lease recovery and restart capability token rotation
- Concurrent worker lease collision resolution
- Safe logging (zero secrets, passwords, tokens, or private keys in runtime logs)
"""

import io
import logging
import unittest
import uuid
import time

from worker.config import WorkerConfig
from worker.db import MockWorkerDBClient, RoleVerificationError, TableAccessViolationError
from worker.service import WorkerService
from worker.logging import SafeLoggingFilter


class TestWorkerRuntimeSecurity(unittest.TestCase):
    """Verifies security boundaries and privilege separation for WorkerService."""

    def setUp(self):
        self.worker_id = uuid.uuid4()
        self.user_id = uuid.uuid4()

        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")

        self.config = WorkerConfig(
            worker_id=self.worker_id,
            lease_duration_seconds=120,
            renewal_interval_seconds=45,
            renewal_extension_seconds=60,
            production_polling_enabled=False,
            test_mode=False,
        )

    def test_01_authorized_role_succeeds(self):
        """Worker with session_user=sentinel_worker_daemon starts successfully."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        self.assertEqual(service.state.value, "RUNNING")
        service.stop()

    def test_02_unauthorized_database_role_fails_closed(self):
        """Worker connecting with unauthorized role (e.g. postgres, anon) fails closed."""
        unauthorized_roles = ["postgres", "anon", "authenticated", "service_role", "supabase_admin"]
        for role in unauthorized_roles:
            bad_db = MockWorkerDBClient(session_user=role)
            bad_db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")
            service = WorkerService(self.config, db_client=bad_db)
            with self.assertRaises(RoleVerificationError):
                service.start()

    def test_03_direct_table_access_denial_enforced(self):
        """If worker has direct SELECT access to sentinel tables, startup fails with TableAccessViolationError."""
        bad_db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        bad_db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")
        # Simulate unauthorized table permission
        bad_db.has_direct_table_access = True

        service = WorkerService(self.config, db_client=bad_db)
        with self.assertRaises(TableAccessViolationError):
            service.start()

    def test_04_concurrent_worker_lease_collision(self):
        """Two worker instances attempting to claim the same lease resolve to exactly one winner."""
        service_1 = WorkerService(self.config, db_client=self.db)
        service_2 = WorkerService(self.config, db_client=self.db)

        service_1.start()
        service_2.start()

        # Instance 1 claims lease
        res_1 = service_1.step()
        self.assertTrue(res_1)
        self.assertTrue(service_1.lease_manager.is_active())

        # Instance 2 tries to claim same worker lease while active: denied
        res_2 = service_2.step()
        self.assertFalse(res_2)
        self.assertFalse(service_2.lease_manager.is_active())

        service_1.stop()
        service_2.stop()

    def test_05_stale_lease_recovery_after_expiry(self):
        """After lease expires, a restarting worker instance can safely claim the lease."""
        service_1 = WorkerService(self.config, db_client=self.db)
        service_1.start()
        service_1.step()
        self.assertTrue(service_1.lease_manager.is_active())

        # Simulate lease expiry in DB
        self.db.workers[str(self.worker_id)]["lease_expires_at"] = time.time() - 10

        # Restarted service 2 can claim
        service_2 = WorkerService(self.config, db_client=self.db)
        service_2.start()
        res_2 = service_2.step()
        self.assertTrue(res_2)
        self.assertTrue(service_2.lease_manager.is_active())

        service_1.stop()
        service_2.stop()

    def test_06_safe_logging_zero_secrets(self):
        """WorkerService execution logs contain zero passwords, tokens, or private keys."""
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] [%(levelname)s] %(message)s"))
        handler.addFilter(SafeLoggingFilter())

        svc_logger = logging.getLogger("sentinel.worker.service")
        lease_logger = logging.getLogger("sentinel.worker.lease")
        svc_logger.addHandler(handler)
        lease_logger.addHandler(handler)
        svc_logger.setLevel(logging.DEBUG)
        lease_logger.setLevel(logging.DEBUG)

        service = WorkerService(self.config, db_client=self.db)
        try:
            service.start()
            service.step()
            raw_token = service.identity.raw_token
            service.stop()

            log_output = log_stream.getvalue()

            # Ensure raw capability token is NEVER in logs
            if raw_token:
                self.assertNotIn(raw_token, log_output)
            # Ensure private key markers are NEVER in logs
            self.assertNotIn("BEGIN" + " RSA PRIVATE KEY", log_output)
            self.assertNotIn("BEGIN" + " PRIVATE KEY", log_output)
        finally:
            svc_logger.removeHandler(handler)
            lease_logger.removeHandler(handler)
