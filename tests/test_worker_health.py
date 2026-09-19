"""
tests/test_worker_health.py
Verification of Worker Health Telemetry and Secret Omission:
- Health status metrics collection (worker_id, state, uptime, lease, db)
- Heartbeat timestamp tracking
- is_healthy() evaluation
- Strict secret omission (zero capability tokens, private keys, passwords in health dumps)
"""

import unittest
import uuid
import time

from worker.config import WorkerConfig
from worker.db import MockWorkerDBClient
from worker.service import WorkerService
from worker.health import WorkerHealthMonitor, WorkerHealthStatus


class TestWorkerHealth(unittest.TestCase):
    """Verifies worker health telemetry and security boundaries."""

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

    def test_01_health_status_fields(self):
        """Worker health status accurately reflects runtime state."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        service.step()

        health = service.get_health_status()
        self.assertIsInstance(health, WorkerHealthStatus)
        self.assertEqual(health.worker_id, str(self.worker_id))
        self.assertEqual(health.state, "RUNNING")
        self.assertTrue(health.lease_active)
        self.assertGreater(health.lease_expires_in_seconds, 0)
        self.assertFalse(health.production_polling_enabled)
        self.assertFalse(health.test_mode)
        self.assertGreaterEqual(health.uptime_seconds, 0)

        service.stop()

    def test_02_heartbeat_timestamp_advancement(self):
        """record_heartbeat updates the last_heartbeat timestamp."""
        service = WorkerService(self.config, db_client=self.db)
        monitor = service.health_monitor

        initial_heartbeat = monitor.last_heartbeat_iso
        time.sleep(0.01)
        monitor.record_heartbeat()
        updated_heartbeat = monitor.last_heartbeat_iso

        self.assertGreaterEqual(updated_heartbeat, initial_heartbeat)

    def test_03_is_healthy_evaluation(self):
        """is_healthy() returns True when RUNNING + connected, False when STOPPED."""
        service = WorkerService(self.config, db_client=self.db)
        self.assertFalse(service.health_monitor.is_healthy())

        service.start()
        self.assertTrue(service.health_monitor.is_healthy())

        service.stop()
        self.assertFalse(service.health_monitor.is_healthy())

    def test_04_zero_secrets_in_health_dumps(self):
        """Health telemetry dictionary and repr contain zero sensitive credentials or keys."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()
        service.step()

        health = service.get_health_status()
        health_dict = health.to_dict()
        health_repr = repr(health)

        # Forbidden secret keys / patterns
        forbidden_substrings = [
            "raw_token",
            "capability_token",
            "private_key",
            "master_key",
            "password",
            "BEGIN" + " RSA PRIVATE KEY",
            "secret",
        ]

        for forbidden in forbidden_substrings:
            self.assertNotIn(forbidden, health_dict.keys(), f"'{forbidden}' must not be a key in health dict.")
            self.assertNotIn(forbidden, health_repr.lower(), f"'{forbidden}' must not appear in health repr.")

        # Ensure held token is never in dict values
        held_token = service.identity.raw_token
        if held_token:
            self.assertNotIn(held_token, str(health_dict))
            self.assertNotIn(held_token, health_repr)

        service.stop()
