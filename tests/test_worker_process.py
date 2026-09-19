"""
tests/test_worker_process.py
Verification of Worker Service Process Lifecycle & Isolation:
- WorkerService startup, step, and clean termination
- Idle state enforcement (0 mailboxes polled by default)
- Controlled test-mode dispatch
- Streamlit process isolation (Streamlit is never imported or executed)
- Outbound-only design (zero public network listeners)
"""

import sys
import unittest
import uuid
from unittest.mock import MagicMock

from worker.config import WorkerConfig
from worker.db import MockWorkerDBClient
from worker.service import WorkerService
from worker.runtime import DaemonState


class TestWorkerProcess(unittest.TestCase):
    """Verifies worker process execution, state transitions, and isolation."""

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

    def test_01_service_startup_and_running_state(self):
        """WorkerService starts cleanly, connects DB, verifies role and table denial, enters RUNNING."""
        service = WorkerService(self.config, db_client=self.db)
        self.assertEqual(service.state, DaemonState.STOPPED)

        service.start()
        self.assertEqual(service.state, DaemonState.RUNNING)
        self.assertTrue(service.is_running)

        service.stop()
        self.assertEqual(service.state, DaemonState.STOPPED)
        self.assertFalse(service.is_running)

    def test_02_service_step_lease_lifecycle(self):
        """WorkerService step claims lease and records heartbeat."""
        service = WorkerService(self.config, db_client=self.db)
        service.start()

        # Step 1: claims lease
        res = service.step()
        self.assertTrue(res)
        self.assertTrue(service.lease_manager.is_active())

        # Check heartbeat recorded
        health = service.get_health_status()
        self.assertTrue(health.lease_active)
        self.assertEqual(health.state, "RUNNING")

        service.stop()

    def test_03_default_idle_state_does_not_poll_mailboxes(self):
        """Default startup has production_polling_enabled=False; step executes zero mailbox polls."""
        mock_poller = MagicMock()
        mock_factory = MagicMock(return_value=mock_poller)

        service = WorkerService(self.config, db_client=self.db, poller_factory=mock_factory)
        service.start()

        # Execute multiple steps
        for _ in range(3):
            service.step()

        # Poller factory must NOT have been invoked because production polling is disabled
        mock_factory.assert_not_called()
        mock_poller.poll.assert_not_called()

        service.stop()

    def test_04_controlled_test_mode_executes_poller(self):
        """When test_mode=True, step invokes the configured test poller factory."""
        test_config = WorkerConfig(
            worker_id=self.worker_id,
            lease_duration_seconds=120,
            production_polling_enabled=False,
            test_mode=True,
        )
        mock_poller = MagicMock()
        mock_factory = MagicMock(return_value=mock_poller)

        service = WorkerService(test_config, db_client=self.db, poller_factory=mock_factory)
        service.start()

        service.step()
        mock_factory.assert_called_once()
        mock_poller.poll.assert_called_once()

        service.stop()

    def test_05_bounded_run_stops_at_max_iterations(self):
        """run(max_iterations=3) terminates cleanly and stops the service."""
        service = WorkerService(self.config, db_client=self.db)
        service.run(max_iterations=3, step_sleep_seconds=0.01)

        self.assertEqual(service.state, DaemonState.STOPPED)
        self.assertEqual(service._iteration_count, 3)

    def test_06_streamlit_isolation_in_service(self):
        """WorkerService does not import streamlit or expose UI components."""
        import subprocess
        # Verify in a clean Python process that importing worker.service never imports streamlit
        result = subprocess.run(
            [sys.executable, "-c", "import worker.service; import sys; sys.exit(0 if 'streamlit' not in sys.modules else 1)"],
            capture_output=True
        )
        self.assertEqual(result.returncode, 0, "Importing worker.service must never pull in streamlit.")

        import glob
        worker_files = glob.glob("worker/**/*.py", recursive=True)
        for wf in worker_files:
            with open(wf, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.assertNotIn("import streamlit", content, f"{wf} must not import streamlit")
            self.assertNotIn("from streamlit", content, f"{wf} must not import streamlit")

    def test_07_outbound_only_no_inbound_listener(self):
        """WorkerService does not create server sockets or listen on network ports."""
        import socket
        orig_bind = socket.socket.bind
        bind_calls = []

        def tracked_bind(sock_self, *args, **kwargs):
            bind_calls.append((sock_self, args, kwargs))
            return orig_bind(sock_self, *args, **kwargs)

        with unittest.mock.patch("socket.socket.bind", side_effect=tracked_bind):
            service = WorkerService(self.config, db_client=self.db)
            service.start()
            service.step()
            service.stop()

        self.assertEqual(len(bind_calls), 0, "Worker service must never bind an inbound server socket.")
