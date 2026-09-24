"""
tests/test_poll_once.py
Unit tests for the extracted WorkerService.poll_once() method.
Verifies single-iteration bounded execution for scheduled/ephemeral invocation.
"""

import unittest
from unittest.mock import patch, MagicMock
from worker.service import WorkerService


class TestWorkerPollOnce(unittest.TestCase):
    """Tests bounded single-iteration execution via WorkerService.poll_once()."""

    def test_01_poll_once_method_exists(self):
        """WorkerService has a callable poll_once classmethod."""
        self.assertTrue(hasattr(WorkerService, "poll_once"))
        self.assertTrue(callable(getattr(WorkerService, "poll_once")))

    @patch("worker.service.WorkerConfig.from_env")
    @patch.object(WorkerService, "step", return_value=True)
    def test_02_poll_once_executes_single_step(self, mock_step, mock_config_env):
        """poll_once executes start, step, stop once and returns completed status."""
        mock_config = MagicMock()
        mock_config.lease_duration_seconds = 30
        mock_config.renewal_interval_seconds = 10
        mock_config.renewal_extension_seconds = 30
        mock_config.production_polling_enabled = False
        mock_config.test_mode = False
        mock_config.worker_id = None
        mock_config_env.return_value = mock_config

        with patch.object(WorkerService, "start") as mock_start, \
             patch.object(WorkerService, "stop") as mock_stop:
            result = WorkerService.poll_once()

            mock_start.assert_called_once()
            mock_step.assert_called_once()
            mock_stop.assert_called_once()

            self.assertEqual(result.get("status"), "completed")
            self.assertTrue(result.get("step_result"))

    @patch("worker.service.WorkerConfig.from_env")
    @patch.object(WorkerService, "step", side_effect=RuntimeError("Simulated lease failure"))
    def test_03_poll_once_handles_exception_safely(self, mock_step, mock_config_env):
        """poll_once catches exceptions gracefully and guarantees service.stop() is called."""
        mock_config = MagicMock()
        mock_config.worker_id = None
        mock_config_env.return_value = mock_config

        with patch.object(WorkerService, "start") as mock_start, \
             patch.object(WorkerService, "stop") as mock_stop:
            result = WorkerService.poll_once()

            mock_start.assert_called_once()
            mock_step.assert_called_once()
            mock_stop.assert_called_once()

            self.assertEqual(result.get("status"), "error")
            self.assertIn("Simulated lease failure", result.get("error", ""))


if __name__ == "__main__":
    unittest.main()
