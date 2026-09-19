"""
tests/test_worker_deployment.py
Security verification for Sentinel Worker Deployment Artifacts:
- Dockerfile non-root unprivileged user enforcement
- Dockerfile secret and network port isolation (outbound-only, no EXPOSE)
- .dockerignore exclusion of .env, .git, keys, tests, and UI code
- WorkerConfig deployment defaults (production_polling_enabled=False, test_mode=False)
- WorkerConfig validation of worker identity and resource limits
"""

import os
import unittest
import uuid

from worker.config import WorkerConfig


class TestWorkerDeployment(unittest.TestCase):
    """Verifies deployment configuration, container manifests, and safety defaults."""

    def test_01_dockerfile_security_hardening(self):
        """Verifies Dockerfile runs as unprivileged non-root user and exposes no inbound ports."""
        dockerfile_path = "Dockerfile"
        self.assertTrue(os.path.exists(dockerfile_path), "Dockerfile must exist in project root.")

        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Non-root user check
        self.assertIn("useradd", content, "Dockerfile must create an unprivileged user.")
        self.assertIn("USER sentinel", content, "Dockerfile must switch to non-root USER sentinel.")

        # Outbound-only: no public EXPOSE ports
        lines = [line.strip() for line in content.splitlines()]
        expose_lines = [line for line in lines if line.startswith("EXPOSE")]
        self.assertEqual(len(expose_lines), 0, "External worker must be outbound-only with 0 exposed inbound ports.")

        # Entrypoint check
        self.assertTrue(
            any('ENTRYPOINT ["python", "-m", "worker"]' in line for line in lines),
            "Dockerfile must use standard package entrypoint python -m worker."
        )

        # No secrets or .env copied
        self.assertNotIn(".env", content, "Dockerfile must never copy .env files.")
        self.assertNotIn(".pem", content, "Dockerfile must never copy .pem files.")
        self.assertNotIn(".key", content, "Dockerfile must never copy .key files.")

    def test_02_dockerignore_excludes_sensitive_files(self):
        """.dockerignore must strictly block secrets, git history, UI code, and tests."""
        dockerignore_path = ".dockerignore"
        self.assertTrue(os.path.exists(dockerignore_path), ".dockerignore must exist in project root.")

        with open(dockerignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        mandatory_excludes = [
            ".git",
            ".env",
            "*.pem",
            "*.key",
            "app/",
            "tests/",
            "data/",
        ]
        for pattern in mandatory_excludes:
            self.assertIn(pattern, content, f".dockerignore must exclude '{pattern}'")

    def test_03_default_configuration_safe_idle_state(self):
        """WorkerConfig defaults to idle state with production polling strictly disabled."""
        w_id = uuid.uuid4()
        config = WorkerConfig(worker_id=w_id)

        # Production polling MUST be False by default
        self.assertFalse(config.production_polling_enabled, "Production polling must be False by default.")
        self.assertFalse(config.test_mode, "Test mode must be False by default.")
        self.assertEqual(config.heartbeat_interval_seconds, 30)
        self.assertEqual(config.max_db_connections, 5)
        self.assertEqual(config.db_connect_timeout_seconds, 10)

    def test_04_config_from_env_defaults(self):
        """WorkerConfig.from_env defaults to idle state without accidental polling."""
        w_id = uuid.uuid4()
        env = {
            "SENTINEL_WORKER_ID": str(w_id),
            "SENTINEL_WORKER_DB_URL": "postgresql://sentinel_worker_daemon:pass@localhost:5432/db",
        }
        config = WorkerConfig.from_env(env)
        self.assertEqual(config.worker_id, w_id)
        self.assertFalse(config.production_polling_enabled)
        self.assertFalse(config.test_mode)

    def test_05_config_from_env_test_mode_opt_in(self):
        """Test mode requires explicit SENTINEL_WORKER_TEST_MODE=1 opt-in."""
        w_id = uuid.uuid4()
        env = {
            "SENTINEL_WORKER_ID": str(w_id),
            "SENTINEL_WORKER_TEST_MODE": "1",
        }
        config = WorkerConfig.from_env(env)
        self.assertTrue(config.test_mode)
        # Production polling still False
        self.assertFalse(config.production_polling_enabled)

    def test_06_config_from_env_invalid_worker_id(self):
        """Malformed worker ID raises ValueError."""
        env = {"SENTINEL_WORKER_ID": "not-a-valid-uuid"}
        with self.assertRaises(ValueError):
            WorkerConfig.from_env(env)

    def test_07_config_validation_requires_worker_id(self):
        """Runtime execution requires a non-empty worker_id."""
        config = WorkerConfig(worker_id=None)
        with self.assertRaises(ValueError):
            config.validate_for_runtime()
