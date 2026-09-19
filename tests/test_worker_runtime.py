"""
tests/test_worker_runtime.py
Rigorous unit and security tests for the external Sentinel worker runtime foundation.
Verifies configuration loading, operational bounds, credential masking, worker identity binding,
capability-token memory isolation, safe logging redaction, clean shutdown, and security invariants.
"""

import io
import logging
import os
import re
import unittest
import uuid
from unittest.mock import patch

from worker.config import (
    WorkerConfig,
    mask_db_url,
    MIN_LEASE_DURATION_SECONDS,
    MAX_LEASE_DURATION_SECONDS,
    DEFAULT_LEASE_DURATION_SECONDS,
)
from worker.identity import WorkerIdentity, CapabilityToken
from worker.logging import SafeLoggingFilter, get_worker_logger
from worker.db import MockWorkerDBClient, RoleVerificationError
from worker.lease import WorkerLeaseManager
from worker.runtime import SentinelWorkerDaemon, DaemonState


class TestWorkerConfig(unittest.TestCase):
    """Tests for WorkerConfig loading, validation, and redaction."""

    def test_01_default_config_safe_values(self):
        """Verify default configuration values and bounded limits."""
        cfg = WorkerConfig()
        self.assertIsNone(cfg.worker_id)
        self.assertIsNone(cfg.db_url)
        self.assertIsNone(cfg.private_key_pem)
        self.assertEqual(cfg.lease_duration_seconds, DEFAULT_LEASE_DURATION_SECONDS)
        self.assertGreaterEqual(cfg.lease_duration_seconds, MIN_LEASE_DURATION_SECONDS)
        self.assertLessEqual(cfg.lease_duration_seconds, MAX_LEASE_DURATION_SECONDS)

    def test_02_load_from_env_valid(self):
        """Verify loading valid configuration from environment dict."""
        w_id = str(uuid.uuid4())
        env = {
            "SENTINEL_WORKER_ID": w_id,
            "SENTINEL_WORKER_DB_URL": "postgresql://sentinel_worker_daemon:secret123@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres",
            "SENTINEL_LEASE_DURATION_SECONDS": "180",
            "SENTINEL_RENEWAL_EXTENSION_SECONDS": "90",
            "SENTINEL_RENEWAL_INTERVAL_SECONDS": "60",
        }
        cfg = WorkerConfig.from_env(env)
        self.assertEqual(str(cfg.worker_id), w_id)
        self.assertEqual(cfg.lease_duration_seconds, 180)
        self.assertEqual(cfg.renewal_extension_seconds, 90)
        self.assertEqual(cfg.renewal_interval_seconds, 60)

    def test_03_invalid_worker_id_fails_closed(self):
        """Verify malformed worker UUID fails closed with ValueError."""
        env = {"SENTINEL_WORKER_ID": "not-a-valid-uuid-12345"}
        with self.assertRaises(ValueError):
            WorkerConfig.from_env(env)

    def test_04_lease_duration_clamped_to_sql_bounds(self):
        """Verify lease durations outside bounds are clamped between 30 and 600 seconds."""
        # Too low -> clamped to MIN (30)
        cfg_low = WorkerConfig.from_env({"SENTINEL_LEASE_DURATION_SECONDS": "10"})
        self.assertEqual(cfg_low.lease_duration_seconds, MIN_LEASE_DURATION_SECONDS)

        # Too high -> clamped to MAX (600)
        cfg_high = WorkerConfig.from_env({"SENTINEL_LEASE_DURATION_SECONDS": "1000"})
        self.assertEqual(cfg_high.lease_duration_seconds, MAX_LEASE_DURATION_SECONDS)

    def test_05_db_url_password_masked_in_repr(self):
        """Verify database password in connection URL is never revealed in __repr__ or __str__."""
        raw_pw = "SuperSecretDbPassword!@#123"
        url = f"postgresql://sentinel_worker_daemon:{raw_pw}@aws-pooler.supabase.com:6543/postgres"
        cfg = WorkerConfig(worker_id=uuid.uuid4(), db_url=url)

        repr_str = repr(cfg)
        str_str = str(cfg)

        self.assertNotIn(raw_pw, repr_str)
        self.assertNotIn(raw_pw, str_str)
        self.assertIn("postgresql://sentinel_worker_daemon:***@aws-pooler.supabase.com:6543/postgres", repr_str)

    def test_06_private_key_redacted_in_repr(self):
        """Verify private key is never revealed in __repr__."""
        pk_prefix = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
        pk_suffix = "-----" + "END RSA PRIVATE KEY" + "-----"
        fake_pk = f"{pk_prefix}\nMIIEowIBAAKCAQEA...\n{pk_suffix}"
        cfg = WorkerConfig(worker_id=uuid.uuid4(), private_key_pem=fake_pk)
        repr_str = repr(cfg)
        self.assertNotIn("MIIEowIBAAKCAQEA", repr_str)
        self.assertIn("private_key=[SET]", repr_str)

    def test_07_validate_for_runtime_requires_worker_id(self):
        """Verify validate_for_runtime() raises ValueError when worker_id is missing."""
        cfg = WorkerConfig()
        with self.assertRaises(ValueError) as ctx:
            cfg.validate_for_runtime()
        self.assertIn("SENTINEL_WORKER_ID is mandatory", str(ctx.exception))


class TestWorkerIdentity(unittest.TestCase):
    """Tests for WorkerIdentity, CapabilityToken security, and tenant protection."""

    def setUp(self):
        self.worker_id = uuid.uuid4()
        self.identity = WorkerIdentity(self.worker_id)
        self.test_raw_token = os.urandom(32).hex()  # 64 hex chars

    def test_08_capability_token_creation_and_hash(self):
        """Verify CapabilityToken calculates SHA-256 matching PostgreSQL encode(sha256(decode(token, 'hex')), 'hex')."""
        import hashlib
        token = CapabilityToken(self.test_raw_token)
        expected_hash = hashlib.sha256(bytes.fromhex(self.test_raw_token)).hexdigest()
        self.assertEqual(token.token_hash, expected_hash)
        self.assertEqual(token.raw_token, self.test_raw_token)

    def test_09_capability_token_repr_redaction(self):
        """Verify CapabilityToken __repr__ and __str__ never output raw token or hash."""
        token = CapabilityToken(self.test_raw_token)
        repr_str = repr(token)
        str_str = str(token)

        self.assertNotIn(self.test_raw_token, repr_str)
        self.assertNotIn(self.test_raw_token, str_str)
        self.assertIn("[REDACTED_ACTIVE]", repr_str)

    def test_10_capability_token_constant_time_verification(self):
        """Verify constant-time hash verification succeeds on match and fails on mismatch."""
        token = CapabilityToken(self.test_raw_token)
        self.assertTrue(token.verify_hash(token.token_hash))
        self.assertFalse(token.verify_hash("0" * 64))
        self.assertFalse(token.verify_hash(""))
        self.assertFalse(token.verify_hash(None))

    def test_11_capability_token_clear_wipes_memory(self):
        """Verify clear() wipes raw token and hash from memory."""
        token = CapabilityToken(self.test_raw_token)
        token.clear()
        self.assertFalse(token.is_active())
        with self.assertRaises(ValueError):
            _ = token.raw_token
        with self.assertRaises(ValueError):
            _ = token.token_hash
        self.assertIn("[REDACTED_WIPED]", repr(token))

    def test_12_malformed_capability_token_rejected(self):
        """Verify capability tokens not conforming to 64 hex chars fail closed."""
        invalid_tokens = [
            "short",
            "not_hex" * 8,
            os.urandom(16).hex(),  # 32 chars
            os.urandom(64).hex(),  # 128 chars
            "",
            None,
        ]
        for inv in invalid_tokens:
            with self.assertRaises(ValueError):
                CapabilityToken(inv)

    def test_13_worker_identity_refuses_arbitrary_tenant_id(self):
        """Verify WorkerIdentity strictly rejects setting user_id or tenant_id."""
        with self.assertRaises(AttributeError):
            self.identity.user_id = str(uuid.uuid4())
        with self.assertRaises(AttributeError):
            self.identity.tenant_id = str(uuid.uuid4())
        with self.assertRaises(AttributeError):
            self.identity.mailbox_id = str(uuid.uuid4())

    def test_14_worker_identity_bind_and_clear_token(self):
        """Verify binding and clearing capability token on WorkerIdentity."""
        self.assertFalse(self.identity.has_token())
        self.identity.bind_token(self.test_raw_token)
        self.assertTrue(self.identity.has_token())
        self.assertEqual(self.identity.raw_token, self.test_raw_token)

        self.identity.clear_token()
        self.assertFalse(self.identity.has_token())
        self.assertIsNone(self.identity.raw_token)


class TestSafeLogging(unittest.TestCase):
    """Tests for SafeLoggingFilter redaction across all sensitive credential types."""

    def setUp(self):
        self.filter = SafeLoggingFilter()

    def test_15_redact_capability_token_and_hash(self):
        """Verify 64-hex capability tokens and hashes are redacted."""
        raw_token = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
        msg = f"Worker acquired lease with token {raw_token} successfully."
        redacted = self.filter.redact_message(msg)
        self.assertNotIn(raw_token, redacted)
        self.assertIn("[REDACTED_HEX_64]", redacted)

    def test_16_redact_rsa_private_key(self):
        """Verify RSA private key blocks are completely redacted from log messages."""
        pk_prefix = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
        pk_suffix = "-----" + "END RSA PRIVATE KEY" + "-----"
        priv_key = f"{pk_prefix}\nMIIEowIBAAKCAQEA0lX...sensitive...key...material\n{pk_suffix}"
        msg = f"Loading worker private key:\n{priv_key}"
        redacted = self.filter.redact_message(msg)
        self.assertNotIn("MIIEowIBAAKCAQEA0lX", redacted)
        self.assertIn("[REDACTED_RSA_PRIVATE_KEY]", redacted)

    def test_17_redact_database_connection_password(self):
        """Verify database password in connection string is redacted."""
        db_url = "postgresql://sentinel_worker_daemon:P@ssword123!@db.host.co:6543/postgres"
        msg = f"Connecting to {db_url}"
        redacted = self.filter.redact_message(msg)
        self.assertNotIn("P@ssword123!", redacted)
        self.assertIn("postgresql://sentinel_worker_daemon:***@db.host.co:6543/postgres", redacted)

    def test_18_redact_ciphertext_envelopes(self):
        """Verify v1 and v2 ciphertext envelopes are redacted."""
        v1_envelope = "v1:0123456789abcdef01234567:fedcba9876543210fedcba98765432101234"
        v2_envelope = "v2:k1:d3JhcHBlZF9kZWs=:bm9uY2U=:Y2lwaGVydGV4dA=="
        msg = f"Payload: {v1_envelope} and {v2_envelope}"
        redacted = self.filter.redact_message(msg)
        self.assertNotIn(v1_envelope, redacted)
        self.assertNotIn(v2_envelope, redacted)
        self.assertIn("[REDACTED_V1_CIPHERTEXT]", redacted)
        self.assertIn("[REDACTED_V2_CIPHERTEXT]", redacted)

    def test_19_logger_integration_redacts_stream(self):
        """Verify logger with SafeLoggingFilter redacts output in stream handler."""
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(SafeLoggingFilter())

        logger = logging.getLogger("test.redaction.logger")
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)

        secret_token = "f" * 64
        logger.info("Worker event token=%s", secret_token)
        output = stream.getvalue()

        self.assertNotIn(secret_token, output)
        self.assertIn("[REDACTED_HEX_64]", output)


class TestWorkerDaemonLifecycle(unittest.TestCase):
    """Tests for SentinelWorkerDaemon lifecycle, signal handling, and clean shutdown."""

    def setUp(self):
        self.worker_id = uuid.uuid4()
        self.user_id = uuid.uuid4()
        self.config = WorkerConfig(worker_id=self.worker_id)
        self.mock_db = MockWorkerDBClient()
        self.mock_db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")
        self.daemon = SentinelWorkerDaemon(self.config, db_client=self.mock_db)

    def test_20_daemon_start_and_stop_cleanly(self):
        """Verify daemon transitions STOPPED -> RUNNING -> STOPPED cleanly."""
        self.assertEqual(self.daemon.state, DaemonState.STOPPED)
        self.daemon.start()
        self.assertEqual(self.daemon.state, DaemonState.RUNNING)
        self.assertTrue(self.daemon.is_running)

        self.daemon.stop()
        self.assertEqual(self.daemon.state, DaemonState.STOPPED)
        self.assertFalse(self.daemon.is_running)

    def test_21_daemon_step_acquires_lease(self):
        """Verify single step iteration acquires lease and holds active token."""
        self.daemon.start()
        held = self.daemon.step()
        self.assertTrue(held)
        self.assertTrue(self.daemon.lease_manager.is_active())
        self.assertTrue(self.daemon.identity.has_token())
        self.daemon.stop()

    def test_22_daemon_stop_releases_lease_and_clears_token(self):
        """Verify stopping daemon releases lease and wipes capability token."""
        self.daemon.start()
        self.daemon.step()
        self.assertTrue(self.daemon.identity.has_token())

        self.daemon.stop()
        self.assertFalse(self.daemon.identity.has_token())
        self.assertFalse(self.daemon.lease_manager.is_active())
        # Confirm DB state is released
        w_state = self.mock_db.workers[str(self.worker_id)]
        self.assertIsNone(w_state["lease_owner"])
        self.assertIsNone(w_state["lease_token_hash"])

    def test_23_daemon_bounded_run_stops_at_max_iterations(self):
        """Verify run() stops cleanly when max_iterations is reached."""
        self.daemon.run(max_iterations=3, step_sleep_seconds=0.01)
        self.assertEqual(self.daemon.state, DaemonState.STOPPED)
        self.assertEqual(self.daemon._iteration_count, 3)

    def test_24_streamlit_does_not_import_worker(self):
        """Invariant: Streamlit source code must not import worker modules."""
        streamlit_app_path = os.path.join(os.path.dirname(__file__), "..", "app.py")
        if os.path.isfile(streamlit_app_path):
            with open(streamlit_app_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("import worker", content)
            self.assertNotIn("from worker", content)


if __name__ == "__main__":
    unittest.main()
