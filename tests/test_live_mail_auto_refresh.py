"""
tests/test_live_mail_auto_refresh.py
Validation suite for Live Mail Analysis automatic refresh, public key loading,
credential encryption, tenant isolation, and counter stability.
"""

import os
import unittest
import uuid
import time
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa

from core.sentinel_crypto import (
    load_public_key_from_env,
    load_private_key_from_env,
    encrypt_credential_asymmetric,
    decrypt_credential_asymmetric,
    KeyNotFoundError,
    CONTEXT_MAILBOX,
)
from core.sentinel_stats import (
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    reset_user_sentinel_stats,
    get_sentinel_worker_runtime,
)
from core.sentinel_control import (
    connect_user_sentinel_mailbox,
    upsert_user_checkpoint,
    get_user_checkpoint,
    get_user_worker,
)


class TestLiveMailAutoRefreshAndCrypto(unittest.TestCase):
    """Verifies public key loading, encryption, auto-refresh telemetry, and isolation."""

    def setUp(self):
        self.test_user_id = str(uuid.uuid4())
        self.test_mailbox_id = str(uuid.uuid4())
        self.test_worker_id = str(uuid.uuid4())
        reset_user_sentinel_stats(self.test_user_id, self.test_mailbox_id)

    def tearDown(self):
        reset_user_sentinel_stats(self.test_user_id, self.test_mailbox_id)

    def test_01_public_key_loads_and_parses(self):
        """Worker public key loads and parses as RSA public key."""
        pub_key = load_public_key_from_env()
        self.assertIsInstance(pub_key, rsa.RSAPublicKey)
        self.assertEqual(pub_key.key_size, 2048)

    def test_02_missing_public_key_fails_closed(self):
        """Missing worker public key fails closed with KeyNotFoundError."""
        with patch.dict(os.environ, {"SENTINEL_WORKER_PUBLIC_KEY": ""}, clear=False):
            with patch("core.sentinel_crypto.os.path.isfile", return_value=False):
                with patch("worker.imap_client._lookup_local_env_var", return_value=None):
                    with self.assertRaises(KeyNotFoundError):
                        load_public_key_from_env("NON_EXISTENT_KEY_VAR_12345")

    def test_03_credential_encryption_roundtrip(self):
        """In-memory synthetic credential encryption and decryption round-trip."""
        pub_key = load_public_key_from_env()
        priv_key = load_private_key_from_env()
        synthetic_secret = "synthetic-test-password-123"

        envelope = encrypt_credential_asymmetric(
            plaintext=synthetic_secret,
            public_key=pub_key,
            user_id=self.test_user_id,
            purpose=CONTEXT_MAILBOX,
        )
        self.assertTrue(envelope.startswith("v2:"))

        decrypted = decrypt_credential_asymmetric(
            envelope=envelope,
            private_key=priv_key,
            user_id=self.test_user_id,
            purpose=CONTEXT_MAILBOX,
        )
        self.assertEqual(decrypted, synthetic_secret)

    def test_04_tampered_tenant_fails_decryption(self):
        """Envelope bound to user A fails closed if decrypted for user B."""
        pub_key = load_public_key_from_env()
        priv_key = load_private_key_from_env()

        envelope = encrypt_credential_asymmetric(
            plaintext="secret",
            public_key=pub_key,
            user_id=self.test_user_id,
            purpose=CONTEXT_MAILBOX,
        )
        other_user_id = str(uuid.uuid4())
        with self.assertRaises(Exception):
            decrypt_credential_asymmetric(
                envelope=envelope,
                private_key=priv_key,
                user_id=other_user_id,
                purpose=CONTEXT_MAILBOX,
            )

    def test_05_telemetry_counter_stability_on_repeated_reads(self):
        """Repeated UI reads do NOT increment or mutate telemetry counters."""
        record_user_sentinel_poll(
            user_id=self.test_user_id,
            mailbox_id=self.test_mailbox_id,
            arrived=2,
            analysed=2,
            clean=2,
            suspicious=0,
            high_critical=0,
            last_uid=105,
            poll_time_str="11:00:00",
        )

        for _ in range(10):
            stats = get_user_sentinel_stats(
                user_id=self.test_user_id,
                mailbox_id=self.test_mailbox_id,
            )
            self.assertEqual(stats["emails_arrived"], 2)
            self.assertEqual(stats["emails_analysed"], 2)
            self.assertEqual(stats["clean"], 2)
            self.assertEqual(stats["last_processed_uid"], 105)

    def test_06_tenant_telemetry_isolation(self):
        """User A cannot see User B's telemetry metrics."""
        user_b = str(uuid.uuid4())
        record_user_sentinel_poll(
            user_id=self.test_user_id,
            mailbox_id=self.test_mailbox_id,
            arrived=5,
            analysed=5,
            last_uid=200,
        )

        stats_b = get_user_sentinel_stats(user_id=user_b, mailbox_id="none")
        self.assertEqual(stats_b["emails_arrived"], 0)
        self.assertEqual(stats_b["emails_analysed"], 0)
        self.assertEqual(stats_b["last_processed_uid"], 0)

    def test_07_worker_runtime_state_reflects_stopped(self):
        """When worker record is stopped, runtime correctly reports STOPPED."""
        worker_rec = {
            "id": self.test_worker_id,
            "actual_state": "STOPPED",
            "desired_state": "STOPPED",
            "lease_owner": None,
            "lease_expires_at": None,
        }
        with patch("core.sentinel_stats.os.path.exists", return_value=False):
            rt = get_sentinel_worker_runtime(worker_rec=worker_rec)
            self.assertFalse(rt["worker_process_alive"])
            self.assertFalse(rt["worker_poll_loop_active"])
            self.assertEqual(rt["status"], "STOPPED")

    def test_08_worker_runtime_state_reflects_running_lease(self):
        """When worker record has active lease in Supabase, runtime reports RUNNING."""
        import datetime
        future_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)
        worker_rec = {
            "id": self.test_worker_id,
            "actual_state": "RUNNING",
            "desired_state": "RUNNING",
            "lease_owner": "sentinel_worker_daemon",
            "lease_expires_at": future_dt.isoformat(),
            "last_heartbeat": "11:00:00",
        }
        with patch("core.sentinel_stats.os.path.exists", return_value=False):
            rt = get_sentinel_worker_runtime(worker_rec=worker_rec)
            self.assertTrue(rt["worker_process_alive"])
            self.assertTrue(rt["worker_poll_loop_active"])
            self.assertEqual(rt["status"], "RUNNING")


if __name__ == "__main__":
    unittest.main()
