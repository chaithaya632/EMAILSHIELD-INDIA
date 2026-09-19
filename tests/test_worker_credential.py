"""
tests/test_worker_credential.py
Comprehensive verification of Sentinel Phase 6B:
Credential Retrieval, Authorization & Worker-Only Decryption.

Covers:
- Synthetic credential provisioning simulation (User A & User B)
- Worker A & Worker B lease acquisition
- Encrypted credential retrieval via rpc_fetch_leased_mailbox_credential
- Worker-only asymmetric decryption via WorkerKeyRing
- RSA-OAEP SHA-256 + AES-256-GCM + tenant AAD context binding
- Wrong private key rejection
- Ciphertext tampering detection
- AAD tampering detection (cross-tenant mismatch)
- Key version validation & unknown key version rejection
- Credential version verification
- Wrong capability token rejection
- Wrong worker rejection
- Cross-tenant retrieval denial
- Released lease retrieval denial
- Expired lease retrieval denial
- Token isolation between workers
- Streamlit isolation verification
- Response safety (no plaintext in DB responses)
- Safe logging verification (zero secrets in logs)
- Best-effort memory cleanup (LeasedCredential.clear())
- Zero IMAP connection verification
"""

import io
import json
import logging
import os
import time
import unittest
import uuid
from typing import Dict, Any

from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    WorkerKeyRing,
    ProvisioningKeyRing,
    DecryptionError,
    UnknownKeyVersionError,
    PayloadFormatError,
    CONTEXT_MAILBOX,
)
from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.db import MockWorkerDBClient, RoleVerificationError
from worker.lease import WorkerLeaseManager
from worker.credentials import LeasedCredential, WorkerCredentialService
from worker.logging import SafeLoggingFilter


class TestSentinelPhase6BCredentials(unittest.TestCase):
    """Rigorous verification of Phase 6B credential retrieval and worker-only decryption."""

    @classmethod
    def setUpClass(cls):
        # Generate genuine in-memory 2048-bit RSA keypairs for testing
        cls.priv_key_worker_a, cls.pub_key_worker_a = generate_worker_asymmetric_keypair(2048)
        cls.priv_key_worker_b, cls.pub_key_worker_b = generate_worker_asymmetric_keypair(2048)
        cls.priv_key_unauthorized, cls.pub_key_unauthorized = generate_worker_asymmetric_keypair(2048)

        # Synthetic identities (strictly non-routable .invalid domain)
        cls.user_a_id = uuid.uuid4()
        cls.user_b_id = uuid.uuid4()
        cls.worker_a_id = uuid.uuid4()
        cls.worker_b_id = uuid.uuid4()
        cls.mailbox_a_id = uuid.uuid4()
        cls.mailbox_b_id = uuid.uuid4()

        cls.synthetic_cred_a = json.dumps({
            "email_address": "sentinel-test-user-a@example.invalid",
            "username": "synthetic-worker-test-a",
            "password": "SYNTHETIC_ONLY_DO_NOT_USE_A_SECRET_KEY_123",
            "imap_host": "imap.example.invalid",
            "imap_port": 993,
        })

        cls.synthetic_cred_b = json.dumps({
            "email_address": "sentinel-test-user-b@example.invalid",
            "username": "synthetic-worker-test-b",
            "password": "SYNTHETIC_ONLY_DO_NOT_USE_B_SECRET_KEY_456",
            "imap_host": "imap.example.invalid",
            "imap_port": 993,
        })

        # Encrypt using ProvisioningKeyRing (representing Edge Function encryption)
        cls.prov_ring_a = ProvisioningKeyRing(active_version="k1", keys={"k1": cls.pub_key_worker_a})
        cls.prov_ring_b = ProvisioningKeyRing(active_version="k1", keys={"k1": cls.pub_key_worker_b})

        cls.envelope_a = cls.prov_ring_a.encrypt(cls.synthetic_cred_a, user_id=str(cls.user_a_id))
        cls.envelope_b = cls.prov_ring_b.encrypt(cls.synthetic_cred_b, user_id=str(cls.user_b_id))

    def setUp(self):
        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")

        # Seed synthetic workers
        self.db.seed_worker(self.worker_a_id, self.user_a_id, desired_state="RUNNING")
        self.db.seed_worker(self.worker_b_id, self.user_b_id, desired_state="RUNNING")

        # Seed synthetic mailboxes with encrypted envelopes
        self.db.seed_mailbox(
            self.mailbox_a_id,
            self.worker_a_id,
            self.user_a_id,
            encrypted_credentials=self.envelope_a,
            credential_version=1
        )
        self.db.seed_mailbox(
            self.mailbox_b_id,
            self.worker_b_id,
            self.user_b_id,
            encrypted_credentials=self.envelope_b,
            credential_version=1
        )

        self.identity_a = WorkerIdentity(self.worker_a_id)
        self.identity_b = WorkerIdentity(self.worker_b_id)

        self.lease_mgr_a = WorkerLeaseManager(self.identity_a, self.db)
        self.lease_mgr_b = WorkerLeaseManager(self.identity_b, self.db)

        self.worker_ring_a = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key_worker_a})
        self.worker_ring_b = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key_worker_b})

        self.cred_service_a = WorkerCredentialService(self.identity_a, self.worker_ring_a, self.db)
        self.cred_service_b = WorkerCredentialService(self.identity_b, self.worker_ring_b, self.db)

    # =========================================================================
    # STEP 5 & 6: PROVISIONING & LEASE CLAIM
    # =========================================================================

    def test_01_synthetic_provisioning_and_lease_claim(self):
        """Step 5 & 6: Verify synthetic provisioning envelopes and Worker A & B lease claims."""
        self.assertTrue(self.envelope_a.startswith("v2:k1:"))
        self.assertTrue(self.envelope_b.startswith("v2:k1:"))

        claimed_a = self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.assertTrue(claimed_a)
        self.assertTrue(self.lease_mgr_a.is_active())
        self.assertTrue(self.identity_a.has_token())

        claimed_b = self.lease_mgr_b.acquire_lease(duration_seconds=120)
        self.assertTrue(claimed_b)
        self.assertTrue(self.lease_mgr_b.is_active())
        self.assertTrue(self.identity_b.has_token())

    # =========================================================================
    # STEP 7 & 8: ENCRYPTED FETCH & WORKER-ONLY DECRYPTION
    # =========================================================================

    def test_02_encrypted_credential_retrieval_and_decryption(self):
        """Step 7 & 8: Encrypted credential retrieval and worker-only decryption round-trip."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)

        # 1. Fetch and decrypt via WorkerCredentialService
        leased_cred = self.cred_service_a.fetch_and_decrypt()
        self.assertIsInstance(leased_cred, LeasedCredential)
        self.assertEqual(leased_cred.worker_id, str(self.worker_a_id))
        self.assertEqual(leased_cred.user_id, str(self.user_a_id))
        self.assertEqual(leased_cred.mailbox_id, str(self.mailbox_a_id))

        # 2. Verify deterministic plaintext reconstruction without printing secrets
        parsed_secret = json.loads(leased_cred.secret)
        expected_secret = json.loads(self.synthetic_cred_a)
        self.assertEqual(parsed_secret["email_address"], expected_secret["email_address"])
        self.assertEqual(parsed_secret["username"], expected_secret["username"])
        self.assertEqual(parsed_secret["password"], expected_secret["password"])

        # 3. Verify LeasedCredential __repr__ redacts secret
        repr_str = repr(leased_cred)
        self.assertNotIn("SYNTHETIC_ONLY", repr_str)
        self.assertIn("[REDACTED_ACTIVE]", repr_str)

    # =========================================================================
    # STEP 9: WRONG PRIVATE KEY
    # =========================================================================

    def test_03_wrong_private_key_fails_closed(self):
        """Step 9: Attempting to decrypt Worker A's credential with wrong private key is DENIED."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)

        # Unauthorized keyring possesses a different RSA-2048 private key
        unauthorized_ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key_unauthorized})
        unauthorized_service = WorkerCredentialService(self.identity_a, unauthorized_ring, self.db)

        with self.assertRaises(DecryptionError):
            unauthorized_service.fetch_and_decrypt()

    # =========================================================================
    # STEP 10: CIPHERTEXT TAMPERING
    # =========================================================================

    def test_04_ciphertext_tampering_denied(self):
        """Step 10: Modifying one byte of ciphertext envelope fails AES-GCM authentication."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)

        parts = self.envelope_a.split(":")
        # Tamper with ciphertext
        tampered_ct = parts[4][:-4] + "AAAA"
        tampered_envelope = ":".join(parts[:4] + [tampered_ct])

        self.db.mailboxes[str(self.mailbox_a_id)]["encrypted_credentials"] = tampered_envelope

        with self.assertRaises(DecryptionError):
            self.cred_service_a.fetch_and_decrypt()

    # =========================================================================
    # STEP 11: AAD TAMPERING (CROSS-TENANT BINDING)
    # =========================================================================

    def test_05_aad_tampering_denied(self):
        """Step 11: Decrypting envelope under different user_id fails AAD authentication."""
        # Directly attempt decrypting envelope A using User B's user_id
        with self.assertRaises(DecryptionError):
            self.worker_ring_a.decrypt(
                self.envelope_a,
                user_id=str(self.user_b_id),
                purpose=CONTEXT_MAILBOX
            )

    # =========================================================================
    # STEP 12: KEY VERSION VALIDATION
    # =========================================================================

    def test_06_unknown_key_version_fails_closed(self):
        """Step 12: Envelope with unknown key version fails closed with UnknownKeyVersionError."""
        priv_k2, pub_k2 = generate_worker_asymmetric_keypair(2048)
        prov_k2 = ProvisioningKeyRing(active_version="k2", keys={"k2": pub_k2})
        envelope_k2 = prov_k2.encrypt(self.synthetic_cred_a, user_id=str(self.user_a_id), key_version="k2")

        # WorkerKeyRing A only has k1
        with self.assertRaises(UnknownKeyVersionError):
            self.worker_ring_a.decrypt(envelope_k2, user_id=str(self.user_a_id))

    # =========================================================================
    # STEP 13: CREDENTIAL VERSION VALIDATION
    # =========================================================================

    def test_07_credential_version_validation(self):
        """Step 13: Verify credential version is retrieved accurately from database record."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.db.mailboxes[str(self.mailbox_a_id)]["credential_version"] = 42

        cred = self.cred_service_a.fetch_and_decrypt()
        self.assertEqual(cred.credential_version, 42)

    # =========================================================================
    # STEP 14 & 15: WRONG CAPABILITY TOKEN & WRONG WORKER
    # =========================================================================

    def test_08_wrong_capability_token_denied(self):
        """Step 14: Credential fetch with invalid capability token is strictly DENIED."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        wrong_token = "0" * 64

        with self.assertRaises(PermissionError) as ctx:
            self.db.fetch_leased_mailbox_credential(self.worker_a_id, wrong_token)
        self.assertIn("capability token verification failed", str(ctx.exception).lower())

    def test_09_wrong_worker_denied(self):
        """Step 15: Worker B attempting to fetch Worker A's mailbox is DENIED."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.lease_mgr_b.acquire_lease(duration_seconds=120)

        # Worker B passes Worker B's token to fetch Worker A's mailbox
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_a_id, self.identity_b.raw_token)

    # =========================================================================
    # STEP 16: CROSS-TENANT ISOLATION
    # =========================================================================

    def test_10_cross_tenant_fetch_denied(self):
        """Step 16: Worker A -> Mailbox B is DENIED; Worker B -> Mailbox A is DENIED."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.lease_mgr_b.acquire_lease(duration_seconds=120)

        # 1. Worker A cannot fetch Worker B's credentials
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_b_id, self.identity_a.raw_token)

        # 2. Worker B cannot fetch Worker A's credentials
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_a_id, self.identity_b.raw_token)

    # =========================================================================
    # STEP 17 & 18: RELEASED LEASE & EXPIRED LEASE
    # =========================================================================

    def test_11_released_lease_denied(self):
        """Step 17: After legitimate release, old token cannot retrieve credentials."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        saved_raw_token = self.identity_a.raw_token

        # Fetch works before release
        res_before = self.db.fetch_leased_mailbox_credential(self.worker_a_id, saved_raw_token)
        self.assertTrue(res_before["success"])

        # Release lease
        self.lease_mgr_a.release_lease()

        # Fetch denied after release
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_a_id, saved_raw_token)

    def test_12_expired_lease_denied(self):
        """Step 18: Credential retrieval after lease expiry is DENIED."""
        self.lease_mgr_a.acquire_lease(duration_seconds=60)
        raw_token = self.identity_a.raw_token

        # Advance expiration into past
        self.db.workers[str(self.worker_a_id)]["lease_expires_at"] = time.time() - 1.0

        with self.assertRaises(PermissionError) as ctx:
            self.db.fetch_leased_mailbox_credential(self.worker_a_id, raw_token)
        self.assertIn("lease expired", str(ctx.exception).lower())

    # =========================================================================
    # STEP 19: TOKEN ISOLATION
    # =========================================================================

    def test_13_token_isolation_between_workers(self):
        """Step 19: Worker A token cannot be used for Worker B and vice-versa."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.lease_mgr_b.acquire_lease(duration_seconds=120)

        # Worker A token -> Worker A: PASS
        res_a = self.db.fetch_leased_mailbox_credential(self.worker_a_id, self.identity_a.raw_token)
        self.assertTrue(res_a["success"])

        # Worker A token -> Worker B: DENIED
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_b_id, self.identity_a.raw_token)

        # Worker B token -> Worker A: DENIED
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_a_id, self.identity_b.raw_token)

    # =========================================================================
    # STEP 20: STREAMLIT ISOLATION
    # =========================================================================

    def test_14_streamlit_never_receives_decrypted_credentials(self):
        """Step 20: Streamlit source code never accesses LeasedCredential or decrypts mailboxes."""
        streamlit_app = os.path.join(os.path.dirname(__file__), "..", "app.py")
        if os.path.isfile(streamlit_app):
            with open(streamlit_app, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("LeasedCredential", content)
            self.assertNotIn("WorkerCredentialService", content)
            self.assertNotIn("decrypt_credential_asymmetric", content)
            self.assertNotIn("rpc_fetch_leased_mailbox_credential", content)

    # =========================================================================
    # STEP 21: SUPABASE RESPONSE SAFETY
    # =========================================================================

    def test_15_supabase_response_safety(self):
        """Step 21: Database RPC response contains only ciphertext, zero plaintext secrets."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        res = self.db.fetch_leased_mailbox_credential(self.worker_a_id, self.identity_a.raw_token)

        # Asserts no plaintext password in response keys or values
        self.assertNotIn("password", res)
        self.assertNotIn("username", res)
        self.assertIn("encrypted_credentials", res)
        self.assertTrue(res["encrypted_credentials"].startswith("v2:"))
        self.assertNotIn("SYNTHETIC_ONLY", str(res))

    # =========================================================================
    # STEP 22: LOGGING SAFETY
    # =========================================================================

    def test_16_logging_safety_no_credentials_or_tokens(self):
        """Step 22: Capturing worker logger confirms zero passwords, tokens, or private keys in logs."""
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(SafeLoggingFilter())

        logger = logging.getLogger("test.credentials.logging")
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)

        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        raw_tok = self.identity_a.raw_token

        # Log simulated operational message containing sensitive material
        logger.info("Fetched credential token=%s payload=%s", raw_tok, self.envelope_a)
        log_output = stream.getvalue()

        self.assertNotIn(raw_tok, log_output)
        self.assertNotIn(self.envelope_a, log_output)
        self.assertNotIn("SYNTHETIC_ONLY", log_output)
        self.assertIn("[REDACTED_HEX_64]", log_output)
        self.assertIn("[REDACTED_V2_CIPHERTEXT]", log_output)

    # =========================================================================
    # STEP 23: MEMORY CLEANUP
    # =========================================================================

    def test_17_best_effort_memory_cleanup(self):
        """Step 23: Best-effort memory cleanup: clear() removes plaintext from LeasedCredential."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred = self.cred_service_a.fetch_and_decrypt()

        # Secret accessible before cleanup
        self.assertIsNotNone(cred.secret)
        self.assertIn("SYNTHETIC_ONLY", cred.secret)

        # Execute cleanup
        cred.clear()

        # Secret inaccessible after cleanup
        with self.assertRaises(ValueError):
            _ = cred.secret
        self.assertIn("[REDACTED_WIPED]", repr(cred))

    def test_18_context_manager_automatic_memory_cleanup(self):
        """Step 23b: LeasedCredential context manager automatically scrubs memory upon exit."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        with self.cred_service_a.fetch_and_decrypt() as cred:
            self.assertIsNotNone(cred.secret)
            captured_cred = cred

        # Out of context: secret is wiped
        with self.assertRaises(ValueError):
            _ = captured_cred.secret

    # =========================================================================
    # STEP 24: NO REAL IMAP CONNECTION
    # =========================================================================

    def test_19_no_imap_or_network_calls_in_worker(self):
        """Step 24: Verifies worker credential service makes zero IMAP or network socket connections."""
        import worker.credentials
        source_code = inspect_source(worker.credentials)
        self.assertNotIn("imaplib", source_code)
        self.assertNotIn("IMAP4", source_code)
        self.assertNotIn("socket.connect", source_code)
        self.assertNotIn("requests.", source_code)
        self.assertNotIn("urllib.request", source_code)


def inspect_source(mod) -> str:
    import inspect
    return inspect.getsource(mod)


if __name__ == "__main__":
    unittest.main()
