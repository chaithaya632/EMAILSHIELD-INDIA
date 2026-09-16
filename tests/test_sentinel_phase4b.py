"""
tests/test_sentinel_phase4b.py
Rigorous verification of EMAILSHIELD INDIA Sentinel Phase 4B:
Capability-Token Lease Security, Asymmetric Hybrid Envelope Encryption,
Idempotency, Monotonic CAS Versioning, and Tenant Isolation.
"""

import hashlib
import os
import re
import time
import unittest
import uuid
from typing import Dict, Any, List, Optional

from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    export_public_key_pem,
    export_private_key_pem,
    load_public_key_from_pem,
    load_private_key_from_pem,
    encrypt_credential_asymmetric,
    decrypt_credential_asymmetric,
    InvalidKeyError,
    PayloadFormatError,
    UnsupportedVersionError,
    DecryptionError,
    ENVELOPE_VERSION_V2,
    CONTEXT_MAILBOX,
    CONTEXT_ALERT,
)

PHASE4B_SQL_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "sentinel_phase4b.sql")


class TestSentinelPhase4bSQLStructure(unittest.TestCase):
    """Verifies DDL, capability-token structures, and privilege separation in sentinel_phase4b.sql."""

    @classmethod
    def setUpClass(cls):
        with open(PHASE4B_SQL_FILE, "r", encoding="utf-8") as f:
            cls.sql_content = f.read()

    def test_01_lease_token_hash_column_added(self):
        """Verify that lease_token_hash is added to sentinel_workers."""
        self.assertIn("lease_token_hash TEXT", self.sql_content)

    def test_02_provisioning_idempotency_table_declared(self):
        """Verify sentinel_provisioning_idempotency table declaration and constraints."""
        self.assertIn("CREATE TABLE IF NOT EXISTS public.sentinel_provisioning_idempotency", self.sql_content)
        self.assertIn("CONSTRAINT uq_provisioning_idempotency UNIQUE (user_id, request_id)", self.sql_content)
        self.assertIn("ALTER TABLE public.sentinel_provisioning_idempotency ENABLE ROW LEVEL SECURITY", self.sql_content)

    def test_03_all_five_rpcs_use_security_definer_and_search_path(self):
        """Verify SECURITY DEFINER and pinned search_path on all 5 RPCs."""
        rpcs = [
            "rpc_set_encrypted_mailbox_credential",
            "rpc_claim_worker_lease",
            "rpc_fetch_leased_mailbox_credential",
            "rpc_renew_worker_lease",
            "rpc_release_worker_lease",
        ]
        for rpc in rpcs:
            pattern = rf"FUNCTION\s+public\.{re.escape(rpc)}[\s\S]*?AS\s*\$\$"
            match = re.search(pattern, self.sql_content, re.IGNORECASE)
            self.assertIsNotNone(match, f"Could not extract function header for {rpc}")
            header = match.group(0)
            self.assertIn("SECURITY DEFINER", header.upper())
            self.assertTrue(re.search(r"SET\s+search_path\s*=\s*pg_catalog,\s*public", header, re.IGNORECASE))

    def test_04_capability_token_generation_and_hashing_in_claim_rpc(self):
        """Verify claim RPC generates 256-bit token and stores only SHA-256 hash."""
        self.assertIn("gen_random_bytes(32)", self.sql_content)
        self.assertIn("sha256", self.sql_content.lower())
        self.assertIn("lease_token_hash = v_token_hash", self.sql_content)

    def test_05_capability_token_parameter_on_fetch_renew_release(self):
        """Verify fetch, renew, and release RPCs require p_lease_token parameter."""
        self.assertIn("rpc_fetch_leased_mailbox_credential(UUID, TEXT)", self.sql_content)
        self.assertIn("rpc_renew_worker_lease(UUID, TEXT, INTEGER)", self.sql_content)
        self.assertIn("rpc_release_worker_lease(UUID, TEXT)", self.sql_content)

    def test_06_privilege_separation_rules(self):
        """Verify privileges: authenticated has only provisioning; worker has only worker RPCs."""
        # Authenticated has provisioning
        self.assertTrue(re.search(r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.rpc_set_encrypted_mailbox_credential[\s\S]*?TO\s+authenticated", self.sql_content))
        # Worker role has lease RPCs
        self.assertTrue(re.search(r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.rpc_claim_worker_lease[\s\S]*?TO\s+sentinel_worker_role", self.sql_content))
        self.assertTrue(re.search(r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.rpc_fetch_leased_mailbox_credential[\s\S]*?TO\s+sentinel_worker_role", self.sql_content))
        self.assertTrue(re.search(r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.rpc_renew_worker_lease[\s\S]*?TO\s+sentinel_worker_role", self.sql_content))
        self.assertTrue(re.search(r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.rpc_release_worker_lease[\s\S]*?TO\s+sentinel_worker_role", self.sql_content))
        # Authenticated revoked from worker RPCs
        self.assertTrue(re.search(r"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.rpc_claim_worker_lease[\s\S]*?FROM\s+authenticated", self.sql_content))


class MockPhase4bDatabase:
    """
    Simulation of Phase 4B database state machine:
    - 256-bit CSPRNG lease token generation
    - SHA-256 token hashing
    - Monotonic version check & CAS
    - Idempotency tracking
    """

    def __init__(self):
        self.workers: Dict[str, Dict[str, Any]] = {}
        self.mailboxes: Dict[str, Dict[str, Any]] = {}
        self.idempotency: Dict[str, Dict[str, Any]] = {}

    def rpc_set_encrypted_mailbox_credential(
        self,
        auth_uid: Optional[str],
        p_worker_id: str,
        p_ciphertext: str,
        p_credential_version: int,
        p_expected_previous_version: Optional[int] = None,
        p_idempotency_key: Optional[str] = None
    ) -> bool:
        if not auth_uid:
            raise PermissionError("Authentication required: caller identity is unauthenticated")

        # Idempotency check
        if p_idempotency_key:
            key_id = f"{auth_uid}:{p_idempotency_key}"
            if key_id in self.idempotency:
                rec = self.idempotency[key_id]
                if rec["expires_at"] > time.time() and rec["status"] == "COMPLETED":
                    return True  # Idempotent duplicate handled safely

        if not p_worker_id:
            raise ValueError("p_worker_id cannot be null")
        if not p_ciphertext or not p_ciphertext.strip():
            raise ValueError("p_ciphertext cannot be null or empty")
        if len(p_ciphertext) > 8192:
            raise ValueError("p_ciphertext exceeds maximum allowed length of 8192 characters")

        # Validate v1 or v2 envelope regex
        v1_match = re.match(r"^v1:[0-9a-fA-F]{24}:[0-9a-fA-F]{34,}$", p_ciphertext)
        v2_match = re.match(r"^v2:[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+={0,2}:[a-zA-Z0-9_\-]+={0,2}:[a-zA-Z0-9_\-]+={0,2}$", p_ciphertext)
        if not (v1_match or v2_match):
            raise ValueError("Invalid ciphertext envelope structure")

        if not isinstance(p_credential_version, int) or isinstance(p_credential_version, bool) or p_credential_version <= 0:
            raise ValueError("p_credential_version must be a positive integer")

        worker = self.workers.get(p_worker_id)
        if not worker or worker.get("user_id") != auth_uid:
            raise PermissionError(f"Ownership violation: worker {p_worker_id} does not belong to caller {auth_uid}")

        mailbox = next((m for m in self.mailboxes.values() if m.get("worker_id") == p_worker_id and m.get("user_id") == auth_uid), None)
        if not mailbox:
            return False

        current_version = mailbox.get("credential_version", 1)

        # CAS check
        if p_expected_previous_version is not None:
            if current_version != p_expected_previous_version:
                raise ValueError(f"Concurrent stale update rejected: expected version {p_expected_previous_version} does not match current {current_version}")

        # Monotonic version check
        if p_credential_version <= current_version:
            raise ValueError(f"Credential version rollback rejected: current version is {current_version}, proposed is {p_credential_version}")

        mailbox["encrypted_credentials"] = p_ciphertext
        mailbox["credential_version"] = p_credential_version
        mailbox["credential_status"] = "ACTIVE"
        mailbox["updated_at"] = time.time()

        if p_idempotency_key:
            self.idempotency[f"{auth_uid}:{p_idempotency_key}"] = {
                "request_id": p_idempotency_key,
                "user_id": auth_uid,
                "worker_id": p_worker_id,
                "credential_version": p_credential_version,
                "created_at": time.time(),
                "expires_at": time.time() + 900,
                "status": "COMPLETED"
            }

        return True

    def rpc_claim_worker_lease(
        self,
        p_worker_id: Optional[str] = None,
        p_lease_duration_seconds: int = 300
    ) -> Optional[Dict[str, Any]]:
        now = time.time()
        candidates = [self.workers[p_worker_id]] if p_worker_id and p_worker_id in self.workers else list(self.workers.values())

        for w in candidates:
            if w.get("desired_state") == "RUNNING":
                exp = w.get("lease_expires_at")
                if exp is None or exp < now:
                    # Kernel generation of 256-bit CSPRNG token
                    raw_token = os.urandom(32).hex()  # 64 hex chars
                    token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()

                    w["lease_owner"] = "ACTIVE_LEASE"
                    w["lease_token_hash"] = token_hash
                    w["lease_expires_at"] = now + p_lease_duration_seconds
                    w["actual_state"] = "RUNNING"
                    w["last_heartbeat"] = now
                    w["updated_at"] = now
                    return {
                        "worker_id": w["id"],
                        "user_id": w["user_id"],
                        "poll_interval_seconds": w["poll_interval_seconds"],
                        "lease_expires_at": w["lease_expires_at"],
                        "lease_token": raw_token  # Raw token returned ONCE to claimant
                    }
        return None

    def rpc_fetch_leased_mailbox_credential(self, p_worker_id: str, p_lease_token: str) -> Optional[Dict[str, Any]]:
        if not p_worker_id or not p_lease_token:
            raise ValueError("Parameters cannot be empty")
        if len(p_lease_token.strip()) != 64:
            raise ValueError("Invalid lease capability token format")

        token_hash = hashlib.sha256(p_lease_token.strip().encode("ascii")).hexdigest()
        worker = self.workers.get(p_worker_id)
        if not worker:
            raise PermissionError("Worker not found")

        now = time.time()
        if (
            worker.get("lease_token_hash") != token_hash
            or worker.get("lease_expires_at", 0) <= now
            or worker.get("desired_state") != "RUNNING"
        ):
            raise PermissionError(f"Access denied: invalid lease capability token or expired lease for worker {p_worker_id}")

        mailbox = next((m for m in self.mailboxes.values() if m.get("worker_id") == p_worker_id), None)
        if not mailbox or not mailbox.get("is_active") or mailbox.get("credential_status") != "ACTIVE":
            return None

        return {
            "mailbox_id": mailbox["id"],
            "user_id": mailbox["user_id"],
            "provider": mailbox["provider"],
            "email_address": mailbox["email_address"],
            "encrypted_credentials": mailbox["encrypted_credentials"],
            "credential_version": mailbox["credential_version"]
        }

    def rpc_renew_worker_lease(self, p_worker_id: str, p_lease_token: str, p_lease_duration_seconds: int = 300) -> float:
        if not p_worker_id or not p_lease_token:
            raise ValueError("Parameters cannot be empty")
        token_hash = hashlib.sha256(p_lease_token.strip().encode("ascii")).hexdigest()
        worker = self.workers.get(p_worker_id)
        if not worker:
            raise PermissionError("Worker not found")

        now = time.time()
        if (
            worker.get("lease_token_hash") != token_hash
            or worker.get("lease_expires_at", 0) <= now
            or worker.get("desired_state") != "RUNNING"
        ):
            raise PermissionError(f"Renewal denied: active lease not found or invalid capability token for worker {p_worker_id}")

        worker["lease_expires_at"] = now + p_lease_duration_seconds
        worker["last_heartbeat"] = now
        worker["updated_at"] = now
        return worker["lease_expires_at"]

    def rpc_release_worker_lease(self, p_worker_id: str, p_lease_token: str) -> bool:
        if not p_worker_id or not p_lease_token:
            raise ValueError("Parameters cannot be empty")
        token_hash = hashlib.sha256(p_lease_token.strip().encode("ascii")).hexdigest()
        worker = self.workers.get(p_worker_id)
        if not worker or worker.get("lease_token_hash") != token_hash:
            return False

        worker["lease_owner"] = None
        worker["lease_token_hash"] = None
        worker["lease_expires_at"] = None
        worker["actual_state"] = "STOPPED"
        worker["updated_at"] = time.time()
        return True


class TestSentinelPhase4bSecurity(unittest.TestCase):
    """Behavioral security test suite for Phase 4B."""

    def setUp(self):
        self.db = MockPhase4bDatabase()
        self.user_a = str(uuid.uuid4())
        self.user_b = str(uuid.uuid4())

        self.worker_a = str(uuid.uuid4())
        self.db.workers[self.worker_a] = {
            "id": self.worker_a,
            "user_id": self.user_a,
            "desired_state": "RUNNING",
            "actual_state": "STOPPED",
            "poll_interval_seconds": 60,
            "lease_owner": None,
            "lease_token_hash": None,
            "lease_expires_at": None,
            "last_heartbeat": None,
            "updated_at": time.time()
        }

        self.mailbox_a = str(uuid.uuid4())
        self.db.mailboxes[self.mailbox_a] = {
            "id": self.mailbox_a,
            "user_id": self.user_a,
            "worker_id": self.worker_a,
            "provider": "gmail",
            "email_address": "user_a@gmail.com",
            "is_active": True,
            "encrypted_credentials": "v1:0123456789abcdef01234567:aabbccddeeff00112233445566778899aabbccddeeff",
            "credential_version": 1,
            "credential_status": "ACTIVE",
            "updated_at": time.time()
        }

        self.worker_b = str(uuid.uuid4())
        self.db.workers[self.worker_b] = {
            "id": self.worker_b,
            "user_id": self.user_b,
            "desired_state": "RUNNING",
            "actual_state": "STOPPED",
            "poll_interval_seconds": 60,
            "lease_owner": None,
            "lease_token_hash": None,
            "lease_expires_at": None,
            "last_heartbeat": None,
            "updated_at": time.time()
        }

    # =================================================================
    # Category 1: Capability Tokens
    # =================================================================
    def test_07_token_generated_only_by_successful_claim(self):
        """Lease capability token is generated upon successful claim and is 64 hex characters."""
        claim = self.db.rpc_claim_worker_lease(self.worker_a, p_lease_duration_seconds=300)
        self.assertIsNotNone(claim)
        raw_token = claim["lease_token"]
        self.assertEqual(len(raw_token), 64)
        self.assertTrue(re.match(r"^[0-9a-fA-F]{64}$", raw_token))

    def test_08_raw_token_not_stored_in_database(self):
        """Database stores ONLY the SHA-256 hash of the token, never the raw token."""
        claim = self.db.rpc_claim_worker_lease(self.worker_a, p_lease_duration_seconds=300)
        raw_token = claim["lease_token"]
        stored_hash = self.db.workers[self.worker_a]["lease_token_hash"]
        self.assertNotEqual(raw_token, stored_hash)
        expected_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        self.assertEqual(stored_hash, expected_hash)

    def test_09_wrong_token_denied(self):
        """Presenting an incorrect lease token is strictly denied."""
        self.db.rpc_claim_worker_lease(self.worker_a, p_lease_duration_seconds=300)
        wrong_token = "0" * 64
        with self.assertRaises(PermissionError):
            self.db.rpc_fetch_leased_mailbox_credential(self.worker_a, wrong_token)

    def test_10_expired_token_denied(self):
        """An expired lease capability token cannot fetch credentials or renew."""
        claim = self.db.rpc_claim_worker_lease(self.worker_a, p_lease_duration_seconds=300)
        raw_token = claim["lease_token"]
        # Manually expire lease
        self.db.workers[self.worker_a]["lease_expires_at"] = time.time() - 1
        with self.assertRaises(PermissionError):
            self.db.rpc_fetch_leased_mailbox_credential(self.worker_a, raw_token)
        with self.assertRaises(PermissionError):
            self.db.rpc_renew_worker_lease(self.worker_a, raw_token)

    def test_11_released_token_denied(self):
        """A released lease clears the token hash; subsequent use is denied."""
        claim = self.db.rpc_claim_worker_lease(self.worker_a, p_lease_duration_seconds=300)
        raw_token = claim["lease_token"]
        released = self.db.rpc_release_worker_lease(self.worker_a, raw_token)
        self.assertTrue(released)
        self.assertIsNone(self.db.workers[self.worker_a]["lease_token_hash"])
        with self.assertRaises(PermissionError):
            self.db.rpc_fetch_leased_mailbox_credential(self.worker_a, raw_token)

    def test_12_token_from_another_worker_denied(self):
        """A valid token for Worker A cannot be used to fetch or release Worker B."""
        claim_a = self.db.rpc_claim_worker_lease(self.worker_a, p_lease_duration_seconds=300)
        token_a = claim_a["lease_token"]
        with self.assertRaises(PermissionError):
            self.db.rpc_fetch_leased_mailbox_credential(self.worker_b, token_a)
        released = self.db.rpc_release_worker_lease(self.worker_b, token_a)
        self.assertFalse(released)

    # =================================================================
    # Category 2: Asymmetric Hybrid Cryptography
    # =================================================================
    def test_13_asymmetric_envelope_encryption_decryption_roundtrip(self):
        """Verifies full asymmetric hybrid encryption roundtrip (RSA-OAEP + AES-256-GCM)."""
        priv, pub = generate_worker_asymmetric_keypair(2048)
        secret = "super_sensitive_app_password_999!"
        envelope = encrypt_credential_asymmetric(
            plaintext=secret,
            public_key=pub,
            user_id=self.user_a,
            purpose=CONTEXT_MAILBOX,
            key_version="k1"
        )
        self.assertTrue(envelope.startswith("v2:k1:"))
        decrypted = decrypt_credential_asymmetric(
            envelope=envelope,
            private_key=priv,
            user_id=self.user_a,
            purpose=CONTEXT_MAILBOX,
            expected_key_version="k1"
        )
        self.assertEqual(decrypted, secret)

    def test_14_wrong_private_key_fails(self):
        """Decryption with a different private key fails closed."""
        priv1, pub1 = generate_worker_asymmetric_keypair(2048)
        priv2, pub2 = generate_worker_asymmetric_keypair(2048)
        envelope = encrypt_credential_asymmetric("password", pub1, self.user_a)
        with self.assertRaises(DecryptionError):
            decrypt_credential_asymmetric(envelope, priv2, self.user_a)

    def test_15_tampered_components_fail(self):
        """Tampering with wrapped DEK, nonce, or ciphertext tag causes fail-closed DecryptionError."""
        priv, pub = generate_worker_asymmetric_keypair(2048)
        envelope = encrypt_credential_asymmetric("password", pub, self.user_a)
        parts = envelope.split(":")

        # Tampered wrapped DEK
        tampered_wdek = parts[0] + ":" + parts[1] + ":" + ("A" + parts[2][1:]) + ":" + parts[3] + ":" + parts[4]
        with self.assertRaises(DecryptionError):
            decrypt_credential_asymmetric(tampered_wdek, priv, self.user_a)

        # Tampered nonce
        tampered_nonce = parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + ("A" + parts[3][1:]) + ":" + parts[4]
        with self.assertRaises(DecryptionError):
            decrypt_credential_asymmetric(tampered_nonce, priv, self.user_a)

        # Tampered ciphertext
        tampered_ct = parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + parts[3] + ":" + ("A" + parts[4][1:])
        with self.assertRaises(DecryptionError):
            decrypt_credential_asymmetric(tampered_ct, priv, self.user_a)

    def test_16_wrong_aad_tenant_id_fails(self):
        """Ciphertext copied to a different tenant fails authentication tag verification."""
        priv, pub = generate_worker_asymmetric_keypair(2048)
        envelope = encrypt_credential_asymmetric("password", pub, self.user_a)
        # Attempt to decrypt using User B context
        with self.assertRaises(DecryptionError):
            decrypt_credential_asymmetric(envelope, priv, self.user_b)

    def test_17_pem_export_and_import(self):
        """Verifies PEM export and loading for both public and private keys."""
        priv, pub = generate_worker_asymmetric_keypair(2048)
        pub_pem = export_public_key_pem(pub)
        priv_pem = export_private_key_pem(priv)
        self.assertIn("BEGIN PUBLIC KEY", pub_pem)
        self.assertIn("BEGIN PRIVATE KEY", priv_pem)
        loaded_pub = load_public_key_from_pem(pub_pem)
        loaded_priv = load_private_key_from_pem(priv_pem)
        # Verify functional with loaded keys
        env = encrypt_credential_asymmetric("test", loaded_pub, self.user_a)
        self.assertEqual(decrypt_credential_asymmetric(env, loaded_priv, self.user_a), "test")

    # =================================================================
    # Category 3: Versioning & Compare-and-Swap (CAS)
    # =================================================================
    def test_18_cas_expected_version_enforcement(self):
        """Compare-and-Swap rejects updates when expected_previous_version mismatches."""
        priv, pub = generate_worker_asymmetric_keypair(2048)
        env = encrypt_credential_asymmetric("pass_v2", pub, self.user_a)

        # Mismatched expected version (current is 1, caller expects 5)
        with self.assertRaises(ValueError):
            self.db.rpc_set_encrypted_mailbox_credential(
                auth_uid=self.user_a,
                p_worker_id=self.worker_a,
                p_ciphertext=env,
                p_credential_version=2,
                p_expected_previous_version=5  # Stale CAS expectation!
            )

        # Matching expected version succeeds
        ok = self.db.rpc_set_encrypted_mailbox_credential(
            auth_uid=self.user_a,
            p_worker_id=self.worker_a,
            p_ciphertext=env,
            p_credential_version=2,
            p_expected_previous_version=1  # Correct CAS expectation
        )
        self.assertTrue(ok)

    # =================================================================
    # Category 4: Idempotency
    # =================================================================
    def test_19_idempotent_duplicate_request_safe(self):
        """Duplicate request with same idempotency key succeeds idempotently without error."""
        priv, pub = generate_worker_asymmetric_keypair(2048)
        env = encrypt_credential_asymmetric("pass_v2", pub, self.user_a)
        idemp_key = str(uuid.uuid4())

        # First attempt: succeeds
        ok1 = self.db.rpc_set_encrypted_mailbox_credential(
            auth_uid=self.user_a,
            p_worker_id=self.worker_a,
            p_ciphertext=env,
            p_credential_version=2,
            p_idempotency_key=idemp_key
        )
        self.assertTrue(ok1)

        # Second attempt with same key: returns True idempotently
        ok2 = self.db.rpc_set_encrypted_mailbox_credential(
            auth_uid=self.user_a,
            p_worker_id=self.worker_a,
            p_ciphertext=env,
            p_credential_version=2,
            p_idempotency_key=idemp_key
        )
        self.assertTrue(ok2)


if __name__ == "__main__":
    unittest.main()
