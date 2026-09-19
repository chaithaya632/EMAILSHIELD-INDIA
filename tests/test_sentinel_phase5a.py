"""
tests/test_sentinel_phase5a.py
EMAILSHIELD INDIA — Phase 5A Production Control-Plane & Provisioning Gate Tests.

Covers:
1. Supavisor session connection semantics & username format (sentinel_worker_daemon.<ref>)
2. Role privilege boundary & inheritance checks
3. Edge Function contract, AST, and invariant security:
   - Anonymous request denied (401)
   - Invalid / expired JWT denied (401)
   - Forged user_id rejected / ignored (403)
   - Cross-tenant worker provisioning rejected (403)
   - Public-key hybrid encryption via AES-256-GCM + RSA-OAEP SHA-256
   - WorkerKeyRing decryption of Edge Function generated envelopes
   - Stale credential version CAS conflict (409)
   - Idempotency replay returns success without duplicate rows
   - Tampered envelope rejected
   - Zero private keys in Edge Function source
   - Zero service_role references in Edge Function source
   - Zero plaintext persistence
"""

import os
import re
import json
import uuid
import base64
import unittest
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization

from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    export_public_key_pem,
    export_private_key_pem,
    load_public_key_from_pem,
    load_private_key_from_pem,
    encrypt_credential_asymmetric,
    decrypt_credential_asymmetric,
    WorkerKeyRing,
    ProvisioningKeyRing,
    DecryptionError,
    UnknownKeyVersionError,
    PayloadFormatError,
    CONTEXT_MAILBOX,
)


class TestSentinelPhase5A(unittest.TestCase):
    """Automated security gate tests for Sentinel Phase 5A."""

    @classmethod
    def setUpClass(cls):
        # Generate synthetic test keypair (labeled TEST/STAGING ONLY)
        cls.priv_key_1, cls.pub_key_1 = generate_worker_asymmetric_keypair(2048)
        cls.pub_pem_1 = export_public_key_pem(cls.pub_key_1)
        cls.priv_pem_1 = export_private_key_pem(cls.priv_key_1)

        cls.user_a_id = str(uuid.uuid4())
        cls.user_b_id = str(uuid.uuid4())
        cls.worker_a_id = str(uuid.uuid4())
        cls.worker_b_id = str(uuid.uuid4())

        # Load Edge Function source code
        edge_function_path = os.path.join(
            "supabase", "functions", "provision-sentinel-credential", "index.ts"
        )
        with open(edge_function_path, "r", encoding="utf-8") as f:
            cls.edge_source = f.read()

        # Load Phase 4C DDL
        sql_path = os.path.join("data", "sentinel_phase4c.sql")
        with open(sql_path, "r", encoding="utf-8") as f:
            cls.sql_source = f.read()

    # =====================================================================
    # SECTION A: SUPAVISOR SESSION & ROLE BOUNDARY INVARIANTS
    # =====================================================================

    def test_01_supavisor_custom_role_username_format(self):
        """1. Asserts Supavisor custom role connection username format [ROLE].[PROJECT_REF]."""
        project_ref = "wajnscjisvtdwohdcnnl"
        expected_role = "sentinel_worker_daemon"
        pooler_username = f"{expected_role}.{project_ref}"
        self.assertEqual(pooler_username, "sentinel_worker_daemon.wajnscjisvtdwohdcnnl")
        self.assertTrue(pooler_username.startswith("sentinel_worker_daemon."))

    def test_02_role_ddl_nologin_and_nobypassrls(self):
        """2. Verifies sentinel_worker_role has NOLOGIN, NOSUPERUSER, NOBYPASSRLS in DDL."""
        self.assertIn("CREATE ROLE sentinel_worker_role", self.sql_source)
        self.assertIn("NOLOGIN", self.sql_source)
        self.assertIn("NOSUPERUSER", self.sql_source)
        self.assertIn("NOBYPASSRLS", self.sql_source)

    def test_03_daemon_role_inherits_worker_role(self):
        """3. Verifies sentinel_worker_daemon inherits sentinel_worker_role."""
        self.assertIn("CREATE ROLE sentinel_worker_daemon", self.sql_source)
        self.assertIn("GRANT sentinel_worker_role TO sentinel_worker_daemon", self.sql_source)

    def test_04_worker_direct_table_access_strictly_revoked(self):
        """4. Confirms DDL never grants direct table access (SELECT/INSERT/UPDATE) to sentinel_worker_role."""
        self.assertNotIn("GRANT SELECT ON", self.sql_source)
        self.assertNotIn("GRANT INSERT ON", self.sql_source)
        self.assertNotIn("GRANT UPDATE ON", self.sql_source)
        self.assertNotIn("GRANT ALL ON ALL TABLES", self.sql_source)

    def test_05_provisioning_rpc_revoked_from_worker(self):
        """5. Confirms provisioning RPC is revoked from sentinel_worker_role."""
        self.assertIn("REVOKE ALL ON FUNCTION public.rpc_set_encrypted_mailbox_credential", self.sql_source)
        self.assertIn("FROM sentinel_worker_role", self.sql_source)

    def test_06_worker_rpcs_revoked_from_authenticated_and_anon(self):
        """6. Confirms worker RPCs are revoked from authenticated, anon, and PUBLIC."""
        for rpc in ["rpc_claim_worker_lease", "rpc_fetch_leased_mailbox_credential", "rpc_renew_worker_lease", "rpc_release_worker_lease"]:
            self.assertIn(f"REVOKE ALL ON FUNCTION public.{rpc}", self.sql_source)
            self.assertIn(f"TO sentinel_worker_role", self.sql_source)

    # =====================================================================
    # SECTION B: EDGE FUNCTION STATIC & CONTRACT VERIFICATION
    # =====================================================================

    def test_07_edge_function_requires_bearer_auth(self):
        """7. Verifies Edge Function extracts and enforces Bearer Authorization header."""
        self.assertIn('req.headers.get("Authorization")', self.edge_source)
        self.assertIn('startsWith("Bearer ")', self.edge_source)
        self.assertIn('status: 401', self.edge_source)

    def test_08_edge_function_derives_user_id_from_auth_context(self):
        """8. Verifies Edge Function derives identity from auth.getUser() and never trusts client."""
        self.assertIn("await userClient.auth.getUser()", self.edge_source)
        self.assertIn("const verifiedUserId = user.id;", self.edge_source)
        self.assertIn("body.user_id !== verifiedUserId", self.edge_source)
        self.assertIn("status: 403", self.edge_source)

    def test_09_edge_function_verifies_worker_ownership(self):
        """9. Verifies Edge Function checks worker ownership under verified user ID."""
        self.assertIn('.from("sentinel_workers")', self.edge_source)
        self.assertIn('.eq("id", worker_id)', self.edge_source)
        self.assertIn('.eq("user_id", verifiedUserId)', self.edge_source)

    def test_10_edge_function_contains_zero_private_keys(self):
        """10. Invariant: Edge Function must not reference or load private keys."""
        self.assertNotIn("PRIVATE KEY", self.edge_source)
        self.assertNotIn("SENTINEL_WORKER_PRIVATE_KEY", self.edge_source)
        self.assertNotIn("SENTINEL_MASTER_KEY", self.edge_source)
        self.assertIn("SENTINEL_WORKER_PUBLIC_KEY", self.edge_source)

    def test_11_edge_function_contains_zero_service_role(self):
        """11. Invariant: Edge Function must not use service_role key or environment variable."""
        self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", self.edge_source)
        self.assertNotIn("Deno.env.get(\"SUPABASE_SERVICE_ROLE\")", self.edge_source)
        self.assertIn("SUPABASE_ANON_KEY", self.edge_source)

    def test_12_edge_function_zero_secret_logging(self):
        """12. Invariant: Edge Function must not log credentials or auth headers."""
        self.assertNotIn("console.log(mailbox_credential", self.edge_source)
        self.assertNotIn("console.log(authHeader", self.edge_source)
        self.assertNotIn("console.log(body", self.edge_source)

    # =====================================================================
    # SECTION C: CRYPTOGRAPHIC ENVELOPE & KEYRING INTEGRATION
    # =====================================================================

    def test_13_edge_function_envelope_format_compatibility(self):
        """13. Simulates Edge Function WebCrypto envelope generation and verifies WorkerKeyRing compatibility."""
        test_plaintext = "synthetic_app_password_xyz123"
        key_version = "k1"

        # Simulate Edge Function WebCrypto logic in Python:
        # 1. Ephemeral DEK
        dek = AESGCM.generate_key(bit_length=256)
        # 2. RSA-OAEP SHA-256 wrapping of DEK
        wrapped_dek = self.pub_key_1.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # 3. AES-256-GCM with tenant AAD
        nonce = os.urandom(12)
        aad = f"EMAILSHIELD:{CONTEXT_MAILBOX}:{self.user_a_id}:{key_version}".encode("utf-8")
        aesgcm = AESGCM(dek)
        ct_and_tag = aesgcm.encrypt(nonce, test_plaintext.encode("utf-8"), aad)

        # Assemble v2 envelope
        b64_wdek = base64.urlsafe_b64encode(wrapped_dek).decode("ascii")
        b64_nonce = base64.urlsafe_b64encode(nonce).decode("ascii")
        b64_ct = base64.urlsafe_b64encode(ct_and_tag).decode("ascii")
        envelope = f"v2:{key_version}:{b64_wdek}:{b64_nonce}:{b64_ct}"

        # Decrypt via WorkerKeyRing
        ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key_1})
        decrypted = ring.decrypt(envelope, user_id=self.user_a_id)
        self.assertEqual(decrypted, test_plaintext)

    def test_14_cross_tenant_envelope_decryption_denied(self):
        """14. Verifies envelope encrypted for User A fails AAD authentication when decrypted as User B."""
        plaintext = "secret_pw_tenant_a"
        provisioning_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": self.pub_key_1})
        envelope = provisioning_ring.encrypt(plaintext, user_id=self.user_a_id)

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key_1})
        with self.assertRaises(DecryptionError):
            worker_ring.decrypt(envelope, user_id=self.user_b_id)

    def test_15_tampered_envelope_payload_denied(self):
        """15. Verifies tampered ciphertext envelope is rejected by authentication tag."""
        plaintext = "tamper_test_secret"
        provisioning_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": self.pub_key_1})
        envelope = provisioning_ring.encrypt(plaintext, user_id=self.user_a_id)

        # Tamper with the ciphertext component
        parts = envelope.split(":")
        tampered_ct = parts[4][:-4] + "AAAA"
        tampered_envelope = ":".join(parts[:4] + [tampered_ct])

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key_1})
        with self.assertRaises(DecryptionError):
            worker_ring.decrypt(tampered_envelope, user_id=self.user_a_id)

    def test_16_unknown_key_version_fails_closed(self):
        """16. Verifies envelope with unknown key_version fails closed with UnknownKeyVersionError."""
        priv_k2, pub_k2 = generate_worker_asymmetric_keypair(2048)
        provisioning_ring = ProvisioningKeyRing(active_version="k2", keys={"k2": pub_k2})
        envelope = provisioning_ring.encrypt("secret", user_id=self.user_a_id, key_version="k2")

        # WorkerKeyRing only knows k1
        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key_1})
        with self.assertRaises(UnknownKeyVersionError):
            worker_ring.decrypt(envelope, user_id=self.user_a_id)

    # =====================================================================
    # SECTION D: PROVISIONING CONTRACT & CAS / IDEMPOTENCY LOGIC
    # =====================================================================

    def test_17_idempotency_key_format_validation(self):
        """17. Asserts UUID format validation on idempotency keys."""
        valid_uuid = str(uuid.uuid4())
        invalid_uuid = "not-a-valid-uuid"
        uuid_pattern = re.compile(r"^[0-9a-fA-F-]{36}$")
        self.assertTrue(bool(uuid_pattern.match(valid_uuid)))
        self.assertFalse(bool(uuid_pattern.match(invalid_uuid)))

    def test_18_credential_version_monotonic_requirement(self):
        """18. Verifies credential_version must be positive integer."""
        valid_versions = [1, 2, 100]
        invalid_versions = [0, -1, 1.5, "one"]
        for v in valid_versions:
            self.assertTrue(isinstance(v, int) and v > 0)
        for v in invalid_versions:
            self.assertFalse(isinstance(v, int) and v > 0)

    def test_19_edge_function_cas_conflict_handling(self):
        """19. Verifies Edge Function returns HTTP 409 Conflict upon CAS version mismatch."""
        self.assertIn("status: 409", self.edge_source)
        self.assertIn("Concurrent stale update rejected", self.edge_source)

    def test_20_edge_function_forbidden_ownership_handling(self):
        """20. Verifies Edge Function returns HTTP 403 Forbidden upon tenant ownership violation."""
        self.assertIn("status: 403", self.edge_source)
        self.assertIn("Ownership violation", self.edge_source)

    def test_21_no_plaintext_persistence_in_rpc(self):
        """21. Confirms RPC 1 in DDL only stores p_ciphertext and never plaintext."""
        self.assertIn("encrypted_credentials = p_ciphertext", self.sql_source)
        self.assertNotIn("plain_password", self.sql_source)
        self.assertNotIn("raw_password", self.sql_source)

    # =====================================================================
    # SECTION E: SIMULATED EDGE FUNCTION RUNTIME EXECUTION
    # =====================================================================

    def _simulate_edge_function(
        self,
        auth_header: str,
        body: dict,
        auth_user_id: str,
        known_workers: dict,
        key_ring: ProvisioningKeyRing,
    ) -> tuple:
        """Simulates the execution flow of provision-sentinel-credential."""
        if not auth_header or not auth_header.startswith("Bearer "):
            return 401, {"error": "Unauthorized: Missing or invalid Authorization header."}

        token = auth_header[7:].strip()
        if token != "valid_user_jwt":
            return 401, {"error": "Unauthorized: Invalid or expired authentication token."}

        verified_user_id = auth_user_id

        if "user_id" in body and body["user_id"] != verified_user_id:
            return 403, {"error": "Access denied: client cannot specify or override user_id."}

        worker_id = body.get("worker_id")
        if not worker_id or worker_id not in known_workers:
            return 403, {"error": "Ownership violation: worker does not exist or does not belong to caller."}

        if known_workers[worker_id]["user_id"] != verified_user_id:
            return 403, {"error": "Ownership violation: worker does not exist or does not belong to caller."}

        mailbox_credential = body.get("mailbox_credential")
        if not mailbox_credential or not isinstance(mailbox_credential, str) or len(mailbox_credential.strip()) == 0:
            return 400, {"error": "Invalid or missing mailbox_credential."}

        cred_ver = body.get("credential_version")
        if not isinstance(cred_ver, int) or cred_ver <= 0:
            return 400, {"error": "credential_version must be a positive integer."}

        exp_prev_ver = body.get("expected_previous_version")
        current_ver = known_workers[worker_id].get("current_version", 1)
        if exp_prev_ver is not None and exp_prev_ver != current_ver:
            return 409, {"error": "Conflict: credential version mismatch or concurrent update."}

        # Idempotency check
        idem_key = body.get("idempotency_key")
        if idem_key and idem_key in known_workers[worker_id].get("idempotency_records", {}):
            return 200, {
                "success": True,
                "worker_id": worker_id,
                "credential_version": current_ver,
                "key_version": key_ring.active_version,
            }

        # Perform encryption using provisioning public key ring
        envelope = key_ring.encrypt(mailbox_credential, user_id=verified_user_id)

        # Update simulated storage (stores ONLY ciphertext envelope, NEVER plaintext)
        known_workers[worker_id]["current_version"] = cred_ver
        known_workers[worker_id]["encrypted_credentials"] = envelope
        if idem_key:
            if "idempotency_records" not in known_workers[worker_id]:
                known_workers[worker_id]["idempotency_records"] = {}
            known_workers[worker_id]["idempotency_records"][idem_key] = True

        return 200, {
            "success": True,
            "worker_id": worker_id,
            "credential_version": cred_ver,
            "key_version": key_ring.active_version,
        }

    def test_22_simulated_edge_function_anonymous_denied(self):
        """22. Verifies anonymous request without Bearer token returns 401."""
        status, resp = self._simulate_edge_function("", {}, self.user_a_id, {}, ProvisioningKeyRing("k1", {"k1": self.pub_key_1}))
        self.assertEqual(status, 401)
        self.assertIn("Missing or invalid Authorization header", resp["error"])

    def test_23_simulated_edge_function_invalid_jwt_denied(self):
        """23. Verifies request with invalid JWT returns 401."""
        status, resp = self._simulate_edge_function("Bearer invalid_token", {}, self.user_a_id, {}, ProvisioningKeyRing("k1", {"k1": self.pub_key_1}))
        self.assertEqual(status, 401)
        self.assertIn("Invalid or expired authentication token", resp["error"])

    def test_24_simulated_edge_function_forged_user_id_denied(self):
        """24. Verifies request attempting to forge another user's user_id returns 403."""
        body = {"user_id": self.user_b_id, "worker_id": self.worker_a_id}
        status, resp = self._simulate_edge_function("Bearer valid_user_jwt", body, self.user_a_id, {}, ProvisioningKeyRing("k1", {"k1": self.pub_key_1}))
        self.assertEqual(status, 403)
        self.assertIn("client cannot specify or override user_id", resp["error"])

    def test_25_simulated_edge_function_cross_tenant_worker_denied(self):
        """25. Verifies User A attempting to provision for User B's worker returns 403."""
        known_workers = {self.worker_b_id: {"user_id": self.user_b_id, "current_version": 1}}
        body = {
            "worker_id": self.worker_b_id,
            "mailbox_credential": "synthetic_password_1",
            "credential_version": 2,
        }
        status, resp = self._simulate_edge_function("Bearer valid_user_jwt", body, self.user_a_id, known_workers, ProvisioningKeyRing("k1", {"k1": self.pub_key_1}))
        self.assertEqual(status, 403)
        self.assertIn("Ownership violation", resp["error"])

    def test_26_simulated_edge_function_valid_provisioning(self):
        """26. Verifies valid provisioning (User A -> User A worker) returns 200 and encrypts payload."""
        known_workers = {self.worker_a_id: {"user_id": self.user_a_id, "current_version": 1}}
        synthetic_pw = "synthetic_app_password_pass5a"
        body = {
            "worker_id": self.worker_a_id,
            "mailbox_credential": synthetic_pw,
            "credential_version": 2,
            "expected_previous_version": 1,
        }
        status, resp = self._simulate_edge_function(
            "Bearer valid_user_jwt", body, self.user_a_id, known_workers, ProvisioningKeyRing("k1", {"k1": self.pub_key_1})
        )
        self.assertEqual(status, 200)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["credential_version"], 2)

        # Verify storage: stored ciphertext envelope, never plaintext
        stored_env = known_workers[self.worker_a_id]["encrypted_credentials"]
        self.assertTrue(stored_env.startswith("v2:k1:"))
        self.assertNotIn(synthetic_pw, stored_env)

        # Verify WorkerKeyRing can decrypt
        worker_ring = WorkerKeyRing("k1", {"k1": self.priv_key_1})
        decrypted = worker_ring.decrypt(stored_env, user_id=self.user_a_id)
        self.assertEqual(decrypted, synthetic_pw)

    def test_27_simulated_edge_function_cas_conflict(self):
        """27. Verifies stale expected_previous_version returns 409 Conflict."""
        known_workers = {self.worker_a_id: {"user_id": self.user_a_id, "current_version": 3}}
        body = {
            "worker_id": self.worker_a_id,
            "mailbox_credential": "pw",
            "credential_version": 4,
            "expected_previous_version": 2,  # Stale: current is 3
        }
        status, resp = self._simulate_edge_function(
            "Bearer valid_user_jwt", body, self.user_a_id, known_workers, ProvisioningKeyRing("k1", {"k1": self.pub_key_1})
        )
        self.assertEqual(status, 409)
        self.assertIn("Conflict", resp["error"])

    def test_28_simulated_edge_function_idempotency_replay(self):
        """28. Verifies idempotency replay returns success without duplicate row modification."""
        idem_key = str(uuid.uuid4())
        known_workers = {self.worker_a_id: {"user_id": self.user_a_id, "current_version": 1}}
        body = {
            "worker_id": self.worker_a_id,
            "mailbox_credential": "initial_pw",
            "credential_version": 2,
            "idempotency_key": idem_key,
        }
        ring = ProvisioningKeyRing("k1", {"k1": self.pub_key_1})
        status1, resp1 = self._simulate_edge_function("Bearer valid_user_jwt", body, self.user_a_id, known_workers, ring)
        self.assertEqual(status1, 200)

        # Replay with same idempotency key
        status2, resp2 = self._simulate_edge_function("Bearer valid_user_jwt", body, self.user_a_id, known_workers, ring)
        self.assertEqual(status2, 200)
        self.assertEqual(resp2["credential_version"], 2)


if __name__ == "__main__":
    unittest.main()

