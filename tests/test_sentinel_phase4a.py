"""
tests/test_sentinel_phase4a.py
Rigorous verification of EMAILSHIELD INDIA Sentinel Phase 4A:
PostgreSQL Database Security Boundary, SECURITY DEFINER RPCs, Privilege Separation,
Monotonic Versioning, Concurrency, and Tenant Isolation.
"""

import os
import re
import threading
import time
import unittest
import uuid
from typing import Dict, Any, List, Optional

PHASE4A_SQL_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "sentinel_phase4a_rpc.sql")
SCHEMA_SQL_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "sentinel_schema.sql")


class TestSentinelPhase4aSQLIntegrity(unittest.TestCase):
    """Verifies DDL structure, SECURITY DEFINER configuration, and permissions in SQL files."""

    @classmethod
    def setUpClass(cls):
        with open(PHASE4A_SQL_FILE, "r", encoding="utf-8") as f:
            cls.sql_phase4a = f.read()
        with open(SCHEMA_SQL_FILE, "r", encoding="utf-8") as f:
            cls.sql_schema = f.read()

    def test_01_all_five_rpcs_declared(self):
        """Verify all 5 required Phase 4A RPCs are defined."""
        expected_rpcs = [
            "rpc_set_encrypted_mailbox_credential",
            "rpc_claim_worker_lease",
            "rpc_fetch_leased_mailbox_credential",
            "rpc_renew_worker_lease",
            "rpc_release_worker_lease",
        ]
        for rpc in expected_rpcs:
            pattern = rf"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+public\.{re.escape(rpc)}"
            self.assertTrue(
                re.search(pattern, self.sql_phase4a, re.IGNORECASE),
                f"Missing RPC declaration: {rpc}"
            )

    def test_02_all_rpcs_use_security_definer_and_pinned_search_path(self):
        """Verify SECURITY DEFINER and SET search_path = pg_catalog, public on all 5 RPCs."""
        # Find each function block
        rpc_names = [
            "rpc_set_encrypted_mailbox_credential",
            "rpc_claim_worker_lease",
            "rpc_fetch_leased_mailbox_credential",
            "rpc_renew_worker_lease",
            "rpc_release_worker_lease",
        ]
        for rpc in rpc_names:
            # Match function definition until AS $$
            pattern = rf"FUNCTION\s+public\.{re.escape(rpc)}[\s\S]*?AS\s*\$\$"
            match = re.search(pattern, self.sql_phase4a, re.IGNORECASE)
            self.assertIsNotNone(match, f"Could not extract function header for {rpc}")
            header = match.group(0)

            self.assertIn("SECURITY DEFINER", header.upper(), f"{rpc} must be declared SECURITY DEFINER")
            self.assertTrue(
                re.search(r"SET\s+search_path\s*=\s*pg_catalog,\s*public", header, re.IGNORECASE),
                f"{rpc} must pin search_path = pg_catalog, public"
            )

    def test_03_privilege_separation_revokes_public_and_anon(self):
        """Verify that EXECUTE is explicitly REVOKED from PUBLIC and anon for all 5 RPCs."""
        rpc_names = [
            "rpc_set_encrypted_mailbox_credential",
            "rpc_claim_worker_lease",
            "rpc_fetch_leased_mailbox_credential",
            "rpc_renew_worker_lease",
            "rpc_release_worker_lease",
        ]
        for rpc in rpc_names:
            # Check REVOKE ALL FROM PUBLIC
            pub_pattern = rf"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.{re.escape(rpc)}[\s\S]*?FROM\s+PUBLIC"
            self.assertTrue(
                re.search(pub_pattern, self.sql_phase4a, re.IGNORECASE),
                f"Missing REVOKE ALL FROM PUBLIC for {rpc}"
            )
            # Check REVOKE ALL FROM anon
            anon_pattern = rf"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.{re.escape(rpc)}[\s\S]*?FROM\s+anon"
            self.assertTrue(
                re.search(anon_pattern, self.sql_phase4a, re.IGNORECASE),
                f"Missing REVOKE ALL FROM anon for {rpc}"
            )

    def test_04_authenticated_users_restricted_to_credential_provisioning_only(self):
        """Verify that authenticated users can ONLY execute rpc_set_encrypted_mailbox_credential."""
        # Must be granted on rpc_set_encrypted_mailbox_credential
        grant_auth = re.search(
            r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.rpc_set_encrypted_mailbox_credential[\s\S]*?TO\s+authenticated",
            self.sql_phase4a,
            re.IGNORECASE
        )
        self.assertIsNotNone(grant_auth, "authenticated role must be granted execute on rpc_set_encrypted_mailbox_credential")

        # Must be REVOKED from authenticated on the 4 worker RPCs
        worker_rpcs = [
            "rpc_claim_worker_lease",
            "rpc_fetch_leased_mailbox_credential",
            "rpc_renew_worker_lease",
            "rpc_release_worker_lease",
        ]
        for rpc in worker_rpcs:
            pattern = rf"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.{re.escape(rpc)}[\s\S]*?FROM\s+authenticated"
            self.assertTrue(
                re.search(pattern, self.sql_phase4a, re.IGNORECASE),
                f"authenticated role must be explicitly revoked from {rpc}"
            )

    def test_05_worker_rpcs_granted_to_dedicated_role_only(self):
        """Verify that the 4 worker RPCs are granted strictly to sentinel_worker_role."""
        worker_rpcs = [
            "rpc_claim_worker_lease",
            "rpc_fetch_leased_mailbox_credential",
            "rpc_renew_worker_lease",
            "rpc_release_worker_lease",
        ]
        for rpc in worker_rpcs:
            pattern = rf"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.{re.escape(rpc)}[\s\S]*?TO\s+sentinel_worker_role"
            self.assertTrue(
                re.search(pattern, self.sql_phase4a, re.IGNORECASE),
                f"sentinel_worker_role must be granted execute on {rpc}"
            )

    def test_06_atomic_locking_skip_locked_in_lease_claim(self):
        """Verify that rpc_claim_worker_lease utilizes FOR UPDATE SKIP LOCKED."""
        self.assertIn(
            "FOR UPDATE SKIP LOCKED",
            self.sql_phase4a.upper(),
            "rpc_claim_worker_lease must implement atomic FOR UPDATE SKIP LOCKED"
        )

    def test_07_envelope_regex_and_monotonic_check_present(self):
        """Verify envelope structure regex and version rollback rejection in SQL."""
        # Envelope regex check
        self.assertIn("v[1-9]:[0-9a-fA-F]{24}:[0-9a-fA-F]{34,}", self.sql_phase4a)
        # Monotonic rollback rejection
        self.assertTrue(
            re.search(r"p_credential_version\s*<=\s*v_current_version", self.sql_phase4a, re.IGNORECASE),
            "rpc_set_encrypted_mailbox_credential must reject credential versions <= current_version"
        )

    def test_08_additive_columns_defined(self):
        """Verify credential_version and credential_status additions on sentinel_mailboxes."""
        self.assertIn("credential_version INTEGER NOT NULL DEFAULT 1", self.sql_phase4a)
        self.assertIn("credential_status TEXT NOT NULL DEFAULT 'ACTIVE'", self.sql_phase4a)
        self.assertIn("CHECK (credential_status IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED'))", self.sql_phase4a)


class MockPostgresDatabase:
    """
    In-memory relational database engine emulating PostgreSQL row-level locking,
    SECURITY DEFINER context switching, and the exact semantics of the 5 Phase 4A RPCs.
    """

    def __init__(self):
        self.workers: Dict[str, Dict[str, Any]] = {}
        self.mailboxes: Dict[str, Dict[str, Any]] = {}
        self.locks: Dict[str, threading.Lock] = {}
        self.global_lock = threading.Lock()

    def _get_worker_lock(self, worker_id: str) -> threading.Lock:
        with self.global_lock:
            if worker_id not in self.locks:
                self.locks[worker_id] = threading.Lock()
            return self.locks[worker_id]

    def rpc_set_encrypted_mailbox_credential(
        self,
        auth_uid: Optional[str],
        p_worker_id: str,
        p_ciphertext: str,
        p_credential_version: int
    ) -> bool:
        # Step 1: Authentication guard
        if not auth_uid:
            raise PermissionError("Authentication required: caller identity is unauthenticated")

        # Step 2: Parameter validation
        if not p_worker_id:
            raise ValueError("p_worker_id cannot be null")
        if not p_ciphertext or not p_ciphertext.strip():
            raise ValueError("p_ciphertext cannot be null or empty")
        if len(p_ciphertext) > 4096:
            raise ValueError("p_ciphertext exceeds maximum allowed length of 4096 characters")
        if not re.match(r"^v[1-9]:[0-9a-fA-F]{24}:[0-9a-fA-F]{34,}$", p_ciphertext):
            raise ValueError("Invalid ciphertext envelope structure")
        if not isinstance(p_credential_version, int) or isinstance(p_credential_version, bool) or p_credential_version <= 0:
            raise ValueError("p_credential_version must be a positive integer")

        # Step 3: Verify tenant ownership of target worker
        worker = self.workers.get(p_worker_id)
        if not worker or worker.get("user_id") != auth_uid:
            raise PermissionError(f"Ownership violation: worker {p_worker_id} does not belong to caller {auth_uid}")

        # Step 4: Verify mailbox existence and check current version
        mailbox = next((m for m in self.mailboxes.values() if m.get("worker_id") == p_worker_id and m.get("user_id") == auth_uid), None)
        if not mailbox:
            return False

        # Step 5: Enforce monotonically increasing credential versions
        current_version = mailbox.get("credential_version", 1)
        if p_credential_version <= current_version:
            raise ValueError(f"Credential version rollback rejected: current version is {current_version}, proposed version is {p_credential_version}")

        # Step 6: Atomic update
        mailbox["encrypted_credentials"] = p_ciphertext
        mailbox["credential_version"] = p_credential_version
        mailbox["credential_status"] = "ACTIVE"
        mailbox["updated_at"] = time.time()
        return True

    def rpc_claim_worker_lease(
        self,
        p_worker_id: Optional[str],
        p_lease_owner_id: str,
        p_lease_duration_seconds: int = 300
    ) -> Optional[Dict[str, Any]]:
        if not p_lease_owner_id or not p_lease_owner_id.strip():
            raise ValueError("p_lease_owner_id cannot be null or empty")
        clean_owner = p_lease_owner_id.strip()
        if len(clean_owner) < 8 or len(clean_owner) > 255:
            raise ValueError("p_lease_owner_id must be between 8 and 255 characters")
        if not re.match(r"^[a-zA-Z0-9_\-\.:]+$", clean_owner):
            raise ValueError("p_lease_owner_id contains invalid characters")
        if not isinstance(p_lease_duration_seconds, int) or p_lease_duration_seconds < 30 or p_lease_duration_seconds > 900:
            raise ValueError("p_lease_duration_seconds must be between 30 and 900 seconds")

        now = time.time()
        candidates = []
        with self.global_lock:
            if p_worker_id:
                if p_worker_id in self.workers:
                    candidates = [self.workers[p_worker_id]]
            else:
                candidates = list(self.workers.values())

        for w in candidates:
            # Emulate FOR UPDATE SKIP LOCKED
            w_lock = self._get_worker_lock(w["id"])
            acquired = w_lock.acquire(blocking=False)
            if not acquired:
                continue  # SKIP LOCKED
            try:
                if w.get("desired_state") == "RUNNING":
                    exp = w.get("lease_expires_at")
                    if exp is None or exp < now:
                        # Claim atomic update
                        w["lease_owner"] = clean_owner
                        w["lease_expires_at"] = now + p_lease_duration_seconds
                        w["actual_state"] = "RUNNING"
                        w["last_heartbeat"] = now
                        w["updated_at"] = now
                        return {
                            "worker_id": w["id"],
                            "user_id": w["user_id"],
                            "poll_interval_seconds": w["poll_interval_seconds"],
                            "lease_expires_at": w["lease_expires_at"]
                        }
            finally:
                w_lock.release()

        return None

    def rpc_fetch_leased_mailbox_credential(
        self,
        p_worker_id: str,
        p_lease_owner_id: str
    ) -> Optional[Dict[str, Any]]:
        if not p_worker_id:
            raise ValueError("p_worker_id cannot be null")
        if not p_lease_owner_id or not p_lease_owner_id.strip():
            raise ValueError("p_lease_owner_id cannot be null or empty")

        clean_owner = p_lease_owner_id.strip()
        now = time.time()
        worker = self.workers.get(p_worker_id)
        if not worker:
            raise PermissionError("Worker not found")

        # Verify active, unexpired lease with matching owner
        if (
            worker.get("lease_owner") != clean_owner
            or worker.get("lease_expires_at", 0) <= now
            or worker.get("desired_state") != "RUNNING"
        ):
            raise PermissionError(f"Access denied: caller does not hold an active unexpired lease for worker {p_worker_id}")

        mailbox = next((m for m in self.mailboxes.values() if m.get("worker_id") == p_worker_id), None)
        if not mailbox or not mailbox.get("is_active") or mailbox.get("credential_status") != "ACTIVE":
            return None

        return {
            "mailbox_id": mailbox["id"],
            "user_id": mailbox["user_id"],
            "provider": mailbox["provider"],
            "email_address": mailbox["email_address"],
            "imap_host": mailbox["imap_host"],
            "imap_port": mailbox["imap_port"],
            "use_ssl": mailbox["use_ssl"],
            "auth_mechanism": mailbox["auth_mechanism"],
            "encrypted_credentials": mailbox["encrypted_credentials"],
            "credential_version": mailbox["credential_version"]
        }

    def rpc_renew_worker_lease(
        self,
        p_worker_id: str,
        p_lease_owner_id: str,
        p_lease_duration_seconds: int = 300
    ) -> float:
        if not p_worker_id:
            raise ValueError("p_worker_id cannot be null")
        if not p_lease_owner_id or not p_lease_owner_id.strip():
            raise ValueError("p_lease_owner_id cannot be null or empty")
        if not isinstance(p_lease_duration_seconds, int) or p_lease_duration_seconds < 30 or p_lease_duration_seconds > 900:
            raise ValueError("p_lease_duration_seconds must be between 30 and 900 seconds")

        clean_owner = p_lease_owner_id.strip()
        now = time.time()
        worker = self.workers.get(p_worker_id)
        if not worker:
            raise PermissionError("Worker not found")

        if (
            worker.get("lease_owner") != clean_owner
            or worker.get("lease_expires_at", 0) <= now
            or worker.get("desired_state") != "RUNNING"
        ):
            raise PermissionError(f"Renewal denied: active lease not found for worker {p_worker_id} and owner {clean_owner}")

        worker["lease_expires_at"] = now + p_lease_duration_seconds
        worker["last_heartbeat"] = now
        worker["updated_at"] = now
        return worker["lease_expires_at"]

    def rpc_release_worker_lease(
        self,
        p_worker_id: str,
        p_lease_owner_id: str
    ) -> bool:
        if not p_worker_id:
            raise ValueError("p_worker_id cannot be null")
        if not p_lease_owner_id or not p_lease_owner_id.strip():
            raise ValueError("p_lease_owner_id cannot be null or empty")

        clean_owner = p_lease_owner_id.strip()
        worker = self.workers.get(p_worker_id)
        if not worker or worker.get("lease_owner") != clean_owner:
            return False

        worker["lease_owner"] = None
        worker["lease_expires_at"] = None
        worker["actual_state"] = "STOPPED"
        worker["updated_at"] = time.time()
        return True


class TestSentinelPhase4aRPCBehaviors(unittest.TestCase):
    """Executes behavioral test cases against simulated PostgreSQL RPC execution semantics."""

    def setUp(self):
        self.db = MockPostgresDatabase()
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
            "lease_expires_at": None,
            "last_heartbeat": None,
            "updated_at": time.time()
        }

        self.mailbox_a = str(uuid.uuid4())
        self.valid_ct_v1 = "v1:0123456789abcdef01234567:aabbccddeeff00112233445566778899aabbccddeeff"
        self.db.mailboxes[self.mailbox_a] = {
            "id": self.mailbox_a,
            "user_id": self.user_a,
            "worker_id": self.worker_a,
            "provider": "gmail",
            "email_address": "user_a@gmail.com",
            "imap_host": "imap.gmail.com",
            "imap_port": 993,
            "use_ssl": True,
            "auth_mechanism": "APP_PASSWORD",
            "is_active": True,
            "encrypted_credentials": self.valid_ct_v1,
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
            "lease_expires_at": None,
            "last_heartbeat": None,
            "updated_at": time.time()
        }

    # =================================================================
    # Category 1: Authentication & Unauthenticated Denial
    # =================================================================
    def test_09_anonymous_rpc_denied(self):
        """Unauthenticated caller (auth.uid() is None) is strictly rejected by RPC 1."""
        with self.assertRaises(PermissionError):
            self.db.rpc_set_encrypted_mailbox_credential(
                auth_uid=None,
                p_worker_id=self.worker_a,
                p_ciphertext=self.valid_ct_v1,
                p_credential_version=2
            )

    # =================================================================
    # Category 2: Tenant Isolation
    # =================================================================
    def test_10_user_a_cannot_provision_user_b_credential(self):
        """User A cannot provision credentials using User B's worker_id."""
        new_ct = "v1:0123456789abcdef01234567:bbccddeeff00112233445566778899aabbccddeeffaa"
        with self.assertRaises(PermissionError):
            self.db.rpc_set_encrypted_mailbox_credential(
                auth_uid=self.user_a,
                p_worker_id=self.worker_b,  # Belongs to User B!
                p_ciphertext=new_ct,
                p_credential_version=2
            )

    def test_11_user_cannot_fetch_credential_without_active_lease(self):
        """User or unauthorized worker cannot fetch credentials without an active lease."""
        with self.assertRaises(PermissionError):
            self.db.rpc_fetch_leased_mailbox_credential(
                p_worker_id=self.worker_a,
                p_lease_owner_id="unauthorized_actor_123"
            )

    def test_12_user_a_cannot_renew_or_release_user_b_lease(self):
        """Worker leasing User A cannot renew or release a lease held by User B."""
        # Setup worker B with active lease held by worker-node-b
        self.db.workers[self.worker_b]["lease_owner"] = "worker-node-b-999"
        self.db.workers[self.worker_b]["lease_expires_at"] = time.time() + 300

        # Attempt renewal by wrong node
        with self.assertRaises(PermissionError):
            self.db.rpc_renew_worker_lease(
                p_worker_id=self.worker_b,
                p_lease_owner_id="worker-node-a-111",
                p_lease_duration_seconds=120
            )

        # Attempt release by wrong node
        released = self.db.rpc_release_worker_lease(
            p_worker_id=self.worker_b,
            p_lease_owner_id="worker-node-a-111"
        )
        self.assertFalse(released)
        # Lease remains intact
        self.assertEqual(self.db.workers[self.worker_b]["lease_owner"], "worker-node-b-999")

    # =================================================================
    # Category 3: Credential Validation & Monotonic Versioning
    # =================================================================
    def test_13_invalid_and_oversized_ciphertext_rejected(self):
        """Malformed envelope regex and payloads > 4096 bytes are rejected."""
        # Malformed format (missing nonce/header)
        with self.assertRaises(ValueError):
            self.db.rpc_set_encrypted_mailbox_credential(
                auth_uid=self.user_a,
                p_worker_id=self.worker_a,
                p_ciphertext="not_a_valid_envelope_format",
                p_credential_version=2
            )

        # Oversized payload
        oversized = "v1:" + ("a" * 24) + ":" + ("b" * 4100)
        with self.assertRaises(ValueError):
            self.db.rpc_set_encrypted_mailbox_credential(
                auth_uid=self.user_a,
                p_worker_id=self.worker_a,
                p_ciphertext=oversized,
                p_credential_version=2
            )

    def test_14_credential_version_rollback_rejected(self):
        """Enforces strictly monotonic versions: version <= current_version is rejected."""
        # Current version is 1. Attempt version 1 rollback (equal)
        new_ct = "v1:0123456789abcdef01234567:bbccddeeff00112233445566778899aabbccddeeffaa"
        with self.assertRaises(ValueError):
            self.db.rpc_set_encrypted_mailbox_credential(
                auth_uid=self.user_a,
                p_worker_id=self.worker_a,
                p_ciphertext=new_ct,
                p_credential_version=1  # Rollback/equal
            )

        # Attempt version 0 (negative/zero)
        with self.assertRaises(ValueError):
            self.db.rpc_set_encrypted_mailbox_credential(
                auth_uid=self.user_a,
                p_worker_id=self.worker_a,
                p_ciphertext=new_ct,
                p_credential_version=0
            )

    def test_15_valid_newer_credential_version_accepted(self):
        """Increasing credential version (v=2 > v=1) succeeds and updates metadata."""
        new_ct = "v1:0123456789abcdef01234567:bbccddeeff00112233445566778899aabbccddeeffaa"
        success = self.db.rpc_set_encrypted_mailbox_credential(
            auth_uid=self.user_a,
            p_worker_id=self.worker_a,
            p_ciphertext=new_ct,
            p_credential_version=2
        )
        self.assertTrue(success)
        mb = self.db.mailboxes[self.mailbox_a]
        self.assertEqual(mb["credential_version"], 2)
        self.assertEqual(mb["encrypted_credentials"], new_ct)
        self.assertEqual(mb["credential_status"], "ACTIVE")

    # =================================================================
    # Category 4: Lease Security & State Machine
    # =================================================================
    def test_16_stopped_worker_cannot_be_claimed(self):
        """Workers with desired_state = 'STOPPED' cannot be claimed."""
        self.db.workers[self.worker_a]["desired_state"] = "STOPPED"
        claim = self.db.rpc_claim_worker_lease(
            p_worker_id=self.worker_a,
            p_lease_owner_id="worker-daemon-alpha"
        )
        self.assertIsNone(claim)

    def test_17_expired_lease_can_be_reclaimed(self):
        """Lease with expired timestamp in the past can be reclaimed by another worker."""
        # Lease expired 10 seconds ago
        self.db.workers[self.worker_a]["lease_owner"] = "dead-worker-node"
        self.db.workers[self.worker_a]["lease_expires_at"] = time.time() - 10

        claim = self.db.rpc_claim_worker_lease(
            p_worker_id=self.worker_a,
            p_lease_owner_id="new-worker-daemon-beta",
            p_lease_duration_seconds=180
        )
        self.assertIsNotNone(claim)
        self.assertEqual(claim["worker_id"], self.worker_a)
        self.assertEqual(self.db.workers[self.worker_a]["lease_owner"], "new-worker-daemon-beta")

    def test_18_active_lease_cannot_be_stolen(self):
        """Active unexpired lease cannot be claimed by another worker."""
        self.db.workers[self.worker_a]["lease_owner"] = "active-worker-daemon"
        self.db.workers[self.worker_a]["lease_expires_at"] = time.time() + 200

        claim = self.db.rpc_claim_worker_lease(
            p_worker_id=self.worker_a,
            p_lease_owner_id="intruder-worker-gamma"
        )
        self.assertIsNone(claim)
        self.assertEqual(self.db.workers[self.worker_a]["lease_owner"], "active-worker-daemon")

    def test_19_lease_lifecycle_claim_fetch_renew_release(self):
        """Complete successful lifecycle: claim -> fetch credentials -> renew -> release."""
        owner = "valid-worker-daemon-node-01"
        # 1. Claim
        claim = self.db.rpc_claim_worker_lease(
            p_worker_id=self.worker_a,
            p_lease_owner_id=owner,
            p_lease_duration_seconds=120
        )
        self.assertIsNotNone(claim)

        # 2. Fetch credential
        cred = self.db.rpc_fetch_leased_mailbox_credential(
            p_worker_id=self.worker_a,
            p_lease_owner_id=owner
        )
        self.assertIsNotNone(cred)
        self.assertEqual(cred["email_address"], "user_a@gmail.com")
        self.assertEqual(cred["encrypted_credentials"], self.valid_ct_v1)

        # 3. Renew
        new_exp = self.db.rpc_renew_worker_lease(
            p_worker_id=self.worker_a,
            p_lease_owner_id=owner,
            p_lease_duration_seconds=300
        )
        self.assertGreater(new_exp, claim["lease_expires_at"])

        # 4. Release
        released = self.db.rpc_release_worker_lease(
            p_worker_id=self.worker_a,
            p_lease_owner_id=owner
        )
        self.assertTrue(released)
        self.assertIsNone(self.db.workers[self.worker_a]["lease_owner"])
        self.assertEqual(self.db.workers[self.worker_a]["actual_state"], "STOPPED")

    # =================================================================
    # Category 5: Real Concurrency & Mutual Exclusion Under Contention
    # =================================================================
    def test_20_concurrent_worker_contention_mutual_exclusion(self):
        """
        Multithreaded contention: 20 simultaneous workers race to claim
        the same single eligible tenant worker using row-level locking.
        Expected: Exactly 1 worker wins; 19 workers receive None.
        """
        results = []
        errors = []
        num_threads = 20
        barrier = threading.Barrier(num_threads)

        def worker_task(thread_id: int):
            owner_id = f"worker-race-node-{thread_id:02d}"
            try:
                # Synchronize threads at barrier before firing simultaneous claim
                barrier.wait()
                res = self.db.rpc_claim_worker_lease(
                    p_worker_id=self.worker_a,
                    p_lease_owner_id=owner_id,
                    p_lease_duration_seconds=60
                )
                results.append((owner_id, res))
            except Exception as e:
                errors.append((owner_id, e))

        threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Unexpected errors during concurrent claim: {errors}")
        successful_claims = [r for r in results if r[1] is not None]
        failed_claims = [r for r in results if r[1] is None]

        self.assertEqual(
            len(successful_claims), 1,
            f"Mutual exclusion failure: expected exactly 1 successful claim, got {len(successful_claims)}"
        )
        self.assertEqual(len(failed_claims), num_threads - 1)

        winning_owner, claim_data = successful_claims[0]
        self.assertEqual(claim_data["worker_id"], self.worker_a)
        self.assertEqual(self.db.workers[self.worker_a]["lease_owner"], winning_owner)


if __name__ == "__main__":
    unittest.main()
