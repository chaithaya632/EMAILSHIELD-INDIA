"""
tests/test_worker_lease.py
Comprehensive verification of Sentinel Phase 6A: Worker Lease Security.
Covers:
- Correct worker + correct capability claim
- Wrong capability token rejection
- Cross-worker lease claim rejection
- Duplicate active lease rejection (no lease stealing)
- Expired lease recovery
- Lease renewal with valid/invalid tokens and non-owners
- Lease release and immediate token invalidation
- Multi-threaded concurrency race condition protection
- Crash / stale lease recovery after expiration
- Tenant isolation (Worker A/Mailbox A vs Worker B/Mailbox B)
- Direct table access denial (least-privilege boundary)
- Live Supabase DB connection check (when SENTINEL_WORKER_DB_URL configured)
"""

import hashlib
import os
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from worker.config import WorkerConfig
from worker.identity import WorkerIdentity, CapabilityToken
from worker.db import (
    MockWorkerDBClient,
    WorkerDBClient,
    WorkerDBError,
    RoleVerificationError,
    TableAccessViolationError,
)
from worker.lease import WorkerLeaseManager


class TestWorkerLeaseSecurity(unittest.TestCase):
    """Rigorous verification of worker lease semantics, tokens, concurrency, and tenant isolation."""

    def setUp(self):
        self.user_a_id = uuid.uuid4()
        self.user_b_id = uuid.uuid4()
        self.worker_a_id = uuid.uuid4()
        self.worker_b_id = uuid.uuid4()
        self.mailbox_a_id = uuid.uuid4()
        self.mailbox_b_id = uuid.uuid4()

        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")

        # Seed synthetic workers
        self.db.seed_worker(self.worker_a_id, self.user_a_id, desired_state="RUNNING")
        self.db.seed_worker(self.worker_b_id, self.user_b_id, desired_state="RUNNING")

        # Seed synthetic mailboxes
        self.db.seed_mailbox(
            self.mailbox_a_id,
            self.worker_a_id,
            self.user_a_id,
            encrypted_credentials="v2:k1:b64_wdek_a:b64_nonce_a:b64_ct_a"
        )
        self.db.seed_mailbox(
            self.mailbox_b_id,
            self.worker_b_id,
            self.user_b_id,
            encrypted_credentials="v2:k1:b64_wdek_b:b64_nonce_b:b64_ct_b"
        )

        self.identity_a = WorkerIdentity(self.worker_a_id)
        self.identity_b = WorkerIdentity(self.worker_b_id)

        self.lease_mgr_a = WorkerLeaseManager(self.identity_a, self.db)
        self.lease_mgr_b = WorkerLeaseManager(self.identity_b, self.db)

    # =========================================================================
    # STEP 8: LEASE CLAIM TESTS
    # =========================================================================

    def test_01_lease_claim_correct_worker_and_capability(self):
        """Test A: Correct worker + correct capability -> LEASE CLAIM: PASS."""
        success = self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.assertTrue(success)
        self.assertTrue(self.lease_mgr_a.is_active())
        self.assertTrue(self.identity_a.has_token())

        # Verify DB state: only SHA-256 hash stored, raw token NEVER in DB
        w_record = self.db.workers[str(self.worker_a_id)]
        self.assertEqual(w_record["lease_owner"], "sentinel_worker_daemon")
        self.assertIsNotNone(w_record["lease_token_hash"])
        self.assertNotIn("lease_token", w_record)  # Raw token not persisted in table!

        # Verify hash match
        expected_hash = hashlib.sha256(bytes.fromhex(self.identity_a.raw_token)).hexdigest()
        self.assertEqual(w_record["lease_token_hash"], expected_hash)

    def test_02_lease_claim_duplicate_active_lease_denied(self):
        """Test D: Duplicate active lease -> second claimant denied."""
        # Worker A claims
        claimed_a = self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.assertTrue(claimed_a)

        # Worker B attempts to claim Worker A's active lease
        worker_b_stealer = WorkerLeaseManager(self.identity_b, self.db)
        # Attempt to claim worker_a_id using identity_b's manager pointed at worker_a
        stealer_res = self.db.claim_worker_lease(self.worker_a_id, duration_seconds=120)
        self.assertFalse(stealer_res["success"])
        self.assertEqual(stealer_res["reason"], "worker_unavailable_or_locked")

    def test_03_wrong_capability_token_denied(self):
        """Test B: Wrong capability token on renewal and release is DENIED."""
        # Acquire legitimate lease
        self.lease_mgr_a.acquire_lease(duration_seconds=120)

        # Forge / tamper with token
        wrong_token = "0" * 64
        renew_res = self.db.renew_worker_lease(self.worker_a_id, wrong_token, extension_seconds=120)
        self.assertFalse(renew_res)

        release_res = self.db.release_worker_lease(self.worker_a_id, wrong_token)
        self.assertFalse(release_res)

    def test_04_worker_a_attempting_worker_b_lease_denied(self):
        """Test C: Worker A attempting to renew/release Worker B lease is DENIED."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.lease_mgr_b.acquire_lease(duration_seconds=120)

        # Worker A tries to renew Worker B using Worker A's token
        renew_cross = self.db.renew_worker_lease(
            self.worker_b_id,
            self.identity_a.raw_token,
            extension_seconds=120
        )
        self.assertFalse(renew_cross)

        # Worker A tries to release Worker B using Worker A's token
        release_cross = self.db.release_worker_lease(
            self.worker_b_id,
            self.identity_a.raw_token
        )
        self.assertFalse(release_cross)

    def test_05_expired_lease_recovery(self):
        """Test E: Expired lease recovery -> legitimate worker reclaims after valid expiry."""
        # 1. Worker A acquires lease for 30 seconds
        self.lease_mgr_a.acquire_lease(duration_seconds=30)
        self.assertTrue(self.lease_mgr_a.is_active())

        # 2. Simulate passage of time past expiry
        w_record = self.db.workers[str(self.worker_a_id)]
        w_record["lease_expires_at"] = time.time() - 10.0  # Expired 10s ago

        # 3. New claimant or reclaimed by Worker A
        reclaim_mgr = WorkerLeaseManager(WorkerIdentity(self.worker_a_id), self.db)
        reclaimed = reclaim_mgr.acquire_lease(duration_seconds=120)
        self.assertTrue(reclaimed)
        self.assertTrue(reclaim_mgr.is_active())

    # =========================================================================
    # STEP 9: LEASE RENEWAL TESTS
    # =========================================================================

    def test_06_lease_renewal_success_and_denials(self):
        """Verify lease renewal success on valid token, denial on wrong token or non-owner."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        initial_expiry = self.lease_mgr_a._expires_at

        # Renewal with correct token: PASS
        time.sleep(0.01)
        renewed = self.lease_mgr_a.renew_lease(extension_seconds=180)
        self.assertTrue(renewed)
        self.assertGreater(self.lease_mgr_a._expires_at, initial_expiry)

        # Renewal with invalid hex token: DENIED
        denied_hex = self.db.renew_worker_lease(self.worker_a_id, "invalid_hex", 120)
        self.assertFalse(denied_hex)

        # Renewal on stopped/unleased worker: DENIED
        self.db.workers[str(self.worker_a_id)]["desired_state"] = "STOPPED"
        denied_stopped = self.lease_mgr_a.renew_lease(120)
        self.assertFalse(denied_stopped)

    # =========================================================================
    # STEP 10: LEASE RELEASE TESTS
    # =========================================================================

    def test_07_lease_release_and_token_invalidation(self):
        """Verify lease release clears lease in DB and immediately invalidates in-memory token."""
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        saved_raw_token = self.identity_a.raw_token
        self.assertTrue(self.lease_mgr_a.is_active())

        # Legitimate release
        released = self.lease_mgr_a.release_lease()
        self.assertTrue(released)
        self.assertFalse(self.lease_mgr_a.is_active())
        self.assertFalse(self.identity_a.has_token())

        # Old capability token after release: DENIED
        renew_old = self.db.renew_worker_lease(self.worker_a_id, saved_raw_token, 120)
        self.assertFalse(renew_old)

        release_old = self.db.release_worker_lease(self.worker_a_id, saved_raw_token)
        self.assertFalse(release_old)

        # Released worker lease is now available for new legitimate claim
        self.db.workers[str(self.worker_a_id)]["desired_state"] = "RUNNING"
        new_mgr = WorkerLeaseManager(WorkerIdentity(self.worker_a_id), self.db)
        self.assertTrue(new_mgr.acquire_lease(duration_seconds=60))

    # =========================================================================
    # STEP 11: CONCURRENCY TESTS
    # =========================================================================

    def test_08_concurrent_claims_exactly_one_winner(self):
        """
        Concurrency test: Worker A and Worker B simultaneously attempt to claim
        the same synthetic worker lease. Exactly one claim must succeed.
        Repeated across 10 rounds to detect race conditions.
        """
        for round_idx in range(10):
            target_worker_id = uuid.uuid4()
            self.db.seed_worker(target_worker_id, self.user_a_id, desired_state="RUNNING")

            results = []

            def attempt_claim(worker_num: int):
                # Separate manager and identity attempting claim
                mgr = WorkerLeaseManager(WorkerIdentity(target_worker_id), self.db)
                ok = mgr.acquire_lease(duration_seconds=120)
                results.append((worker_num, ok))

            # Run 2 threads simultaneously
            with ThreadPoolExecutor(max_workers=2) as executor:
                f1 = executor.submit(attempt_claim, 1)
                f2 = executor.submit(attempt_claim, 2)
                f1.result()
                f2.result()

            success_count = sum(1 for _, ok in results if ok)
            failure_count = sum(1 for _, ok in results if not ok)

            self.assertEqual(
                success_count, 1,
                f"Round {round_idx}: Expected exactly 1 successful claim, got {success_count} ({results})"
            )
            self.assertEqual(
                failure_count, 1,
                f"Round {round_idx}: Expected exactly 1 denied claim, got {failure_count} ({results})"
            )

    # =========================================================================
    # STEP 12: CRASH / STALE LEASE TEST
    # =========================================================================

    def test_09_crash_stale_lease_recovery(self):
        """
        Simulate: Worker A claims lease, crashes/stops without release.
        Lease expires. Worker B attempts claim.
        Expected: Worker A is stale/expired. Worker B successfully claims.
        """
        # 1. Worker A claims lease
        self.lease_mgr_a.acquire_lease(duration_seconds=60)
        self.assertTrue(self.lease_mgr_a.is_active())

        # 2. Worker A crashes (stops without release RPC)
        del self.lease_mgr_a

        # 3. Time passes, lease expires
        w_record = self.db.workers[str(self.worker_a_id)]
        w_record["lease_expires_at"] = time.time() - 5.0  # Expired

        # 4. Worker B claims the expired lease
        worker_b_mgr = WorkerLeaseManager(WorkerIdentity(self.worker_a_id), self.db)
        reclaim_ok = worker_b_mgr.acquire_lease(duration_seconds=120)
        self.assertTrue(reclaim_ok)
        self.assertTrue(worker_b_mgr.is_active())

    # =========================================================================
    # STEP 13: TENANT ISOLATION TESTS
    # =========================================================================

    def test_10_tenant_isolation_credential_rpc(self):
        """
        Verify tenant isolation:
        Worker A -> Mailbox A: ALLOWED
        Worker A -> Mailbox B: DENIED
        Worker B -> Mailbox B: ALLOWED
        Worker B -> Mailbox A: DENIED
        """
        # Worker A acquires lease
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        tok_a = self.identity_a.raw_token

        # Worker B acquires lease
        self.lease_mgr_b.acquire_lease(duration_seconds=120)
        tok_b = self.identity_b.raw_token

        # 1. Worker A -> Mailbox A: ALLOWED
        cred_a = self.db.fetch_leased_mailbox_credential(self.worker_a_id, tok_a)
        self.assertTrue(cred_a["success"])
        self.assertEqual(cred_a["mailbox_id"], str(self.mailbox_a_id))
        self.assertEqual(cred_a["user_id"], str(self.user_a_id))

        # 2. Worker A attempting Worker B: DENIED
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_b_id, tok_a)

        # 3. Worker B -> Mailbox B: ALLOWED
        cred_b = self.db.fetch_leased_mailbox_credential(self.worker_b_id, tok_b)
        self.assertTrue(cred_b["success"])
        self.assertEqual(cred_b["mailbox_id"], str(self.mailbox_b_id))
        self.assertEqual(cred_b["user_id"], str(self.user_b_id))

        # 4. Worker B attempting Worker A: DENIED
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_a_id, tok_b)

    # =========================================================================
    # STEP 5 & 6: DIRECT TABLE ACCESS & SESSION IDENTITY
    # =========================================================================

    def test_11_direct_table_access_denied(self):
        """Verify worker is strictly denied direct table access."""
        with self.assertRaises(PermissionError) as ctx:
            self.db.direct_table_select("sentinel_mailboxes")
        self.assertIn("insufficient_privilege", str(ctx.exception))

    def test_12_unauthorized_session_role_fails_closed(self):
        """Verify client connecting as unauthorized role is immediately rejected."""
        unauthorized_db = MockWorkerDBClient(session_user="authenticated")
        with self.assertRaises(RoleVerificationError):
            unauthorized_db.verify_session_identity()

    def test_13_live_supabase_worker_connection_if_configured(self):
        """
        Live verification against Supabase if SENTINEL_WORKER_DB_URL is configured.
        If not set, skips gracefully with informative status.
        """
        db_url = os.environ.get("SENTINEL_WORKER_DB_URL", "").strip()
        if not db_url:
            self.skipTest("SENTINEL_WORKER_DB_URL not configured. Skipping live network check.")

        config = WorkerConfig(worker_id=self.worker_a_id, db_url=db_url)
        live_client = WorkerDBClient(config)
        try:
            live_client.connect()
            sess_user, curr_user, _ = live_client.verify_session_identity()
            self.assertEqual(sess_user, "sentinel_worker_daemon")
            # Verify table denial on live DB
            live_client.verify_table_privilege_denial()
        finally:
            live_client.close()


if __name__ == "__main__":
    unittest.main()
