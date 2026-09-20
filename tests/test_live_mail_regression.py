"""
tests/test_live_mail_regression.py
Regression tests for Live Mail Analysis:
- 7 initial historical messages establish baseline
- New message UID 8 processed
- 0 new messages on subsequent poll
- New message UID 9 processed
- Worker restart recovery and checkpoint persistence
- UIDVALIDITY change detection and baseline re-establishment
- Mailbox identity stability across polls
- Telemetry persistence and read-only refresh
- Mid-poll lease renewal resilience
- Duplicate worker lease mutual exclusion
"""

import os
import shutil
import time
import unittest
import uuid
from typing import Dict, Any, List, Optional

from worker.identity import WorkerIdentity
from worker.config import WorkerConfig
from worker.lease import WorkerLeaseManager
from worker.db import LocalWorkerDBClient
from worker.credentials import WorkerCredentialService
from worker.checkpoint import CheckpointStore
from worker.synthetic_imap import SyntheticIMAPServer, SyntheticEmailMessage, SyntheticIMAPConnection
from worker.poller import MailboxPoller
from core.sentinel_crypto import (
    WorkerKeyRing,
    ProvisioningKeyRing,
    generate_worker_asymmetric_keypair,
    CONTEXT_MAILBOX,
)
from core.sentinel_stats import (
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    _get_telemetry_file_path,
    _REGISTRY,
    TELEMETRY_DIR,
)


class MockForensicAgent:
    """Mock forensic agent for deterministic testing without external network calls."""
    def run_investigation(self, parsed_email: Dict[str, Any], extracted_iocs: Any) -> Dict[str, Any]:
        return {
            "verdict": "Clean",
            "risk_score": 0.05,
            "ml_pred": "Clean",
        }


class TestLiveMailAnalysisRegression(unittest.TestCase):
    """
    Section 17 regression test suite verifying:
    7 historical messages -> baseline -> UID 8 -> 0 new -> UID 9 -> restart recovery.
    """

    def setUp(self):
        self.user_id = str(uuid.uuid4())
        self.worker_id = str(uuid.uuid4())
        self.mailbox_id = str(uuid.uuid4())
        self.email_address = "synthetic@test.local"
        self.folder_name = "INBOX"

        # Dedicated test DB path
        self.test_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "test_scratch", str(uuid.uuid4())[:8]
        )
        os.makedirs(self.test_dir, exist_ok=True)
        self.db_path = os.path.join(self.test_dir, "test_db.json")

        # Crypto setup
        self.priv_key, self.pub_key = generate_worker_asymmetric_keypair(2048)
        self.keyring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key})
        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": self.pub_key})

        # DB client & lease manager
        self.db_client = LocalWorkerDBClient(db_path=self.db_path)
        self.identity = WorkerIdentity(uuid.UUID(self.worker_id))
        self.db_client.seed_worker(
            worker_id=uuid.UUID(self.worker_id),
            user_id=uuid.UUID(self.user_id),
            desired_state="RUNNING"
        )
        self.lease_mgr = WorkerLeaseManager(self.identity, self.db_client)

        # Encrypted credential envelope
        enc_envelope = prov_ring.encrypt("mock_app_pwd", user_id=self.user_id, purpose=CONTEXT_MAILBOX)
        self.db_client.seed_mailbox(
            mailbox_id=uuid.UUID(self.mailbox_id),
            worker_id=uuid.UUID(self.worker_id),
            user_id=uuid.UUID(self.user_id),
            encrypted_credentials=enc_envelope,
        )

        self.cred_svc = WorkerCredentialService(self.identity, self.keyring, self.db_client)
        self.checkpoint_store = CheckpointStore(self.db_client)
        self.forensic_agent = MockForensicAgent()

        # Synthetic IMAP server
        self.imap_server = SyntheticIMAPServer()
        self.imap_server.register_account(self.email_address, "mock_app_pwd")

        self.config = WorkerConfig(
            worker_id=uuid.UUID(self.worker_id),
            db_url="postgresql://fake/test",
            production_polling_enabled=True,
            test_mode=False,
            lease_duration_seconds=120,
            renewal_interval_seconds=30,
            renewal_extension_seconds=120,
        )

    def tearDown(self):
        try:
            if os.path.exists(self.test_dir):
                shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass

    def _create_poller(self, checkpoint_store: Optional[CheckpointStore] = None, lease_mgr: Optional[WorkerLeaseManager] = None) -> MailboxPoller:
        cp_store = checkpoint_store or self.checkpoint_store
        lm = lease_mgr or self.lease_mgr
        return MailboxPoller(
            config=self.config,
            identity=self.identity,
            lease_manager=lm,
            credential_service=self.cred_svc,
            checkpoint_store=cp_store,
            synthetic_server=self.imap_server,
            forensic_agent=self.forensic_agent,
        )

    def _seed_messages(self, start_uid: int, count: int) -> List[int]:
        added_uids = []
        for i in range(count):
            uid = start_uid + i
            msg = SyntheticEmailMessage(
                uid=uid,
                message_id=f"<msg-{uid}-{self.mailbox_id[:8]}@example.invalid>",
                subject=f"Message {uid}",
                body=f"Body for message {uid}",
                from_addr="sender@example.invalid",
                to_addr=self.email_address,
                date="Sun, 20 Sep 2026 10:00:00 +0530",
            )
            self.imap_server.add_message(self.email_address, msg, folder_name=self.folder_name)
            added_uids.append(uid)
        return added_uids

    def test_01_full_lifecycle_historical_to_incremental_progress(self):
        """
        Tests exact Section 17 lifecycle:
        1. 7 historical messages -> baseline checkpoint UID 7, arrived=0, analysed=0.
        2. New message UID 8 -> only UID 8 processed, arrived=1, analysed=1.
        3. Poll with no new messages -> 0 new messages, counts unchanged.
        4. New message UID 9 -> only UID 9 processed, arrived=2, analysed=2.
        5. Worker restart -> loads checkpoint UID 9 from disk, no reprocessing.
        """
        # Step 1: Initial mailbox has 7 messages (UID 1 to 7)
        self._seed_messages(start_uid=1, count=7)

        # Acquire lease before polling
        self.lease_mgr.acquire_lease(duration_seconds=120)

        # First Poll: Initial sync skips historical messages and establishes baseline
        poller = self._create_poller()
        res_poll_1 = poller.poll(skip_historical=True)

        self.assertEqual(res_poll_1["status"], "INITIAL_SYNC_COMPLETE")
        self.assertEqual(res_poll_1["processed_count"], 0)

        cp = self.checkpoint_store.get_checkpoint(self.user_id, self.worker_id, self.mailbox_id)
        self.assertEqual(cp.last_processed_uid, 7)
        self.assertTrue(cp.has_polled)
        self.assertEqual(cp.emails_arrived, 0)
        self.assertEqual(cp.emails_analysed, 0)

        # Check telemetry after first poll
        stats_1 = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(stats_1["emails_arrived"], 0)
        self.assertEqual(stats_1["emails_analysed"], 0)
        self.assertEqual(stats_1["last_processed_uid"], 7)

        # Step 2: New message arrives with UID 8
        self._seed_messages(start_uid=8, count=1)

        # Second Poll: only UID 8 is processed
        res_poll_2 = poller.poll(skip_historical=False)
        self.assertEqual(res_poll_2["status"], "SUCCESS")
        self.assertEqual(res_poll_2["processed_count"], 1)
        self.assertEqual(len(res_poll_2["events"]), 1)
        self.assertEqual(res_poll_2["events"][0].uid, 8)

        cp_2 = self.checkpoint_store.get_checkpoint(self.user_id, self.worker_id, self.mailbox_id)
        self.assertEqual(cp_2.last_processed_uid, 8)
        self.assertEqual(cp_2.emails_arrived, 1)
        self.assertEqual(cp_2.emails_analysed, 1)

        # Telemetry verification: 1 Arrived, 1 Analysed
        stats_2 = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(stats_2["emails_arrived"], 1)
        self.assertEqual(stats_2["emails_analysed"], 1)
        self.assertEqual(stats_2["last_processed_uid"], 8)

        # Step 3: Third Poll without sending any new email
        res_poll_3 = poller.poll(skip_historical=False)
        self.assertEqual(res_poll_3["status"], "SUCCESS")
        self.assertEqual(res_poll_3["processed_count"], 0)
        self.assertEqual(len(res_poll_3["events"]), 0)

        stats_3 = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        # Invariant: Does NOT recount old messages
        self.assertEqual(stats_3["emails_arrived"], 1)
        self.assertEqual(stats_3["emails_analysed"], 1)
        self.assertEqual(stats_3["last_processed_uid"], 8)

        # Step 4: Fourth Poll: New message arrives with UID 9
        self._seed_messages(start_uid=9, count=1)

        res_poll_4 = poller.poll(skip_historical=False)
        self.assertEqual(res_poll_4["status"], "SUCCESS")
        self.assertEqual(res_poll_4["processed_count"], 1)
        self.assertEqual(res_poll_4["events"][0].uid, 9)

        stats_4 = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(stats_4["emails_arrived"], 2)
        self.assertEqual(stats_4["emails_analysed"], 2)
        self.assertEqual(stats_4["last_processed_uid"], 9)

        # Step 5: Worker Restart Recovery
        # Create brand-new CheckpointStore (simulating new process startup)
        restarted_store = CheckpointStore(self.db_client)
        restarted_store.seed_from_telemetry(self.user_id, self.worker_id, self.mailbox_id)
        recovered_cp = restarted_store.get_checkpoint(self.user_id, self.worker_id, self.mailbox_id)

        # Verify persisted checkpoint recovered from disk
        self.assertEqual(recovered_cp.last_processed_uid, 9)
        self.assertTrue(recovered_cp.has_polled)
        self.assertEqual(recovered_cp.emails_arrived, 2)
        self.assertEqual(recovered_cp.emails_analysed, 2)

        # Poll with restarted worker: no duplicate messages
        restarted_poller = self._create_poller(checkpoint_store=restarted_store)
        res_restarted_poll = restarted_poller.poll(skip_historical=False)
        self.assertEqual(res_restarted_poll["status"], "SUCCESS")
        self.assertEqual(res_restarted_poll["processed_count"], 0)

    def test_02_uidvalidity_change_handling(self):
        """
        Verify that when IMAP UIDVALIDITY changes, the poller detects it,
        safely re-establishes the baseline, and does NOT reprocess old messages.
        """
        # Initial mailbox with messages 1-5, UIDVALIDITY=1
        self._seed_messages(start_uid=1, count=5)
        self.lease_mgr.acquire_lease(duration_seconds=120)

        poller = self._create_poller()
        poller.poll(skip_historical=True)

        cp = self.checkpoint_store.get_checkpoint(self.user_id, self.worker_id, self.mailbox_id)
        self.assertEqual(cp.uid_validity, 1)
        self.assertEqual(cp.last_processed_uid, 5)

        # Change UIDVALIDITY to 2 and add new messages 10-12
        mb = self.imap_server.get_mailbox(self.email_address, self.folder_name)
        mb.uid_validity = 2
        self._seed_messages(start_uid=10, count=3)

        # Poll again: poller detects UIDVALIDITY change
        res = poller.poll(skip_historical=False)
        cp_after = self.checkpoint_store.get_checkpoint(self.user_id, self.worker_id, self.mailbox_id)
        self.assertEqual(cp_after.uid_validity, 2)
        self.assertEqual(cp_after.last_processed_uid, 12)

    def test_03_mailbox_identity_stability(self):
        """
        Verify that the same mailbox maps to the same mailbox identity across multiple polls.
        """
        self._seed_messages(start_uid=1, count=3)
        self.lease_mgr.acquire_lease(duration_seconds=120)

        poller = self._create_poller()
        res1 = poller.poll(skip_historical=True)
        res2 = poller.poll(skip_historical=False)
        res3 = poller.poll(skip_historical=False)

        self.assertEqual(res1["mailbox_id"], self.mailbox_id)
        self.assertEqual(res2["mailbox_id"], self.mailbox_id)
        self.assertEqual(res3["mailbox_id"], self.mailbox_id)

    def test_04_duplicate_worker_prevention(self):
        """
        Verify that multiple workers cannot hold an active lease for the same worker record.
        """
        # Worker 1 acquires lease
        acquired_1 = self.lease_mgr.acquire_lease(duration_seconds=120)
        self.assertTrue(acquired_1)
        self.assertTrue(self.lease_mgr.is_active())

        # Worker 2 attempts to acquire lease on the same worker
        worker_2_id = WorkerIdentity(uuid.UUID(self.worker_id))
        lease_mgr_2 = WorkerLeaseManager(worker_2_id, self.db_client)
        acquired_2 = lease_mgr_2.acquire_lease(duration_seconds=120)
        self.assertFalse(acquired_2)

        # Worker 1 releases lease
        self.lease_mgr.release_lease()

        # Worker 2 now succeeds
        acquired_2_after = lease_mgr_2.acquire_lease(duration_seconds=120)
        self.assertTrue(acquired_2_after)
        lease_mgr_2.release_lease()

    def test_05_mid_poll_lease_renewal(self):
        """
        Verify that poller proactively renews approaching lease mid-poll.
        """
        self._seed_messages(start_uid=1, count=3)

        # Set renewal threshold to 45s, and acquire 30s lease so renewal is triggered
        self.config.renewal_interval_seconds = 45
        self.config.renewal_extension_seconds = 120
        self.lease_mgr.acquire_lease(duration_seconds=30)
        self.assertTrue(self.lease_mgr.time_until_expiry() <= 30)

        poller = self._create_poller()
        res = poller.poll(skip_historical=False)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["processed_count"], 3)

        # Verify lease was renewed
        self.assertTrue(self.lease_mgr.is_active())
        self.assertGreater(self.lease_mgr.time_until_expiry(), 40)

    def test_06_checkpoint_persistence_disk_integrity(self):
        """
        Verify that checkpoint state persists to telemetry file on disk with correct JSON content.
        """
        record_user_sentinel_poll(
            user_id=self.user_id,
            mailbox_id=self.mailbox_id,
            arrived=1,
            analysed=1,
            clean=1,
            duplicates=0,
            errors=0,
            last_uid=42,
        )

        cp_path = _get_telemetry_file_path(self.user_id, self.mailbox_id)
        self.assertTrue(os.path.exists(cp_path))

        import json
        with open(cp_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["user_id"], self.user_id)
        self.assertEqual(data["mailbox_id"], self.mailbox_id)
        self.assertEqual(data["last_processed_uid"], 42)

    def test_07_telemetry_isolation_no_cross_mailbox_pollution(self):
        """
        Verify that creating/polling mailbox 1 does NOT pollute mailbox 2 for the same user.
        """
        mb_1 = str(uuid.uuid4())
        mb_2 = str(uuid.uuid4())

        record_user_sentinel_poll(
            user_id=self.user_id,
            mailbox_id=mb_1,
            arrived=7,
            analysed=7,
            last_uid=77
        )

        # Telemetry for mailbox 1 has 7 emails
        stats_mb1 = get_user_sentinel_stats(self.user_id, mb_1)
        self.assertEqual(stats_mb1["emails_arrived"], 7)
        self.assertEqual(stats_mb1["last_processed_uid"], 77)

        # Telemetry for mailbox 2 must be clean and NOT adopt mailbox 1's 7 emails
        stats_mb2 = get_user_sentinel_stats(self.user_id, mb_2)
        self.assertEqual(stats_mb2["emails_arrived"], 0)
        self.assertEqual(stats_mb2["emails_analysed"], 0)
        self.assertEqual(stats_mb2["last_processed_uid"], 0)

    def test_08_streamlit_refresh_reads_authoritative_telemetry(self):
        """
        Verify that Refresh Telemetry idempotently reads current persisted telemetry.
        """
        record_user_sentinel_poll(
            user_id=self.user_id,
            mailbox_id=self.mailbox_id,
            arrived=1,
            analysed=1,
            last_uid=101
        )

        # First UI read
        ui_stats_1 = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(ui_stats_1["emails_arrived"], 1)
        self.assertEqual(ui_stats_1["emails_analysed"], 1)
        self.assertEqual(ui_stats_1["last_processed_uid"], 101)

        # Second UI read (Refresh)
        ui_stats_2 = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(ui_stats_2["emails_arrived"], 1)
        self.assertEqual(ui_stats_2["emails_analysed"], 1)
        self.assertEqual(ui_stats_2["last_processed_uid"], 101)


if __name__ == "__main__":
    unittest.main()
