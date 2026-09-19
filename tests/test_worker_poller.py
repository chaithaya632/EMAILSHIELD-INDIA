"""
tests/test_worker_poller.py
Comprehensive unit tests for the Sentinel Mailbox Poller.
Covers:
- First poll (empty checkpoint -> process unseen messages)
- Incremental poll (no old-mail rescan)
- Restart persistence (checkpoint prevents re-processing after worker restart)
- Message-ID deduplication (same Message-ID with different UID skipped)
- Concurrent poll protection (POLL_ALREADY_RUNNING)
- Malformed email handling (missing headers, invalid MIME, empty subject)
- Oversized message handling (bounds enforcement)
- Failure semantics (error on message 2 halts checkpoint advancement at message 1)
"""

import json
import os
import unittest
import uuid

from core.sentinel_crypto import generate_worker_asymmetric_keypair, WorkerKeyRing, ProvisioningKeyRing
from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.db import MockWorkerDBClient
from worker.lease import WorkerLeaseManager
from worker.credentials import WorkerCredentialService
from worker.synthetic_imap import SyntheticIMAPServer, SyntheticEmailMessage
from worker.checkpoint import CheckpointStore
from worker.poller import MailboxPoller, MAX_MESSAGE_SIZE_BYTES


class TestWorkerPoller(unittest.TestCase):
    """Verifies safe incremental mailbox polling engine semantics."""

    @classmethod
    def setUpClass(cls):
        cls.priv_key, cls.pub_key = generate_worker_asymmetric_keypair(2048)
        cls.user_id = uuid.uuid4()
        cls.worker_id = uuid.uuid4()
        cls.mailbox_id = uuid.uuid4()

        cls.username = "sentinel-user@example.invalid"
        cls.password = "synthetic_app_password_999"

        # Encrypt synthetic credentials
        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": cls.pub_key})
        secret_json = json.dumps({
            "username": cls.username,
            "password": cls.password,
            "imap_host": "imap.example.invalid",
            "imap_port": 993
        })
        cls.envelope = prov_ring.encrypt(secret_json, user_id=str(cls.user_id))

    def setUp(self):
        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")
        self.db.seed_mailbox(
            self.mailbox_id, self.worker_id, self.user_id,
            encrypted_credentials=self.envelope
        )

        self.identity = WorkerIdentity(self.worker_id)
        self.lease_mgr = WorkerLeaseManager(self.identity, self.db)
        self.lease_mgr.acquire_lease(duration_seconds=180)

        self.worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key})
        self.cred_service = WorkerCredentialService(self.identity, self.worker_ring, self.db)

        self.checkpoint_store = CheckpointStore()
        self.synthetic_server = SyntheticIMAPServer()
        self.synthetic_server.register_account(self.username, self.password)

        self.poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id),
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=self.synthetic_server
        )

    def test_01_first_poll_processes_all_and_advances_checkpoint(self):
        """First poll with empty checkpoint processes UIDs 1, 2, 3 and advances checkpoint to 3."""
        for uid in [1, 2, 3]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(
                    uid=uid,
                    message_id=f"<msg-{uid}@example.invalid>",
                    subject=f"Subject {uid}",
                    body=f"Body content {uid}"
                )
            )

        res = self.poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["processed_count"], 3)
        self.assertEqual(len(res["events"]), 3)

        # Checkpoint is now 3
        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp.last_processed_uid, 3)
        self.assertEqual(cp.last_processed_msg_id, "<msg-3@example.invalid>")

    def test_02_second_poll_no_old_mail_rescan(self):
        """Second poll on the same mailbox processes zero messages and retains checkpoint."""
        for uid in [1, 2, 3]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(uid=uid, message_id=f"<msg-{uid}@example.invalid>")
            )

        # First poll
        self.poller.poll()

        # Second poll
        res2 = self.poller.poll()
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertEqual(res2["processed_count"], 0)
        self.assertEqual(len(res2["events"]), 0)

        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp.last_processed_uid, 3)

    def test_03_incremental_poll_processes_only_new_messages(self):
        """When UID 4 is added, incremental poll processes only UID 4."""
        for uid in [1, 2, 3]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(uid=uid, message_id=f"<msg-{uid}@example.invalid>")
            )
        self.poller.poll()

        # Add new message with UID 4
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=4, message_id="<msg-4@example.invalid>", subject="New Inbound")
        )

        res = self.poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["processed_count"], 1)
        self.assertEqual(res["events"][0].uid, 4)
        self.assertEqual(res["events"][0].subject, "New Inbound")

        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp.last_processed_uid, 4)

    def test_04_restart_persistence(self):
        """Simulate worker restart: fresh poller instance with existing checkpoint store does not re-process."""
        for uid in [1, 2, 3]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(uid=uid, message_id=f"<msg-{uid}@example.invalid>")
            )
        self.poller.poll()

        # Simulate fresh poller startup after restart
        new_poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id),
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=self.checkpoint_store,  # Checkpoint state preserved
            synthetic_server=self.synthetic_server
        )

        res = new_poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["processed_count"], 0)

    def test_05_message_id_deduplication(self):
        """UID 10 and UID 11 share the same Message-ID; UID 11 is skipped as duplicate."""
        dup_msg_id = "<duplicate-target-id@example.invalid>"
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=10, message_id=dup_msg_id, subject="Original Message")
        )
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=11, message_id=dup_msg_id, subject="Duplicate Message")
        )

        res = self.poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        # Exactly 1 event emitted (UID 10), UID 11 filtered out
        self.assertEqual(len(res["events"]), 1)
        self.assertEqual(res["events"][0].uid, 10)

        # Checkpoint advanced to 11 so duplicate is not scanned again
        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp.last_processed_uid, 11)

    def test_06_concurrent_poll_protection(self):
        """Attempting concurrent poll on the same mailbox returns POLL_ALREADY_RUNNING."""
        # Manually hold poll lock
        self.checkpoint_store.acquire_poll_lock(str(self.mailbox_id))

        res = self.poller.poll()
        self.assertEqual(res["status"], "POLL_ALREADY_RUNNING")
        self.assertEqual(res["processed_count"], 0)

        self.checkpoint_store.release_poll_lock(str(self.mailbox_id))

    def test_07_malformed_email_handled_gracefully(self):
        """Malformed email payloads with missing headers or corrupt bytes do not crash poller."""
        # Missing Message-ID and empty subject
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=1, message_id="", subject="", body="Missing headers")
        )
        # Raw corrupt bytes
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=2, message_id="<corrupt@example.invalid>", raw_bytes=b"\xff\xfe\xfd\x80\x81")
        )

        res = self.poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(len(res["events"]), 2)

        # Confirm checkpoint advanced past corrupt messages
        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp.last_processed_uid, 2)

    def test_08_oversized_message_handled_safely(self):
        """Oversized message exceeding limit emits OVERSIZED event without crashing."""
        oversized_body = b"X" * (MAX_MESSAGE_SIZE_BYTES + 1024)
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=1,
                message_id="<oversized@example.invalid>",
                raw_bytes=b"From: sender@example.invalid\r\nSubject: Huge\r\n\r\n" + oversized_body
            )
        )

        res = self.poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(len(res["events"]), 1)
        self.assertEqual(res["events"][0].processing_status, "OVERSIZED")
        self.assertEqual(res["events"][0].error_code, "ERR_MESSAGE_TOO_LARGE")

        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp.last_processed_uid, 1)

    def test_09_failure_halts_checkpoint_at_last_successful_uid(self):
        """If fetch on UID 2 fails, UID 1 is committed and checkpoint halts at 1."""
        for uid in [1, 2, 3]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(uid=uid, message_id=f"<msg-{uid}@example.invalid>")
            )

        # Inject failure on UID 2
        self.synthetic_server.fail_fetch_uid = 2

        with self.assertRaises(Exception):
            self.poller.poll()

        # Checkpoint must remain at 1! (UID 2 and 3 were NOT committed)
        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp.last_processed_uid, 1)

        # Resolve failure and re-poll: UID 2 and 3 are successfully processed
        self.synthetic_server.fail_fetch_uid = None
        res_retry = self.poller.poll()
        self.assertEqual(res_retry["status"], "SUCCESS")
        self.assertEqual(len(res_retry["events"]), 2)
        self.assertEqual(res_retry["events"][0].uid, 2)
        self.assertEqual(res_retry["events"][1].uid, 3)

        cp_final = self.checkpoint_store.get_checkpoint(
            str(self.user_id), str(self.worker_id), str(self.mailbox_id)
        )
        self.assertEqual(cp_final.last_processed_uid, 3)

    def test_10_initial_sync_skips_historical_mail_and_sets_baseline_checkpoint(self):
        """Initial sync with skip_historical=True skips existing messages and establishes baseline checkpoint."""
        for uid in [10, 20, 30]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(uid=uid, message_id=f"<hist-{uid}@example.invalid>", subject=f"Historical {uid}")
            )

        new_cp_store = CheckpointStore()
        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id),
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=new_cp_store,
            synthetic_server=self.synthetic_server
        )

        res = poller.poll(skip_historical=True)
        self.assertEqual(res["status"], "INITIAL_SYNC_COMPLETE")
        self.assertEqual(res["processed_count"], 0)
        self.assertEqual(len(res["events"]), 0)
        self.assertEqual(res["stats"]["emails_arrived"], 0)
        self.assertEqual(res["stats"]["emails_analysed"], 0)
        self.assertEqual(res["stats"]["last_processed_uid"], 30)
        self.assertTrue(res["stats"]["has_polled"])

    def test_11_new_incoming_mail_after_initial_sync_is_detected(self):
        """After initial sync establishes baseline UID 30, incoming message with UID 31 is detected and analysed."""
        for uid in [10, 20, 30]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(uid=uid, message_id=f"<hist-{uid}@example.invalid>", subject=f"Historical {uid}")
            )

        new_cp_store = CheckpointStore()
        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id),
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=new_cp_store,
            synthetic_server=self.synthetic_server
        )

        # Baseline sync
        res_init = poller.poll(skip_historical=True)
        self.assertEqual(res_init["processed_count"], 0)

        # Friend sends new email: assigned UID 31
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=31, message_id="<new-friend-001@example.invalid>", subject="EMAILSHIELD SENTINEL LIVE TEST")
        )

        # Next poll detects and analyses UID 31
        res_poll = poller.poll()
        self.assertEqual(res_poll["status"], "SUCCESS")
        self.assertEqual(res_poll["processed_count"], 1)
        self.assertEqual(len(res_poll["events"]), 1)
        self.assertEqual(res_poll["events"][0].uid, 31)
        self.assertEqual(res_poll["events"][0].subject, "EMAILSHIELD SENTINEL LIVE TEST")
        self.assertEqual(res_poll["stats"]["emails_arrived"], 1)
        self.assertEqual(res_poll["stats"]["emails_analysed"], 1)
        self.assertEqual(res_poll["stats"]["last_processed_uid"], 31)

    def test_12_duplicate_prevention_does_not_increment_emails_arrived(self):
        """Duplicate message with already-seen Message-ID increments duplicates_skipped but not emails_arrived."""
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=40, message_id="<dup-target@example.invalid>", subject="Original")
        )

        new_cp_store = CheckpointStore()
        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id),
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=new_cp_store,
            synthetic_server=self.synthetic_server
        )

        # Poll original message
        res1 = poller.poll()
        self.assertEqual(res1["processed_count"], 1)
        self.assertEqual(res1["stats"]["emails_arrived"], 1)
        self.assertEqual(res1["stats"]["duplicates_skipped"], 0)

        # Test E: Allow another poll with no new messages. Emails Arrived does not increase.
        res_same = poller.poll()
        self.assertEqual(res_same["status"], "SUCCESS")
        self.assertEqual(res_same["processed_count"], 0)
        self.assertEqual(res_same["stats"]["emails_arrived"], 1)
        self.assertEqual(res_same["stats"]["this_poll_arrived"], 0)

        # Duplicate email arrives under new UID 41
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(uid=41, message_id="<dup-target@example.invalid>", subject="Duplicate")
        )

        res2 = poller.poll()
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertEqual(res2["processed_count"], 0)
        # 1 duplicate skipped, emails_analysed remains 1!
        self.assertEqual(res2["stats"]["duplicates_skipped"], 1)
        self.assertEqual(res2["stats"]["emails_analysed"], 1)
        self.assertEqual(res2["stats"]["last_processed_uid"], 41)


if __name__ == "__main__":
    unittest.main()
