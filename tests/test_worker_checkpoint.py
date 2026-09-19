"""
tests/test_worker_checkpoint.py
Unit tests for Sentinel mailbox checkpointing, UID monotonicity, Message-ID deduplication,
and concurrency poll locking.
"""

import unittest
import uuid
from worker.checkpoint import CheckpointStore, MailboxCheckpoint


class TestWorkerCheckpoint(unittest.TestCase):
    """Verifies incremental checkpointing and deduplication state store."""

    def setUp(self):
        self.store = CheckpointStore()
        self.user_a = str(uuid.uuid4())
        self.worker_a = str(uuid.uuid4())
        self.mailbox_a = str(uuid.uuid4())

        self.user_b = str(uuid.uuid4())
        self.worker_b = str(uuid.uuid4())
        self.mailbox_b = str(uuid.uuid4())

    def test_01_default_checkpoint_initialization(self):
        """Verify checkpoint initializes with last_processed_uid = 0."""
        cp = self.store.get_checkpoint(self.user_a, self.worker_a, self.mailbox_a)
        self.assertEqual(cp.last_processed_uid, 0)
        self.assertIsNone(cp.last_processed_msg_id)
        self.assertEqual(cp.folder_name, "INBOX")

    def test_02_monotonic_uid_advancement(self):
        """Verify advancing checkpoint monotonically increases last_processed_uid."""
        self.store.advance_checkpoint(
            self.user_a, self.worker_a, self.mailbox_a,
            uid=10, message_id="<msg-10@example.invalid>"
        )
        cp = self.store.get_checkpoint(self.user_a, self.worker_a, self.mailbox_a)
        self.assertEqual(cp.last_processed_uid, 10)
        self.assertEqual(cp.last_processed_msg_id, "<msg-10@example.invalid>")

        # Monotonicity: advancing with lower UID (e.g. 5) does NOT regress checkpoint
        self.store.advance_checkpoint(
            self.user_a, self.worker_a, self.mailbox_a,
            uid=5, message_id="<msg-05@example.invalid>"
        )
        cp_after = self.store.get_checkpoint(self.user_a, self.worker_a, self.mailbox_a)
        self.assertEqual(cp_after.last_processed_uid, 10)
        self.assertEqual(cp_after.last_processed_msg_id, "<msg-10@example.invalid>")

    def test_03_message_id_deduplication(self):
        """Verify secondary Message-ID deduplication detects previously seen IDs."""
        msg_id = "<duplicate-target@example.invalid>"
        self.assertFalse(self.store.is_duplicate_message_id(self.mailbox_a, msg_id))

        self.store.advance_checkpoint(
            self.user_a, self.worker_a, self.mailbox_a,
            uid=1, message_id=msg_id
        )
        self.assertTrue(self.store.is_duplicate_message_id(self.mailbox_a, msg_id))

        # Different mailbox does not share deduplication index
        self.assertFalse(self.store.is_duplicate_message_id(self.mailbox_b, msg_id))

    def test_04_message_id_dedup_lru_bounded(self):
        """Verify deduplication index has bounded capacity to prevent memory leaks."""
        self.store.MAX_SEEN_MSG_IDS_PER_MAILBOX = 5  # Small limit for test
        for i in range(10):
            self.store.advance_checkpoint(
                self.user_a, self.worker_a, self.mailbox_a,
                uid=i + 1, message_id=f"<msg-{i}@example.invalid>"
            )

        # Oldest (<msg-0> through <msg-4>) should have been evicted
        self.assertFalse(self.store.is_duplicate_message_id(self.mailbox_a, "<msg-0@example.invalid>"))
        self.assertFalse(self.store.is_duplicate_message_id(self.mailbox_a, "<msg-4@example.invalid>"))
        # Newest (<msg-5> through <msg-9>) are retained
        self.assertTrue(self.store.is_duplicate_message_id(self.mailbox_a, "<msg-9@example.invalid>"))

    def test_05_mailbox_concurrency_locking(self):
        """Verify acquire_poll_lock provides mutual exclusion per mailbox."""
        # First acquisition succeeds
        self.assertTrue(self.store.acquire_poll_lock(self.mailbox_a))

        # Concurrent acquisition on same mailbox fails
        self.assertFalse(self.store.acquire_poll_lock(self.mailbox_a))

        # Different mailbox can still acquire lock concurrently
        self.assertTrue(self.store.acquire_poll_lock(self.mailbox_b))

        # Releasing mailbox A allows subsequent acquisition
        self.store.release_poll_lock(self.mailbox_a)
        self.assertTrue(self.store.acquire_poll_lock(self.mailbox_a))
        self.store.release_poll_lock(self.mailbox_a)
        self.store.release_poll_lock(self.mailbox_b)

    def test_06_tenant_isolation(self):
        """Verify checkpoints are completely isolated between tenants."""
        self.store.advance_checkpoint(
            self.user_a, self.worker_a, self.mailbox_a,
            uid=42, message_id="<tenant-a-msg@example.invalid>"
        )
        cp_a = self.store.get_checkpoint(self.user_a, self.worker_a, self.mailbox_a)
        cp_b = self.store.get_checkpoint(self.user_b, self.worker_b, self.mailbox_b)

        self.assertEqual(cp_a.last_processed_uid, 42)
        self.assertEqual(cp_b.last_processed_uid, 0)


if __name__ == "__main__":
    unittest.main()
