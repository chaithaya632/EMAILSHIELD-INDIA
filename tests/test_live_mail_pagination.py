"""
tests/test_live_mail_pagination.py
Comprehensive regression tests for Live Mail Pagination and Navigation in EMAILSHIELD INDIA:
1. 10 emails per page (50 emails -> 5 pages).
2. Previous / Next navigation and boundary conditions (disabled on Page 1 / Page 5).
3. Email 10 -> Next -> Email 11 (auto page advance).
4. Email 11 -> Previous -> Email 10 (auto page retreat).
5. Jump to Mail: valid jumps (1, 25, 50), rejection/clamping of invalid jumps (0, -1, 51).
6. Gmail Inbox ordering (Newest -> Oldest).
7. Lightweight metadata verification (full RFC822 only on analyze).
8. Navigation does NOT modify telemetry, counters, or checkpoints.
"""

import unittest
import uuid
import datetime
from unittest.mock import patch, MagicMock

from core.live_mail_adapter import (
    LiveMailPagination,
    LIVE_MAIL_PAGE_SIZE,
    get_authorized_live_mail_messages,
    convert_live_message_to_rfc822_bytes,
)
from core.sentinel_stats import (
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    reset_user_sentinel_stats,
)
import core.sentinel_control as sc


class TestLiveMailPagination(unittest.TestCase):
    """Test suite covering Live Mail pagination, auto-page transitions, ordering, and state invariants."""

    def setUp(self):
        self.user_id = str(uuid.uuid4())
        self.mailbox_id = str(uuid.uuid4())
        self.mock_client = MagicMock()
        self.mock_client.auth.uid.return_value = self.user_id

        # Generate 50 synthetic messages with timestamps spanning 50 minutes (newest = msg 0, oldest = msg 49)
        base_time = datetime.datetime(2026, 9, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.messages_50 = []
        for i in range(50):
            # i=0 is most recent (+0 min), i=49 is oldest (-49 min)
            msg_time = base_time - datetime.timedelta(minutes=i)
            mid = f"MSG-INBOX-{i+1:03d}"
            self.messages_50.append({
                "id": mid,
                "case_id": mid,
                "message_id": f"<{mid}@emailshield.local>",
                "subject": f"Synthetic Threat Alert #{i+1:03d}",
                "sender": f"sender_{i+1}@external-domain.com",
                "recipient": "investigator@company.in",
                "date": msg_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "timestamp": msg_time.isoformat(),
                "risk": "HIGH" if i % 5 == 0 else "LOW",
                "case_severity": "HIGH" if i % 5 == 0 else "LOW",
                "has_attachment": (i % 3 == 0),
                "attachment_count": 1 if (i % 3 == 0) else 0,
                "has_ioc": (i % 2 == 0),
                "ioc_count": 2 if (i % 2 == 0) else 0,
                "source": "Live Mail Store",
                "snippet": f"Preview snippet for message #{i+1:03d}..."
            })

    def tearDown(self):
        reset_user_sentinel_stats(self.user_id, self.mailbox_id)

    # -------------------------------------------------------------------------
    # 1. 10 emails per page (50 emails -> 5 pages)
    # -------------------------------------------------------------------------
    def test_01_page_size_and_page_calculation(self):
        """Verifies exactly 10 emails per page and 50 emails yields exactly 5 pages."""
        self.assertEqual(LIVE_MAIL_PAGE_SIZE, 10)

        paginator = LiveMailPagination(self.messages_50, page_size=10)
        self.assertEqual(paginator.total_emails, 50)
        self.assertEqual(paginator.total_pages, 5)

        # Verify each page slice contains exactly 10 emails
        for p in range(1, 6):
            paginator.jump_to_email((p - 1) * 10 + 1)
            self.assertEqual(paginator.current_page, p)
            page_slice = paginator.get_current_page_emails()
            self.assertEqual(len(page_slice), 10, f"Page {p} does not contain 10 emails")

    def test_01b_non_divisible_page_calculation(self):
        """Verifies partial pages correctly compute total_pages (e.g. 23 emails -> 3 pages)."""
        subset = self.messages_50[:23]
        paginator = LiveMailPagination(subset, page_size=10)
        self.assertEqual(paginator.total_emails, 23)
        self.assertEqual(paginator.total_pages, 3)

        # Page 3 should contain remaining 3 emails
        paginator.jump_to_email(21)
        self.assertEqual(paginator.current_page, 3)
        self.assertEqual(len(paginator.get_current_page_emails()), 3)

    # -------------------------------------------------------------------------
    # 2. Previous / Next navigation and boundary conditions (disabled on Page 1 / Page 5)
    # -------------------------------------------------------------------------
    def test_02_boundary_conditions_page_1_and_page_5(self):
        """Verifies Previous is disabled on Page 1 and Next is disabled on Page 5."""
        paginator = LiveMailPagination(self.messages_50, page_size=10, current_index=0)

        # On Page 1 / Email 1:
        self.assertEqual(paginator.current_page, 1)
        self.assertEqual(paginator.current_email_number, 1)
        self.assertTrue(paginator.is_first_page)
        self.assertFalse(paginator.has_prev_page)
        self.assertFalse(paginator.has_prev_email)
        self.assertFalse(paginator.prev_page())
        self.assertFalse(paginator.prev_email())

        # Jump to Page 5 / Email 50:
        paginator.jump_to_email(50)
        self.assertEqual(paginator.current_page, 5)
        self.assertEqual(paginator.current_email_number, 50)
        self.assertTrue(paginator.is_last_page)
        self.assertFalse(paginator.has_next_page)
        self.assertFalse(paginator.has_next_email)
        self.assertFalse(paginator.next_page())
        self.assertFalse(paginator.next_email())

    # -------------------------------------------------------------------------
    # 3. Email 10 -> Next -> Email 11 (auto page advance)
    # -------------------------------------------------------------------------
    def test_03_auto_page_advance_from_email_10_to_11(self):
        """
        Email 10 is the last email on Page 1.
        Clicking Next on Email 10 advances to Email 11 and automatically shifts to Page 2.
        """
        paginator = LiveMailPagination(self.messages_50, page_size=10)
        paginator.jump_to_email(10)

        # Verify initial position at Email 10 on Page 1
        self.assertEqual(paginator.current_email_number, 10)
        self.assertEqual(paginator.current_page, 1)

        # Advance to next email
        moved = paginator.next_email()
        self.assertTrue(moved)
        self.assertEqual(paginator.current_email_number, 11)
        self.assertEqual(paginator.current_page, 2, "Page did not auto-advance to Page 2")

        # Verify active email on Page 2 is indeed Email 11
        cur_email = paginator.get_current_email()
        self.assertIsNotNone(cur_email)
        self.assertEqual(cur_email["id"], self.messages_50[10]["id"])

    # -------------------------------------------------------------------------
    # 4. Email 11 -> Previous -> Email 10 (auto page retreat)
    # -------------------------------------------------------------------------
    def test_04_auto_page_retreat_from_email_11_to_10(self):
        """
        Email 11 is the first email on Page 2.
        Clicking Previous on Email 11 retreats to Email 10 and automatically shifts back to Page 1.
        """
        paginator = LiveMailPagination(self.messages_50, page_size=10)
        paginator.jump_to_email(11)

        # Verify initial position at Email 11 on Page 2
        self.assertEqual(paginator.current_email_number, 11)
        self.assertEqual(paginator.current_page, 2)

        # Retreat to previous email
        moved = paginator.prev_email()
        self.assertTrue(moved)
        self.assertEqual(paginator.current_email_number, 10)
        self.assertEqual(paginator.current_page, 1, "Page did not auto-retreat to Page 1")

        # Verify active email on Page 1 is indeed Email 10
        cur_email = paginator.get_current_email()
        self.assertIsNotNone(cur_email)
        self.assertEqual(cur_email["id"], self.messages_50[9]["id"])

    # -------------------------------------------------------------------------
    # 5. Jump to Mail: valid jumps (1, 25, 50), rejection/clamping of invalid jumps
    # -------------------------------------------------------------------------
    def test_05_jump_to_email_valid_and_invalid_bounds(self):
        """
        Tests Jump to Mail:
        - Valid jumps: 1 (Page 1), 25 (Page 3), 50 (Page 5).
        - Rejection (clamp=False): 0, -1, 51.
        - Clamping (clamp=True): 0 -> 1, -1 -> 1, 51 -> 50.
        """
        paginator = LiveMailPagination(self.messages_50, page_size=10)

        # Valid Jump 1 -> Page 1, Email 1
        ok = paginator.jump_to_email(1)
        self.assertTrue(ok)
        self.assertEqual(paginator.current_email_number, 1)
        self.assertEqual(paginator.current_page, 1)

        # Valid Jump 25 -> Page 3, Email 25
        ok = paginator.jump_to_email(25)
        self.assertTrue(ok)
        self.assertEqual(paginator.current_email_number, 25)
        self.assertEqual(paginator.current_page, 3)

        # Valid Jump 50 -> Page 5, Email 50
        ok = paginator.jump_to_email(50)
        self.assertTrue(ok)
        self.assertEqual(paginator.current_email_number, 50)
        self.assertEqual(paginator.current_page, 5)

        # Rejection of invalid jumps (clamp=False)
        self.assertFalse(paginator.jump_to_email(0, clamp=False))
        self.assertFalse(paginator.jump_to_email(-1, clamp=False))
        self.assertFalse(paginator.jump_to_email(51, clamp=False))
        self.assertFalse(paginator.jump_to_email(999, clamp=False))

        # Clamping of invalid jumps (clamp=True)
        paginator.jump_to_email(0, clamp=True)
        self.assertEqual(paginator.current_email_number, 1)
        self.assertEqual(paginator.current_page, 1)

        paginator.jump_to_email(-10, clamp=True)
        self.assertEqual(paginator.current_email_number, 1)
        self.assertEqual(paginator.current_page, 1)

        paginator.jump_to_email(51, clamp=True)
        self.assertEqual(paginator.current_email_number, 50)
        self.assertEqual(paginator.current_page, 5)

        paginator.jump_to_email(100, clamp=True)
        self.assertEqual(paginator.current_email_number, 50)
        self.assertEqual(paginator.current_page, 5)

    # -------------------------------------------------------------------------
    # 6. Gmail Inbox ordering (Newest -> Oldest)
    # -------------------------------------------------------------------------
    def test_06_gmail_inbox_ordering_newest_to_oldest(self):
        """
        Verifies messages are strictly ordered from Newest to Oldest.
        Email #1 is the newest message, and Email #50 is the oldest.
        """
        # Shuffle or reverse messages to test sorting resilience
        shuffled = list(reversed(self.messages_50))
        paginator = LiveMailPagination(shuffled, page_size=10)

        # Paginator must sort Newest -> Oldest
        first_email = paginator.messages[0]
        last_email = paginator.messages[-1]

        self.assertGreater(
            first_email["date"], last_email["date"],
            "First email is not newer than last email"
        )
        self.assertEqual(first_email["id"], self.messages_50[0]["id"])
        self.assertEqual(last_email["id"], self.messages_50[-1]["id"])

        # Check monotonic descent across all 50 items
        for i in range(len(paginator.messages) - 1):
            cur_date = paginator.messages[i]["date"]
            next_date = paginator.messages[i+1]["date"]
            self.assertGreaterEqual(
                cur_date, next_date,
                f"Item {i} is older than item {i+1}, violating Gmail Inbox ordering"
            )

    # -------------------------------------------------------------------------
    # 7. Lightweight metadata verification (full RFC822 only on analyze)
    # -------------------------------------------------------------------------
    def test_07_lightweight_metadata_only_full_rfc822_on_analyze(self):
        """
        Verifies:
        1. Live Mail selector records contain only lightweight metadata (subject, sender, recipient, date, risk, indicators).
        2. Heavy raw RFC822 MIME bytes ('FileBytes', 'raw_bytes') are NOT present during browsing.
        3. Full RFC822 MIME bytes are ONLY generated when convert_live_message_to_rfc822_bytes is explicitly invoked on analyze.
        """
        paginator = LiveMailPagination(self.messages_50, page_size=10)
        email_rec = paginator.get_current_email()

        # Lightweight fields present
        self.assertIn("subject", email_rec)
        self.assertIn("sender", email_rec)
        self.assertIn("recipient", email_rec)
        self.assertIn("date", email_rec)
        self.assertIn("risk", email_rec)
        self.assertIn("has_attachment", email_rec)
        self.assertIn("has_ioc", email_rec)

        # Heavy RFC822 MIME bytes absent during browsing
        self.assertNotIn("FileBytes", email_rec)
        self.assertNotIn("raw_bytes", email_rec)

        # Full RFC822 bytes ONLY generated on convert_live_message_to_rfc822_bytes
        filename, rfc822_bytes = convert_live_message_to_rfc822_bytes(email_rec, user_id=self.user_id)
        self.assertTrue(filename.endswith(".eml"))
        self.assertIsInstance(rfc822_bytes, bytes)
        self.assertGreater(len(rfc822_bytes), 0)
        self.assertIn(b"Subject: " + email_rec["subject"].encode("utf-8"), rfc822_bytes)
        self.assertIn(b"From: " + email_rec["sender"].encode("utf-8"), rfc822_bytes)

    # -------------------------------------------------------------------------
    # 8. Navigation does NOT modify telemetry, counters, or checkpoints
    # -------------------------------------------------------------------------
    def test_08_navigation_does_not_modify_telemetry_or_checkpoints(self):
        """
        Verifies that navigating between pages, jumping to emails, and fetching page slices
        is completely read-only and does NOT increment or mutate:
        - Emails Arrived
        - Emails Analysed
        - Threats Detected
        - last_processed_uid / Checkpoint
        """
        # Baseline telemetry recording
        record_user_sentinel_poll(
            user_id=self.user_id,
            mailbox_id=self.mailbox_id,
            arrived=42,
            analysed=38,
            clean=30,
            suspicious=8,
            last_uid=777
        )

        initial_stats = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(initial_stats["emails_arrived"], 42)
        self.assertEqual(initial_stats["emails_analysed"], 38)
        self.assertEqual(initial_stats["last_processed_uid"], 777)

        # Perform extensive pagination and navigation operations
        paginator = LiveMailPagination(self.messages_50, page_size=10)
        for _ in range(5):
            paginator.next_page()
            _ = paginator.get_current_page_emails()
            _ = paginator.get_current_email()

        for _ in range(50):
            paginator.next_email()

        for jump_target in [1, 10, 11, 25, 49, 50, 0, 51]:
            paginator.jump_to_email(jump_target, clamp=True)

        for _ in range(50):
            paginator.prev_email()

        # Re-verify telemetry remains strictly identical
        post_stats = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(post_stats["emails_arrived"], 42)
        self.assertEqual(post_stats["emails_analysed"], 38)
        self.assertEqual(post_stats["last_processed_uid"], 777)
        self.assertEqual(post_stats["clean"], 30)
        self.assertEqual(post_stats["suspicious"], 8)



if __name__ == "__main__":
    unittest.main()
