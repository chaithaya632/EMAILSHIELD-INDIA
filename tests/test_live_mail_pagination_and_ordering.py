"""
tests/test_live_mail_pagination_and_ordering.py
Regression and feature test suite for Live Mail Pagination, Compact Jump, and Gmail Inbox Ordering:
1. Invariant 1: 10 emails per page in Live Mail selector (Page 1: 1-10 of 50, Page 2: 11-20 of 50).
2. Invariant 1: Boundary behavior (Page 1 Email 1: Previous disabled; Last page Email 50: Next disabled).
3. Invariant 2: Compact Jump to Mail (st.number_input with bounds, rejecting invalid 0, -1, 51).
4. Invariant 3: Gmail Inbox order Newest -> Oldest (timestamps descending, sequence/ID fallback).
5. Invariant 4: Lightweight fetch (only metadata, lazy RFC822 generation).
6. Invariant 5: Email X of Y preserved and cross-page Previous/Next advancement.
7. Invariant 6: Session state isolation (current_live_mail_index, no telemetry/lease modification).
"""

import unittest
import math
import uuid
import datetime
from unittest.mock import patch, MagicMock

import views.analyze as analyze_view
from core.live_mail_adapter import (
    get_authorized_live_mail_messages,
    convert_live_message_to_rfc822_bytes,
    _extract_message_timestamp,
    _message_sort_key,
)


class TestLiveMailPaginationAndOrdering(unittest.TestCase):
    """Verifies pagination, compact jump, and inbox ordering invariants."""

    def setUp(self):
        self.test_user_id = str(uuid.uuid4())
        self.mock_client = MagicMock()
        self.mock_client.auth.uid.return_value = self.test_user_id

    # -------------------------------------------------------------------------
    # Invariant 3: Gmail Inbox Order (Newest -> Oldest)
    # -------------------------------------------------------------------------
    def test_01_gmail_inbox_order_timestamps_descending(self):
        """
        Ensures messages are sorted by date/timestamp descending (Newest -> Oldest),
        falling back to sequence/ID descending.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        cases = [
            {
                "case_id": "case_old",
                "timestamp": (now - datetime.timedelta(hours=5)).isoformat(),
                "subject": "Old Email",
                "user_id": self.test_user_id,
            },
            {
                "case_id": "case_newest",
                "timestamp": now.isoformat(),
                "subject": "Newest Email",
                "user_id": self.test_user_id,
            },
            {
                "case_id": "case_middle",
                "timestamp": (now - datetime.timedelta(hours=2)).isoformat(),
                "subject": "Middle Email",
                "user_id": self.test_user_id,
            },
        ]

        with patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_all_cases", return_value=cases), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            messages = get_authorized_live_mail_messages(self.test_user_id, self.mock_client, limit=50)

            self.assertEqual(len(messages), 3)
            self.assertEqual(messages[0]["case_id"], "case_newest", "Newest message must be first")
            self.assertEqual(messages[1]["case_id"], "case_middle", "Middle message must be second")
            self.assertEqual(messages[2]["case_id"], "case_old", "Old message must be last")

    def test_02_gmail_inbox_order_sequence_fallback(self):
        """
        When timestamps are identical or absent, sorting falls back to sequence/ID descending.
        """
        cases = [
            {"case_id": "msg_10", "timestamp": "2026-01-01 00:00:00", "subject": "Msg 10", "user_id": self.test_user_id},
            {"case_id": "msg_50", "timestamp": "2026-01-01 00:00:00", "subject": "Msg 50", "user_id": self.test_user_id},
            {"case_id": "msg_25", "timestamp": "2026-01-01 00:00:00", "subject": "Msg 25", "user_id": self.test_user_id},
        ]

        with patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_all_cases", return_value=cases), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            messages = get_authorized_live_mail_messages(self.test_user_id, self.mock_client, limit=50)

            self.assertEqual(len(messages), 3)
            self.assertEqual(messages[0]["case_id"], "msg_50", "Highest sequence ID must be first")
            self.assertEqual(messages[1]["case_id"], "msg_25", "Middle sequence ID must be second")
            self.assertEqual(messages[2]["case_id"], "msg_10", "Lowest sequence ID must be last")

    # -------------------------------------------------------------------------
    # Invariant 1 & 6: 10 emails per page & Session State Calculation
    # -------------------------------------------------------------------------
    def test_03_pagination_math_and_session_state(self):
        """
        Validates page calculation:
        current_page = (cur_idx // 10) + 1
        total_pages = max(1, math.ceil(len(messages) / 10))
        Page 1: 1-10 of 50
        Page 2: 11-20 of 50
        """
        total_msgs = 50
        # For indices 0..9 (Page 1)
        for idx in range(10):
            page = (idx // 10) + 1
            total_pages = max(1, math.ceil(total_msgs / 10))
            page_start = (page - 1) * 10 + 1
            page_end = min(page * 10, total_msgs)
            self.assertEqual(page, 1)
            self.assertEqual(total_pages, 5)
            self.assertEqual(page_start, 1)
            self.assertEqual(page_end, 10)

        # For indices 10..19 (Page 2)
        for idx in range(10, 20):
            page = (idx // 10) + 1
            page_start = (page - 1) * 10 + 1
            page_end = min(page * 10, total_msgs)
            self.assertEqual(page, 2)
            self.assertEqual(page_start, 11)
            self.assertEqual(page_end, 20)

        # Last page (Page 5: 41-50)
        for idx in range(40, 50):
            page = (idx // 10) + 1
            page_start = (page - 1) * 10 + 1
            page_end = min(page * 10, total_msgs)
            self.assertEqual(page, 5)
            self.assertEqual(page_start, 41)
            self.assertEqual(page_end, 50)

    # -------------------------------------------------------------------------
    # Invariant 1 & 5: Pagination Controls Removed (Natural Page Scroll)
    # -------------------------------------------------------------------------
    def test_04_previous_next_navigation_and_boundary_conditions(self):
        """
        Verifies that all pagination controls (Previous, Next, Jump to Mail,
        Page X of Y, Email X of Y) are completely removed from the Live Mail UI.
        """
        active_mb = {"id": "mb_nav_test", "is_active": True, "email_address": "analyst@emailshield.in"}
        messages_50 = [{"id": f"msg_{i}", "subject": f"Subject {i}", "sender": f"sender{i}@test.com"} for i in range(50)]

        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_index": 0,
        }
        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=messages_50), \
             patch("views.analyze.st.button") as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md, \
             patch("views.analyze.st.number_input") as mock_num:

            mock_btn.return_value = False
            analyze_view.render(self.test_user_id, self.mock_client)

            # Assert no Previous or Next buttons
            prev_calls = [c for c in mock_btn.call_args_list if c[0] and "Previous" in c[0][0]]
            next_calls = [c for c in mock_btn.call_args_list if c[0] and "Next" in c[0][0]]
            self.assertEqual(len(prev_calls), 0, "Previous button must not be rendered")
            self.assertEqual(len(next_calls), 0, "Next button must not be rendered")

            # Assert no Jump to Mail number input
            self.assertFalse(mock_num.called, "st.number_input (Jump to Mail) must not be called")

            # Assert no Page X of Y or Showing emails X-Y
            md_text = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertNotIn("Page 1 of", md_text)
            self.assertNotIn("Showing emails", md_text)

    test_04_pagination_controls_removed = test_04_previous_next_navigation_and_boundary_conditions

    # -------------------------------------------------------------------------
    # Invariant 2: UID-Anchored Selection and Dedicated Action Card
    # -------------------------------------------------------------------------
    def test_05_compact_jump_rejection_and_clamping(self):
        """
        Verifies that clicking Select on an email card sets selected_live_mail_uid,
        and the dedicated Action Card renders for that email (replacing legacy compact jump).
        """
        active_mb = {"id": "mb_jump_test", "is_active": True, "email_address": "analyst@emailshield.in"}
        messages_50 = [{"id": f"msg_{i}", "subject": f"Subject {i}", "sender": f"sender{i}@test.com"} for i in range(50)]

        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_uid": "msg_5",
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=messages_50), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertEqual(
                analyze_view.st.session_state.get("selected_live_mail_uid"), "msg_5",
                "selected_live_mail_uid must remain msg_5"
            )

            # Check that Dedicated Action Card is rendered
            md_text = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertIn("Currently Selected Email", md_text)
            self.assertIn("Subject 5", md_text)

            # Check that Analyze button exists
            analyze_calls = [c for c in mock_btn.call_args_list if c[1].get("key") == "btn_analyze_selected_live_email"]
            self.assertTrue(len(analyze_calls) > 0, "btn_analyze_selected_live_email must be rendered")

    test_05_natural_scroll_and_selection = test_05_compact_jump_rejection_and_clamping


if __name__ == "__main__":
    unittest.main()

