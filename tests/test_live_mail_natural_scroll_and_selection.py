"""
tests/test_live_mail_natural_scroll_and_selection.py
Comprehensive regression & feature test suite for Live Mail Natural Scroll & Selection UI:

Invariant 1: No pagination controls:
  Verify `← Previous`, `Next →`, `Jump to Mail`, `+ / −`, `Page X of Y`, and `Email X of Y` are NOT present or rendered.
Invariant 2: No internal or fixed-height scroll container:
  Verify `st.container(height=...)`, `overflow-y`, and custom scrollbars are NOT used.
Invariant 3: Natural page flow / vertical cards:
  Verify all loaded emails render vertically directly on the page flow.
Invariant 4: UID-anchored card selection:
  Verify clicking an email card or its Select button sets `selected_live_mail_uid`, `selected_live_mail_message_id`, and `selected_live_mail_index`.
  Verify if no selection is active, it defaults cleanly to `messages[0]`.
Invariant 5: Dedicated "Selected Email" action card:
  Verify the selected email's subject, sender, and `[ 🔍 Analyze This Email ]` button are rendered.
Invariant 6: Analyze execution:
  Verify clicking `[ 🔍 Analyze This Email ]` retrieves RFC822 bytes for the selected UID and triggers forensic analysis.
Invariant 7: Stale risk badge fix:
  Verify unanalyzed emails show `Risk: Not analyzed`.
  Verify analyzed email (e.g. NPTEL) updates to `Risk: SAFE` (never stale `HIGH`).
  Verify NO domain whitelisting is used.
Invariant 8: Gmail inbox ordering:
  Verify newest to oldest ordering is preserved.
Invariant 9: Deduplication:
  Verify each UID appears only once.
Invariant 10: Selection persistence:
  Verify selection persists across Streamlit reruns.
Invariant 11: Logout clears selection:
  Verify `clear_investigator_session()` purges `selected_live_mail_uid`, `selected_live_mail_message_id`, `selected_live_mail_index`, and `live_mail_analysis_status`.
Invariant 12: Zero telemetry mutation:
  Verify manual analysis does not alter Sentinel stats, metrics, or checkpoints.
"""

import unittest
import uuid
import inspect
import datetime
from unittest.mock import patch, MagicMock

import views.analyze as analyze_view
from app import clear_investigator_session
from core.live_mail_adapter import (
    get_authorized_live_mail_messages,
    convert_live_message_to_rfc822_bytes,
)
from core.sentinel_stats import (
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    reset_user_sentinel_stats,
)
import core.sentinel_control as sc


class TestLiveMailNaturalScrollAndSelection(unittest.TestCase):
    """Verifies all 12 invariants of the Live Mail Natural Scroll & Selection UI."""

    def setUp(self):
        self.test_user_id = str(uuid.uuid4())
        self.mailbox_id = str(uuid.uuid4())
        self.mock_client = MagicMock()
        self.mock_client.auth.uid.return_value = self.test_user_id
        self.active_mb = {
            "id": self.mailbox_id,
            "is_active": True,
            "email_address": "analyst@emailshield.in",
            "provider": "gmail"
        }

        # Generate 10 synthetic messages for testing
        base_time = datetime.datetime(2026, 9, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.sample_messages = []
        for i in range(10):
            msg_time = base_time - datetime.timedelta(minutes=i)
            uid = f"msg_{i+1:03d}"
            self.sample_messages.append({
                "id": uid,
                "case_id": uid,
                "message_id": f"<{uid}@domain.in>",
                "subject": f"Security Alert #{i+1:03d}",
                "sender": f"sender_{i+1}@external.com",
                "recipient": "analyst@emailshield.in",
                "date": msg_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "timestamp": msg_time.isoformat(),
                "snippet": f"Preview snippet for message #{i+1:03d}...",
                "body_preview": f"Preview snippet for message #{i+1:03d}...",
                "attachment_count": 1 if i % 2 == 0 else 0,
                "ioc_count": 2 if i % 3 == 0 else 0,
            })

    def tearDown(self):
        reset_user_sentinel_stats(self.test_user_id, self.mailbox_id)

    # -------------------------------------------------------------------------
    # Invariant 1: No pagination controls
    # -------------------------------------------------------------------------
    def test_invariant_01_no_pagination_controls(self):
        """
        Verify `← Previous`, `Next →`, `Jump to Mail`, `+ / −`, `Page X of Y`,
        and `Email X of Y` are NOT present or rendered in the Live Mail view.
        """
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md, \
             patch("views.analyze.st.number_input") as mock_num:

            analyze_view.render(self.test_user_id, self.mock_client)

            # 1. Assert no Previous or Next buttons
            prev_calls = [c for c in mock_btn.call_args_list if c[0] and "Previous" in str(c[0][0])]
            next_calls = [c for c in mock_btn.call_args_list if c[0] and "Next" in str(c[0][0])]
            self.assertEqual(len(prev_calls), 0, "Previous button must NOT be rendered")
            self.assertEqual(len(next_calls), 0, "Next button must NOT be rendered")

            # 2. Assert no Jump to Mail number input or plus/minus controls
            jump_calls = [c for c in mock_num.call_args_list if "Jump to Mail" in str(c)]
            self.assertEqual(len(jump_calls), 0, "Jump to Mail input must NOT be called")

            # 3. Assert no 'Page X of Y' or 'Email X of Y' in rendered markdown
            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertNotIn("Page 1 of", all_md)
            self.assertNotIn("Page 2 of", all_md)
            self.assertNotIn("Email 1 of", all_md)
            self.assertNotIn("Email 2 of", all_md)
            self.assertNotIn("Showing emails", all_md)

    # -------------------------------------------------------------------------
    # Invariant 2: No internal or fixed-height scroll container
    # -------------------------------------------------------------------------
    def test_invariant_02_no_internal_or_fixed_height_scroll_container(self):
        """
        Verify `st.container(height=...)`, `overflow-y`, and custom scrollbars
        are NOT used in the Live Mail view.
        """
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.markdown") as mock_md, \
             patch("views.analyze.st.container") as mock_container:

            analyze_view.render(self.test_user_id, self.mock_client)

            # 1. Assert st.container was not called with height=...
            for call in mock_container.call_args_list:
                kwargs = call[1] if len(call) > 1 else {}
                self.assertNotIn("height", kwargs, "st.container must NOT specify a fixed height")

            # 2. Assert no overflow-y or custom scrollbar styles
            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertNotIn("overflow-y", all_md, "overflow-y must NOT be used in Live Mail view")
            self.assertNotIn("scrollbar", all_md.lower(), "Custom scrollbars must NOT be used in Live Mail view")

    # -------------------------------------------------------------------------
    # Invariant 3: Natural page flow / vertical cards
    # -------------------------------------------------------------------------
    def test_invariant_03_natural_page_flow_vertical_cards(self):
        """
        Verify all loaded emails render vertically directly on the page flow as individual cards.
        """
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)

            # All 10 emails must appear in the rendered markdown cards
            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            for msg in self.sample_messages:
                self.assertIn(msg["subject"], all_md, f"Email {msg['subject']} must be rendered in natural page flow")

            # Verify Inbox Messages header indicates count
            self.assertIn("Inbox Messages (10 loaded)", all_md)

    # -------------------------------------------------------------------------
    # Invariant 4: UID-anchored card selection
    # -------------------------------------------------------------------------
    def test_invariant_04_uid_anchored_card_selection(self):
        """
        Verify clicking an email card or its Select button sets:
          - selected_live_mail_uid
          - selected_live_mail_message_id
          - selected_live_mail_index
        Verify if no selection is active, it defaults cleanly to messages[0].
        """
        # Part A: Defaults cleanly to messages[0] when no selection active
        state_empty = {
            "email_analysis_source": "📬 Select from Live Mail",
        }
        with patch.dict(analyze_view.st.session_state, state_empty, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.markdown"):

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_uid"), "msg_001")
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_message_id"), "<msg_001@domain.in>")
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_index"), 0)

        # Part B: Clicking Select on card index 3 updates selection
        state_select = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_uid": "msg_001",
        }

        def mock_button_click(label, **kwargs):
            # Simulate clicking Select on msg_004 (index 3)
            return kwargs.get("key") == "btn_select_live_msg_004_3"

        with patch.dict(analyze_view.st.session_state, state_select, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.st.button", side_effect=mock_button_click), \
             patch("views.analyze.st.markdown"), \
             patch("views.analyze.st.rerun") as mock_rerun:

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_uid"), "msg_004")
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_message_id"), "<msg_004@domain.in>")
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_index"), 3)
            mock_rerun.assert_called_once()

    # -------------------------------------------------------------------------
    # Invariant 5: Dedicated "Selected Email" action card
    # -------------------------------------------------------------------------
    def test_invariant_05_dedicated_selected_email_action_card(self):
        """
        Verify the selected email's subject, sender, and `[ 🔍 Analyze This Email ]`
        button are rendered in the dedicated action card.
        """
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_uid": "msg_003",
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)

            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertIn("Currently Selected Email", all_md)
            self.assertIn("Security Alert #003", all_md)
            self.assertIn("sender_3@external.com", all_md)
            self.assertIn("msg_003", all_md)

            # Verify action button
            analyze_calls = [c for c in mock_btn.call_args_list if c[1].get("key") == "btn_analyze_selected_live_email"]
            self.assertTrue(len(analyze_calls) > 0, "Dedicated '[ 🔍 Analyze This Email ]' button must be rendered")

    # -------------------------------------------------------------------------
    # Invariant 6: Analyze execution
    # -------------------------------------------------------------------------
    def test_invariant_06_analyze_execution(self):
        """
        Verify clicking `[ 🔍 Analyze This Email ]` retrieves the RFC822 bytes
        for the selected UID and triggers forensic analysis.
        """
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_uid": "msg_002",
        }

        def mock_button_click(label, **kwargs):
            return kwargs.get("key") == "btn_analyze_selected_live_email"

        fake_rfc822_bytes = b"From: sender_2@external.com\r\nSubject: Security Alert #002\r\n\r\nPayload"

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.convert_live_message_to_rfc822_bytes", return_value=("msg_002.eml", fake_rfc822_bytes)) as mock_conv, \
             patch("views.analyze.st.button", side_effect=mock_button_click), \
             patch("views.analyze.st.markdown"), \
             patch("views.analyze.st.rerun") as mock_rerun:

            analyze_view.render(self.test_user_id, self.mock_client)

            mock_conv.assert_called_once()
            called_msg = mock_conv.call_args[0][0]
            self.assertEqual(called_msg["id"], "msg_002", "RFC822 bytes must be generated for selected UID msg_002")

            self.assertEqual(analyze_view.st.session_state.get("current_email_bytes"), fake_rfc822_bytes)
            self.assertIsNone(analyze_view.st.session_state.get("_cached_analysis_payload"))
            mock_rerun.assert_called_once()

    # -------------------------------------------------------------------------
    # Invariant 7: Stale risk badge fix
    # -------------------------------------------------------------------------
    def test_invariant_07_stale_risk_badge_fix(self):
        """
        Verify unanalyzed emails show `Risk: Not analyzed`.
        Verify analyzed email (e.g. NPTEL) updates to `Risk: SAFE` (never stale `HIGH`).
        Verify NO domain whitelisting is used.
        """
        nptel_msg = {
            "id": "nptel_msg_001",
            "case_id": "nptel_msg_001",
            "message_id": "<nptel_001@nptel.ac.in>",
            "subject": "NPTEL Online Certification Course Enrollment",
            "sender": "courses@nptel.ac.in",
            "recipient": "analyst@emailshield.in",
            "date": "2026-09-20 12:00:00 UTC",
            "risk": "HIGH",  # Stale/unverified risk
            "body_preview": "Welcome to your NPTEL course."
        }

        # Case 1: Unanalyzed -> renders 'Not analyzed' badge
        state_unanalyzed = {
            "email_analysis_source": "📬 Select from Live Mail",
            "live_mail_analysis_status": {},  # No prior analysis
        }
        with patch.dict(analyze_view.st.session_state, state_unanalyzed, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=[nptel_msg]), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)
            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertIn("Not analyzed", all_md, "Unanalyzed email must show 'Not analyzed' badge")
            self.assertNotIn(">HIGH<", all_md, "Unanalyzed email must NOT display stale 'HIGH' badge")

        # Case 2: Analyzed -> updates to 'SAFE'
        state_analyzed = {
            "email_analysis_source": "📬 Select from Live Mail",
            "live_mail_analysis_status": {"nptel_msg_001": "SAFE"},
        }
        with patch.dict(analyze_view.st.session_state, state_analyzed, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=[nptel_msg]), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)
            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertIn("SAFE", all_md, "Analyzed email must show updated 'SAFE' badge")
            self.assertNotIn("Not analyzed", all_md)

        # Case 3: Verify NO domain whitelisting is hardcoded
        view_src = inspect.getsource(analyze_view)
        adapter_src = inspect.getsource(sc)
        self.assertNotIn("nptel.ac.in", view_src, "No domain whitelisting in views/analyze.py")
        self.assertNotIn("WHITELISTED_DOMAINS", view_src, "No WHITELISTED_DOMAINS in views/analyze.py")

    # -------------------------------------------------------------------------
    # Invariant 8: Gmail inbox ordering
    # -------------------------------------------------------------------------
    def test_invariant_08_gmail_inbox_ordering(self):
        """
        Verify newest to oldest ordering is preserved.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        unordered_cases = [
            {"case_id": "c_old", "timestamp": (now - datetime.timedelta(hours=6)).isoformat(), "subject": "Old", "user_id": self.test_user_id},
            {"case_id": "c_newest", "timestamp": now.isoformat(), "subject": "Newest", "user_id": self.test_user_id},
            {"case_id": "c_mid", "timestamp": (now - datetime.timedelta(hours=2)).isoformat(), "subject": "Mid", "user_id": self.test_user_id},
        ]

        with patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_all_cases", return_value=unordered_cases), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            messages = get_authorized_live_mail_messages(self.test_user_id, self.mock_client, limit=50)

            self.assertEqual(len(messages), 3)
            self.assertEqual(messages[0]["case_id"], "c_newest", "Newest message must be index 0")
            self.assertEqual(messages[1]["case_id"], "c_mid", "Middle message must be index 1")
            self.assertEqual(messages[2]["case_id"], "c_old", "Oldest message must be index 2")

    # -------------------------------------------------------------------------
    # Invariant 9: Deduplication
    # -------------------------------------------------------------------------
    def test_invariant_09_deduplication(self):
        """
        Verify each UID appears only once, eliminating duplicates while preserving order.
        """
        duplicate_messages = [
            {"id": "uid_001", "subject": "Subj 1", "sender": "s1@test.com"},
            {"id": "uid_002", "subject": "Subj 2", "sender": "s2@test.com"},
            {"id": "uid_001", "subject": "Subj 1 duplicate", "sender": "s1@test.com"},
            {"id": "uid_003", "subject": "Subj 3", "sender": "s3@test.com"},
            {"id": "uid_002", "subject": "Subj 2 duplicate", "sender": "s2@test.com"},
        ]

        state = {
            "email_analysis_source": "📬 Select from Live Mail",
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=duplicate_messages), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)

            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertIn("Inbox Messages (3 loaded)", all_md, "Must count exactly 3 unique emails")

            # Check that Select buttons are rendered for exactly 3 unique UIDs
            btn_keys = [c[1].get("key") for c in mock_btn.call_args_list if "btn_select_live_" in str(c[1].get("key"))]
            self.assertEqual(len(btn_keys), 3, "Exactly 3 Select buttons must be rendered for 3 unique UIDs")

    # -------------------------------------------------------------------------
    # Invariant 10: Selection persistence
    # -------------------------------------------------------------------------
    def test_invariant_10_selection_persistence(self):
        """
        Verify selection persists across Streamlit reruns.
        """
        # Run 1: User previously selected msg_005
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_uid": "msg_005",
            "selected_live_mail_message_id": "<msg_005@domain.in>",
            "selected_live_mail_index": 4,
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)

            # Verify selection was NOT reset to msg_001
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_uid"), "msg_005")
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_index"), 4)

            # Verify dedicated action card displays msg_005
            all_md = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            self.assertIn("Security Alert #005", all_md)

    # -------------------------------------------------------------------------
    # Invariant 11: Logout clears selection
    # -------------------------------------------------------------------------
    def test_invariant_11_logout_clears_selection(self):
        """
        Verify `clear_investigator_session()` purges:
          - selected_live_mail_uid
          - selected_live_mail_message_id
          - selected_live_mail_index
          - live_mail_analysis_status
        """
        fake_session = {
            "user_id": self.test_user_id,
            "selected_live_mail_uid": "msg_007",
            "selected_live_mail_message_id": "<msg_007@domain.in>",
            "selected_live_mail_index": 6,
            "live_mail_analysis_status": {"msg_007": "SAFE"},
            "current_email_bytes": b"fake_bytes",
        }

        with patch("streamlit.session_state", fake_session):
            clear_investigator_session()
            self.assertNotIn("selected_live_mail_uid", fake_session)
            self.assertNotIn("selected_live_mail_message_id", fake_session)
            self.assertNotIn("selected_live_mail_index", fake_session)
            self.assertNotIn("live_mail_analysis_status", fake_session)
            self.assertNotIn("current_email_bytes", fake_session)

    # -------------------------------------------------------------------------
    # Invariant 12: Zero telemetry mutation
    # -------------------------------------------------------------------------
    def test_invariant_12_zero_telemetry_mutation(self):
        """
        Verify manual analysis does not alter Sentinel stats, metrics, or checkpoints.
        """
        record_user_sentinel_poll(
            user_id=self.test_user_id,
            mailbox_id=self.mailbox_id,
            arrived=20,
            analysed=15,
            clean=12,
            suspicious=3,
            last_uid=300
        )

        stats_before = get_user_sentinel_stats(self.test_user_id, self.mailbox_id)
        self.assertEqual(stats_before["emails_arrived"], 20)
        self.assertEqual(stats_before["emails_analysed"], 15)
        self.assertEqual(stats_before["last_processed_uid"], 300)

        # Simulate user selecting and clicking Analyze This Email
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_uid": "msg_001",
        }

        def mock_button_click(label, **kwargs):
            return kwargs.get("key") == "btn_analyze_selected_live_email"

        fake_rfc822_bytes = b"From: s1@ext.com\r\nSubject: Test\r\n\r\nBody"

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=self.sample_messages), \
             patch("views.analyze.convert_live_message_to_rfc822_bytes", return_value=("test.eml", fake_rfc822_bytes)), \
             patch("views.analyze.st.button", side_effect=mock_button_click), \
             patch("views.analyze.st.markdown"), \
             patch("views.analyze.st.rerun"):

            analyze_view.render(self.test_user_id, self.mock_client)

        # Verify Sentinel stats and checkpoint are completely unchanged
        stats_after = get_user_sentinel_stats(self.test_user_id, self.mailbox_id)
        self.assertEqual(stats_after["emails_arrived"], 20, "emails_arrived must remain 20")
        self.assertEqual(stats_after["emails_analysed"], 15, "emails_analysed must remain 15")
        self.assertEqual(stats_after["last_processed_uid"], 300, "last_processed_uid must remain 300")


if __name__ == "__main__":
    unittest.main()
