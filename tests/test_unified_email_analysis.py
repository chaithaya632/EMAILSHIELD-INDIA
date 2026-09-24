"""
tests/test_unified_email_analysis.py
Comprehensive test suite validating the Merged Single Email + Batch Unified Analysis Experience in EMAILSHIELD INDIA.

Requirements verified:
1.  test_01_unified_page_no_mode_selector:
    Inspect views/analyze.py to confirm that render() does not render 'Single Email' vs 'Batch Analysis'
    radio choices or 'Analysis Mode'. Confirm that the page header title is 'Analyze Email' with unified subtitle.
2.  test_02_source_options_upload_and_live_mail:
    Inspect render() to confirm source options are ['📤 Upload Email', '📬 Select from Live Mail'].
    Confirm default selection and programmatic routing from Dashboard (show_batch flag).
3.  test_03_upload_email_path_intact:
    Verify that when '📤 Upload Email' is active, st.file_uploader for .eml files is available and sets current_email_bytes.
4.  test_04_live_mail_requires_authenticated_caller:
    Verify unauthenticated or unauthorized users are blocked fail-closed when accessing Live Mail selection.
5.  test_05_live_mail_empty_states:
    Test empty state when no mailbox is connected and when mailbox has 0 messages.
6.  test_06_scrolling_navigation_previous_next:
    Test current_live_mail_index navigation logic: Previous decrements index (bounded to 0),
    Next increments index (bounded to len - 1), bounds clamping, and jump navigation.
7.  test_07_no_filters_in_live_mail_selection:
    Verify that Live Mail selection does NOT contain Risk filter, IOC filter, Attachment filter,
    Date filter, Search filter, or Sort controls.
    Verify it does NOT render a giant table or multi-select controls ('Selected: X emails', 'Select All', 'Clear Selection').
8.  test_08_single_email_selection_button:
    Verify the action button is '🔍 Analyze This Email' (not 'Analyze Selected Emails').
    Verify clicking the button converts message to RFC 822 MIME bytes and stores them in current_email_bytes.
9.  test_09_both_sources_converge_on_canonical_result_ui:
    Verify that both convert_live_message_to_rfc822_bytes and .eml upload provide RFC 822 MIME bytes
    (current_email_bytes) that feed into the identical forensic pipeline (SecureEmailParser, MLClassifier,
    evaluate_rules, calculate_hybrid_risk, extract_all_indicators, analyze_all_attachments).
    Enforce CRITICAL UX acceptance: identical canonical result renderer, zero separate Batch/Live Mail result UI.
10. test_10_choose_another_email_resets_state:
    Verify that clicking 'Choose Another Email' clears current_email_bytes and resets the view to email selection.
11. test_11_live_telemetry_isolation_mandatory_check:
    CRITICAL: Verify that manually selecting and analyzing a Live Mail email does NOT alter:
    - Emails Arrived
    - Emails Analysed
    - Threats Detected
    - Last UID / last_processed_uid
    - sentinel_telemetry.json
    - TenantSentinelMetrics
    - CheckpointStore
12. test_12_tenant_and_mailbox_isolation:
    Verify cross-tenant Live Mail email queries are strictly denied and mailbox filtering is enforced.
"""

import os
import sys
import io
import json
import inspect
import unittest
from unittest.mock import patch, MagicMock, call
import pandas as pd

import views.analyze as analyze_view
from core.live_mail_adapter import (
    convert_live_message_to_rfc822_bytes,
    get_authorized_live_mail_messages,
    DEFAULT_LIVE_MAIL_LIMIT,
    LIVE_MAIL_LIMIT_OPTIONS,
)
from core.parser import SecureEmailParser
from core.classifier import MLClassifier
from core.batch_scanner import categorize_content
from core.auth_claims import evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.indicators import extract_all_indicators
from core.attachments import analyze_all_attachments


class TestUnifiedEmailAnalysis(unittest.TestCase):
    """Test suite validating the 12 requirements for the unified Analyze Email experience."""

    def setUp(self):
        self.classifier = MLClassifier()
        self.test_user_id = "user_unified_analyst_001"
        self.mock_client = MagicMock()
        self.mock_client.auth.uid.return_value = self.test_user_id

    # -------------------------------------------------------------------------
    # Requirement 1: Unified Page Has No Mode Selector
    # -------------------------------------------------------------------------
    def test_01_unified_page_no_mode_selector(self):
        """
        Inspect views/analyze.py to confirm that render() does not render
        'Single Email' vs 'Batch Analysis' radio choices or 'Analysis Mode'.
        Confirm that the page header title is 'Analyze Email' with unified subtitle.
        """
        src = inspect.getsource(analyze_view.render)

        # 1. Confirm absence of separate Analysis Mode selector
        self.assertNotIn(
            "Analysis Mode",
            src,
            "render() must not contain 'Analysis Mode' radio label or mode switcher."
        )
        self.assertNotIn(
            '["🔍 Single Email", "📦 Batch Analysis"]',
            src,
            "render() must not offer 'Single Email' vs 'Batch Analysis' mode choices."
        )
        self.assertNotIn(
            "analysis_mode_selector",
            src,
            "render() must not reference the legacy 'analysis_mode_selector' key."
        )

        # 2. Confirm page header title and unified subtitle
        self.assertIn(
            "page_header('Analyze Email'",
            src,
            "render() must invoke page_header with title 'Analyze Email'."
        )
        self.assertIn(
            "Analyze an email for threats, IOCs and forensic evidence",
            src,
            "render() must specify the unified subtitle in page_header."
        )

        # 3. Simulate execution with mocked Streamlit
        mock_session_state = {}
        with patch.dict(analyze_view.st.session_state, mock_session_state, clear=True), \
             patch("views.analyze.page_header") as mock_ph, \
             patch("views.analyze.st.radio") as mock_radio, \
             patch("views.analyze.render_single_email"):

            analyze_view.render(self.test_user_id, self.mock_client)
            mock_ph.assert_called_once_with(
                'Analyze Email',
                'Analyze an email for threats, IOCs and forensic evidence'
            )
            for c_args in mock_radio.call_args_list:
                label = c_args[0][0] if c_args[0] else c_args[1].get("label", "")
                self.assertNotEqual(
                    label,
                    "Analysis Mode",
                    "st.radio must not be called with 'Analysis Mode'"
                )

    # -------------------------------------------------------------------------
    # Requirement 2: Source Options (Upload and Live Mail)
    # -------------------------------------------------------------------------
    def test_02_source_options_upload_and_live_mail(self):
        """
        Inspect render() to confirm source options are ['📤 Upload Email', '📬 Select from Live Mail'].
        Verify default selection and programmatic routing from Dashboard (show_batch flag).
        """
        src = inspect.getsource(analyze_view.render)
        self.assertIn('["📤 Upload Email", "📬 Select from Live Mail"]', src)

        # 1. Default selection is Upload Email (index 0) when state is empty
        mock_session_state = {}
        with patch.dict(analyze_view.st.session_state, mock_session_state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio") as mock_radio, \
             patch("views.analyze.render_single_email"):

            analyze_view.render(self.test_user_id, self.mock_client)
            matching_calls = [
                c for c in mock_radio.call_args_list
                if c[1].get("options") == ["📤 Upload Email", "📬 Select from Live Mail"]
            ]
            self.assertEqual(len(matching_calls), 1)
            self.assertEqual(matching_calls[0][1].get("index"), 0)
            self.assertEqual(matching_calls[0][1].get("key"), "email_analysis_source")

        # 2. Programmatic routing from Dashboard 'show_batch' flag routes to Live Mail
        mock_session_state = {"show_batch": True}
        with patch.dict(analyze_view.st.session_state, mock_session_state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio") as mock_radio, \
             patch("views.analyze.is_authorized_caller", return_value=False), \
             patch("views.analyze.error_card"):

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertEqual(
                analyze_view.st.session_state.get("email_analysis_source"),
                "📬 Select from Live Mail",
                "show_batch flag from Dashboard must route to '📬 Select from Live Mail'"
            )
            self.assertNotIn("show_batch", analyze_view.st.session_state, "show_batch flag must be popped")

    # -------------------------------------------------------------------------
    # Requirement 3: Upload Email Path Intact
    # -------------------------------------------------------------------------
    def test_03_upload_email_path_intact(self):
        """
        Verify that when '📤 Upload Email' is active, st.file_uploader for .eml files
        is available and sets current_email_bytes.
        """
        src = inspect.getsource(analyze_view.render_single_email)
        self.assertIn("st.file_uploader", src)
        self.assertIn("Upload .eml file locally", src)
        self.assertIn("type=[\"eml\"]", src)

        # Functional simulation of file upload
        sample_eml_bytes = (
            b"From: test-sender@secure.in\r\n"
            b"To: analyst@emailshield.in\r\n"
            b"Subject: Inbound Sample Report\r\n"
            b"Date: Sun, 20 Sep 2026 10:00:00 +0000\r\n"
            b"\r\n"
            b"Valid forensic EML body content."
        )
        mock_file = MagicMock()
        mock_file.size = len(sample_eml_bytes)
        mock_file.getvalue.return_value = sample_eml_bytes

        mock_session_state = {"email_analysis_source": "📤 Upload Email"}
        with patch.dict(analyze_view.st.session_state, mock_session_state, clear=True), \
             patch("views.analyze.st.file_uploader", return_value=mock_file), \
             patch("views.analyze.check_rate_limit", return_value=(True, 0)), \
             patch("views.analyze.st.columns", return_value=[MagicMock(), MagicMock()]):

            analyze_view.render_single_email(self.test_user_id, self.mock_client)
            self.assertEqual(
                analyze_view.st.session_state.get("current_email_bytes"),
                sample_eml_bytes,
                "Uploaded .eml bytes must be stored in current_email_bytes"
            )

    # -------------------------------------------------------------------------
    # Requirement 4: Live Mail Requires Authenticated Caller
    # -------------------------------------------------------------------------
    def test_04_live_mail_requires_authenticated_caller(self):
        """
        Verify unauthenticated or unauthorized users are blocked fail-closed
        when accessing Live Mail selection.
        """
        # 1. UI Layer: Unauthenticated caller renders error card
        mock_session_state = {"email_analysis_source": "📬 Select from Live Mail"}
        with patch.dict(analyze_view.st.session_state, mock_session_state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=False), \
             patch("views.analyze.error_card") as mock_error, \
             patch("views.analyze.get_authorized_live_mail_messages") as mock_get_msgs:

            analyze_view.render(current_user_id=None, user_client=None)
            self.assertTrue(mock_error.called, "error_card must be rendered when unauthenticated")
            title = mock_error.call_args[1].get("title") or mock_error.call_args[0][0]
            self.assertIn("Authentication Required", title)
            mock_get_msgs.assert_not_called()

        # 2. Adapter Layer: Fail-closed checks on get_authorized_live_mail_messages
        self.assertEqual(get_authorized_live_mail_messages(user_id=None, client=None), [])
        self.assertEqual(get_authorized_live_mail_messages(user_id="", client=None), [])

        with patch("core.live_mail_adapter.is_authorized_caller", return_value=False):
            res_unauth = get_authorized_live_mail_messages(user_id="intruder_id", client=MagicMock())
            self.assertEqual(res_unauth, [], "Unauthorized user must receive empty list")

    # -------------------------------------------------------------------------
    # Requirement 5: Live Mail Empty States
    # -------------------------------------------------------------------------
    def test_05_live_mail_empty_states(self):
        """
        Test empty state when no mailbox is connected and when mailbox has 0 messages.
        """
        # State A: No mailbox connected
        mock_session_state = {"email_analysis_source": "📬 Select from Live Mail"}
        with patch.dict(analyze_view.st.session_state, mock_session_state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=None), \
             patch("views.analyze.list_user_mailboxes", return_value=[]), \
             patch("views.analyze.empty_state") as mock_empty:

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertTrue(mock_empty.called, "empty_state must be called when no mailbox is connected")
            kwargs = mock_empty.call_args[1] if mock_empty.call_args[1] else {}
            self.assertEqual(kwargs.get("icon"), "📬")
            self.assertIn("No mailbox connected", kwargs.get("title", ""))

        # State B: Connected mailbox with 0 messages
        active_mailbox = {
            "id": "mb_active_001",
            "is_active": True,
            "email_address": "soc@emailshield.in",
            "provider": "Gmail"
        }
        mock_session_state = {"email_analysis_source": "📬 Select from Live Mail"}
        with patch.dict(analyze_view.st.session_state, mock_session_state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mailbox), \
             patch("views.analyze.list_user_mailboxes", return_value=[active_mailbox]), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=[]), \
             patch("views.analyze.empty_state") as mock_empty:

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertTrue(mock_empty.called, "empty_state must be called when mailbox has 0 messages")
            kwargs = mock_empty.call_args[1] if mock_empty.call_args[1] else {}
            self.assertEqual(kwargs.get("icon"), "📭")
            self.assertIn("No Live Mail emails available yet", kwargs.get("title", ""))

    # -------------------------------------------------------------------------
    # Requirement 6: Natural Page Scroll & Card Selection (No Pagination Buttons)
    # -------------------------------------------------------------------------
    def test_06_scrolling_navigation_previous_next(self):
        """
        Test that pagination controls (Previous/Next) are removed and replaced
        by natural vertical card scrolling and selection by UID.
        """
        sample_messages = [
            {"id": f"msg_{i}", "subject": f"Inbound {i}", "sender": f"sender{i}@domain.com"}
            for i in range(4)
        ]
        active_mb = {"id": "mb_active", "is_active": True, "email_address": "soc@corp.in"}

        state = {"email_analysis_source": "📬 Select from Live Mail"}
        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=sample_messages), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)

            # Assert no Previous or Next buttons
            btn_labels = [c[0][0] for c in mock_btn.call_args_list if c[0]]
            self.assertFalse(any("Previous" in str(l) for l in btn_labels), "Previous button must NOT be rendered")
            self.assertFalse(any("Next" in str(l) for l in btn_labels), "Next button must NOT be rendered")

            # Assert natural vertical rendering of all 4 messages
            md_text = " ".join(str(c[0][0]) for c in mock_md.call_args_list if c[0])
            for i in range(4):
                self.assertIn(f"Inbound {i}", md_text)


    # -------------------------------------------------------------------------
    # Requirement 7: No Filters in Live Mail Selection
    # -------------------------------------------------------------------------
    def test_07_no_filters_in_live_mail_selection(self):
        """
        Verify that Live Mail selection does NOT contain Risk filter, IOC filter,
        Attachment filter, Date filter, Search filter, or Sort controls.
        Verify it does NOT render a giant table or multi-select controls
        ('Selected: X emails', 'Select All', 'Clear Selection').
        """
        src = inspect.getsource(analyze_view.render)
        self.assertIn("📬 Select from Live Mail", src)
        live_mail_section = src.split('selected_source == "📤 Upload Email":')[1]

        # 1. Assert absence of category filters and search
        self.assertNotIn("live_batch_filter_risk", live_mail_section)
        self.assertNotIn("live_batch_filter_att", live_mail_section)
        self.assertNotIn("live_batch_filter_ioc", live_mail_section)
        self.assertNotIn("live_mail_search_input", live_mail_section)
        self.assertNotIn("Search Live Mail", live_mail_section)
        self.assertNotIn("filter_risk", live_mail_section)
        self.assertNotIn("sort_by", live_mail_section)

        # 2. Assert absence of table, multi-select checkboxes, and mass actions
        self.assertNotIn("st.dataframe", live_mail_section)
        self.assertNotIn("Select All Visible", live_mail_section)
        self.assertNotIn("Clear Selection", live_mail_section)
        self.assertNotIn("btn_select_all", live_mail_section)
        self.assertNotIn("btn_clear_selection", live_mail_section)
        self.assertNotIn("Selected: ", live_mail_section)
        self.assertNotIn("chk_live_", live_mail_section)

    # -------------------------------------------------------------------------
    # Requirement 8: Single Email Selection Action Button
    # -------------------------------------------------------------------------
    def test_08_single_email_selection_button(self):
        """
        Verify the action button is '🔍 Analyze This Email' (not 'Analyze Selected Emails').
        Verify button click produces bytes and updates session state.
        """
        src = inspect.getsource(analyze_view.render)
        self.assertIn("🔍 Analyze This Email", src)
        self.assertNotIn("Analyze Selected Emails", src)
        self.assertNotIn("Analyze X Selected Email(s)", src)

        sample_msg = {
            "id": "live_msg_select_btn_test",
            "subject": "Wire Transfer Urgent Review",
            "sender": "cfo@company.in",
            "recipient": "finance@company.in",
            "case_data": {
                "headers": {"subject": "Wire Transfer Urgent Review", "from": "cfo@company.in"},
                "body": "Please wire funds promptly."
            }
        }
        active_mb = {"id": "mb_act", "is_active": True, "email_address": "finance@company.in"}
        state = {"email_analysis_source": "📬 Select from Live Mail", "current_live_mail_index": 0}

        def mock_button_click(label, **kwargs):
            return label == "🔍 Analyze This Email"

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=[sample_msg]), \
             patch("views.analyze.st.button", side_effect=mock_button_click), \
             patch("views.analyze.st.selectbox", return_value=0), \
             patch("views.analyze.st.rerun") as mock_rerun:

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertIsNotNone(analyze_view.st.session_state.get("current_email_bytes"))
            self.assertIsInstance(analyze_view.st.session_state.get("current_email_bytes"), bytes)
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_id"), "live_msg_select_btn_test")
            mock_rerun.assert_called_once()

    # -------------------------------------------------------------------------
    # Requirement 9: Both Sources Converge on Canonical Result UI
    # -------------------------------------------------------------------------
    def test_09_both_sources_converge_on_canonical_result_ui(self):
        """
        Verify that both convert_live_message_to_rfc822_bytes and .eml upload provide RFC 822 MIME bytes
        (current_email_bytes) that feed into the identical forensic pipeline (SecureEmailParser, MLClassifier,
        evaluate_rules, calculate_hybrid_risk, extract_all_indicators, analyze_all_attachments).

        Enforces CRITICAL UX ACCEPTANCE:
        - no separate Batch Analysis result UI
        - no separate Live Mail result UI
        - no duplicated forensic renderer
        - no reduced analysis capability
        Both paths converge on render_forensic_results(bytes_data, ...)
        """
        # 1. Structural check: render() routes both sources to render_forensic_results when bytes_data is set
        render_src = inspect.getsource(analyze_view.render)
        self.assertIn("render_forensic_results(bytes_data", render_src)

        # 2. Path A: Raw EML upload byte stream
        upload_eml_bytes = (
            b"From: payment-update@secure-bank.in\r\n"
            b"To: target-victim@corp.in\r\n"
            b"Subject: Immediate Action: Account Verification Required\r\n"
            b"Date: Sun, 20 Sep 2026 12:00:00 +0000\r\n"
            b"Message-ID: <MSG-UPLOAD-BANK-001@secure-bank.in>\r\n"
            b"\r\n"
            b"Verify your online banking access at http://phishing-portal.xyz/login\r\n"
        )

        # 3. Path B: Live Mail converted to RFC822 bytes
        live_mail_record = {
            "id": "live_msg_converge_002",
            "subject": "Immediate Action: Account Verification Required",
            "sender": "payment-update@secure-bank.in",
            "recipient": "target-victim@corp.in",
            "date": "Sun, 20 Sep 2026 12:00:00 +0000",
            "case_data": {
                "headers": {
                    "subject": "Immediate Action: Account Verification Required",
                    "from": "payment-update@secure-bank.in",
                    "to": "target-victim@corp.in",
                    "date": "Sun, 20 Sep 2026 12:00:00 +0000",
                    "message-id": "<MSG-LIVE-BANK-002@secure-bank.in>",
                },
                "body": "Verify your online banking access at http://phishing-portal.xyz/login",
                "indicators": [{"type": "URL", "value": "http://phishing-portal.xyz/login"}]
            }
        }
        _, live_mail_bytes = convert_live_message_to_rfc822_bytes(live_mail_record, self.test_user_id)
        self.assertIsInstance(live_mail_bytes, bytes)

        # 4. Both streams execute identically through the canonical forensic pipeline
        for label, stream in [("EML_Upload", upload_eml_bytes), ("Live_Mail", live_mail_bytes)]:
            parser = SecureEmailParser(stream)
            parsed_data = parser.parse()
            headers = parsed_data.get("headers", {})
            subject = str(headers.get("subject", ""))
            sender = str(headers.get("from", ""))
            body = parsed_data.get("body", "")

            self.assertEqual(subject, "Immediate Action: Account Verification Required", f"Subject mismatch in {label}")
            self.assertIn("payment-update@secure-bank.in", sender, f"Sender mismatch in {label}")

            content_type = categorize_content(subject, body, sender, headers)
            auth_alignment = evaluate_auth_and_alignment(headers)
            ml_pred = self.classifier.predict(subject, body)
            rule_findings = evaluate_rules(parsed_data, auth_alignment=auth_alignment, content_type=content_type)
            risk_score, reasons = calculate_hybrid_risk(
                rule_findings, ml_pred["probability"],
                auth_alignment=auth_alignment, content_type=content_type
            )
            indicators = extract_all_indicators(body + " " + str(headers))
            attachments = analyze_all_attachments(parsed_data.get("attachments", []))

            self.assertIn(risk_score, ["LOW", "SUSPICIOUS", "HIGH", "CRITICAL"])
            self.assertGreaterEqual(len(indicators.get("urls", [])), 1)
            self.assertIn("http://phishing-portal.xyz/login", indicators["urls"])

    # -------------------------------------------------------------------------
    # Requirement 10: Choose Another Email Resets State
    # -------------------------------------------------------------------------
    def test_10_choose_another_email_resets_state(self):
        """
        Verify that clicking 'Choose Another Email' clears current_email_bytes
        and resets the view to email selection.
        """
        src = inspect.getsource(analyze_view.render)
        self.assertIn("btn_choose_another_email", src)
        self.assertIn("← Choose Another Email", src)

        # 1. State with active email bytes
        state = {
            "current_email_bytes": b"SAMPLE-MIME-RAW-BYTES",
            "_cached_analysis_payload": {"sha256": "1234567890abcdef"},
            "selected_live_mail_id": "msg_active_99",
        }

        def mock_btn_choose(label, **kwargs):
            return label == "← Choose Another Email" or kwargs.get("key") == "btn_choose_another_email"

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.button", side_effect=mock_btn_choose), \
             patch("views.analyze.st.rerun") as mock_rerun, \
             patch("views.analyze.render_forensic_results"):

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertIsNone(analyze_view.st.session_state.get("current_email_bytes"), "current_email_bytes must be reset to None")
            self.assertIsNone(analyze_view.st.session_state.get("_cached_analysis_payload"), "_cached_analysis_payload must be reset to None")
            self.assertNotIn("selected_live_mail_id", analyze_view.st.session_state, "selected_live_mail_id must be removed")
            mock_rerun.assert_called_once()

        # 2. Subsequent call with cleared state renders email source options
        analyze_view.st.session_state["current_email_bytes"] = None
        with patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio") as mock_radio, \
             patch("views.analyze.render_single_email"):

            analyze_view.render(self.test_user_id, self.mock_client)
            source_calls = [
                c for c in mock_radio.call_args_list
                if c[1].get("options") == ["📤 Upload Email", "📬 Select from Live Mail"]
            ]
            self.assertEqual(len(source_calls), 1, "Source selector must be rendered after reset")

    # -------------------------------------------------------------------------
    # Requirement 11: Live Telemetry Isolation Mandatory Check
    # -------------------------------------------------------------------------
    def test_11_live_telemetry_isolation_mandatory_check(self):
        """
        CRITICAL: Verify that manually selecting and analyzing a Live Mail email does NOT alter:
        - Emails Arrived
        - Emails Analysed
        - Threats Detected
        - Last UID / last_processed_uid
        - sentinel_telemetry.json
        - TenantSentinelMetrics
        - CheckpointStore
        """
        telemetry_dir = os.path.join("data", "local", "sentinel_telemetry")
        telemetry_file = os.path.join(telemetry_dir, "sentinel_telemetry.json")

        initial_mtime = os.path.getmtime(telemetry_file) if os.path.exists(telemetry_file) else None
        initial_content = None
        if os.path.exists(telemetry_file):
            try:
                with open(telemetry_file, "r", encoding="utf-8") as tf:
                    initial_content = tf.read()
            except Exception:
                pass

        sample_live_msg = {
            "id": "live_telemetry_iso_check",
            "subject": "Quarterly Operations Review",
            "sender": "operations@corporate.in",
            "recipient": "analyst@emailshield.in",
            "case_data": {
                "headers": {"subject": "Quarterly Operations Review", "from": "operations@corporate.in"},
                "body": "Quarterly review data attached."
            }
        }

        with patch("core.sentinel_stats.record_user_sentinel_poll") as mock_poll, \
             patch("core.sentinel_control.upsert_user_checkpoint") as mock_checkpoint, \
             patch("core.sentinel_control.save_user_mailbox_metadata") as mock_update_mb, \
             patch("core.telegram_alert.send_telegram_alert") as mock_tg, \
             patch("core.whatsapp_alert.send_whatsapp_alert") as mock_wa:

            # 1. Convert live message to RFC822 bytes
            _, file_bytes = convert_live_message_to_rfc822_bytes(sample_live_msg, self.test_user_id)
            self.assertIsInstance(file_bytes, bytes)

            # 2. Execute the entire forensic pipeline (as render_forensic_results does)
            parser = SecureEmailParser(file_bytes)
            parsed_data = parser.parse()
            headers = parsed_data.get("headers", {})
            subject = str(headers.get("subject", ""))
            sender = str(headers.get("from", ""))
            body = parsed_data.get("body", "")

            content_type = categorize_content(subject, body, sender, headers)
            auth_alignment = evaluate_auth_and_alignment(headers)
            ml_pred = self.classifier.predict(subject, body)
            rule_findings = evaluate_rules(parsed_data, auth_alignment=auth_alignment, content_type=content_type)
            risk_score, _ = calculate_hybrid_risk(
                rule_findings, ml_pred["probability"],
                auth_alignment=auth_alignment, content_type=content_type
            )
            iocs = extract_all_indicators(body + " " + str(headers))
            atts = analyze_all_attachments(parsed_data.get("attachments", []))

            # Assert Sentinel worker telemetry and checkpoint methods were NEVER called
            mock_poll.assert_not_called()
            mock_checkpoint.assert_not_called()
            mock_update_mb.assert_not_called()
            mock_tg.assert_not_called()
            mock_wa.assert_not_called()

            # Confirm sentinel_telemetry.json was NOT touched
            if initial_mtime is not None and os.path.exists(telemetry_file):
                current_mtime = os.path.getmtime(telemetry_file)
                self.assertEqual(initial_mtime, current_mtime, "Analysis modified sentinel_telemetry.json mtime!")
                with open(telemetry_file, "r", encoding="utf-8") as tf:
                    current_content = tf.read()
                self.assertEqual(initial_content, current_content, "Analysis modified sentinel_telemetry.json contents!")

    # -------------------------------------------------------------------------
    # Requirement 12: Tenant and Mailbox Isolation
    # -------------------------------------------------------------------------
    def test_12_tenant_and_mailbox_isolation(self):
        """
        Verify cross-tenant Live Mail email queries are strictly denied
        and mailbox filtering is enforced.
        """
        tenant_alpha = "user_tenant_alpha_001"
        tenant_beta = "user_tenant_beta_002"

        mb_alpha_primary = "mb_alpha_primary_111"
        mb_alpha_secondary = "mb_alpha_secondary_222"
        mb_beta_primary = "mb_beta_primary_333"

        cases_store = [
            {"case_id": "c_a1", "user_id": tenant_alpha, "mailbox_id": mb_alpha_primary, "subject": "Alpha Secret 1", "sender": "sec@alpha.in"},
            {"case_id": "c_a2", "user_id": tenant_alpha, "mailbox_id": mb_alpha_secondary, "subject": "Alpha Secondary 2", "sender": "sec2@alpha.in"},
            {"case_id": "c_b1", "user_id": tenant_beta, "mailbox_id": mb_beta_primary, "subject": "Beta Classified 1", "sender": "ceo@beta.in"},
            {"case_id": "c_b2", "user_id": tenant_beta, "mailbox_id": mb_beta_primary, "subject": "Beta Financials 2", "sender": "cfo@beta.in"},
        ]

        mock_alpha_client = MagicMock()
        mock_beta_client = MagicMock()

        with patch("core.live_mail_adapter.get_all_cases", return_value=cases_store), \
             patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:

            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            # 1. Tenant Alpha queries all authorized messages
            alpha_msgs = get_authorized_live_mail_messages(user_id=tenant_alpha, client=mock_alpha_client)
            alpha_ids = [m["id"] for m in alpha_msgs]
            self.assertEqual(len(alpha_msgs), 2)
            self.assertIn("c_a1", alpha_ids)
            self.assertIn("c_a2", alpha_ids)
            self.assertNotIn("c_b1", alpha_ids, "Cross-tenant leak: Beta case c_b1 visible to Alpha!")
            self.assertNotIn("c_b2", alpha_ids, "Cross-tenant leak: Beta case c_b2 visible to Alpha!")

            # 2. Tenant Alpha filters by mb_alpha_primary
            alpha_mb1_msgs = get_authorized_live_mail_messages(user_id=tenant_alpha, client=mock_alpha_client, mailbox_id=mb_alpha_primary)
            alpha_mb1_ids = [m["id"] for m in alpha_mb1_msgs]
            self.assertEqual(len(alpha_mb1_msgs), 1)
            self.assertIn("c_a1", alpha_mb1_ids)
            self.assertNotIn("c_a2", alpha_mb1_ids)

            # 3. Tenant Alpha attempts cross-tenant mailbox query (mb_beta_primary)
            alpha_tamper_msgs = get_authorized_live_mail_messages(user_id=tenant_alpha, client=mock_alpha_client, mailbox_id=mb_beta_primary)
            self.assertEqual(len(alpha_tamper_msgs), 0, "Cross-tenant mailbox access must return empty list")

            # 4. Tenant Beta queries all authorized messages
            beta_msgs = get_authorized_live_mail_messages(user_id=tenant_beta, client=mock_beta_client)
            beta_ids = [m["id"] for m in beta_msgs]
            self.assertEqual(len(beta_msgs), 2)
            self.assertIn("c_b1", beta_ids)
            self.assertIn("c_b2", beta_ids)
            self.assertNotIn("c_a1", beta_ids, "Cross-tenant leak: Alpha case c_a1 visible to Beta!")
            self.assertNotIn("c_a2", beta_ids, "Cross-tenant leak: Alpha case c_a2 visible to Beta!")

    # -------------------------------------------------------------------------
    # Requirement 13: Header CRLF / Newline Sanitization in convert_live_message_to_rfc822_bytes
    # -------------------------------------------------------------------------
    def test_13_header_newline_sanitization_in_convert_live_message(self):
        """
        Validates:
        1. Message records with \r\n, \n, or \r in subject, sender, recipient, date, message_id,
           and auth headers do NOT raise ValueError: Header values may not contain linefeed or carriage return characters.
        2. as_bytes() succeeds and headers are cleanly unfolded and sanitized (no raw CR or LF).
        3. Various CRLF variations: mixed CRLF, lone \r, lone \n, consecutive CRLFs, tab-unfolding.
        """
        # Test Case A: Comprehensive dirty record with \r\n, \n, and \r across all headers
        dirty_record = {
            "id": "crlf_test_001\r\n",
            "subject": "Urgent Action Required:\r\nVerify Wire Transfer\nImmediately\r",
            "sender": "cfo-spoofed@corporate.in\r\nBcc: evil-attacker@phish.in",
            "recipient": "finance-analyst@corp.in\r\n",
            "date": "Sun, 20 Sep 2026 12:00:00 +0000\r\n",
            "message_id": "<msg-crlf-123\r\n@evil.in>",
            "case_data": {
                "headers": {
                    "subject": "Urgent Action Required:\r\nVerify Wire Transfer\nImmediately\r",
                    "from": "cfo-spoofed@corporate.in\r\nBcc: evil-attacker@phish.in",
                    "to": "finance-analyst@corp.in\r\n",
                    "date": "Sun, 20 Sep 2026 12:00:00 +0000\r\n",
                    "message-id": "<msg-crlf-123\r\n@evil.in>",
                    "authentication-results": "mx.emailshield.in;\r\n spf=pass (corp.in: spf matches)\r\n dkim=pass",
                    "dkim-signature": "v=1; a=rsa-sha256;\r\n d=corporate.in; s=202601;\r\n b=ab12cd34ef==",
                    "return-path": "<bounces@corporate.in>\r\n",
                },
                "received_chain": [
                    "from mail.evil.in ([198.51.100.1])\r\n by mx.emailshield.in with ESMTP;\r\n Sun, 20 Sep 2026 12:00:00 +0000"
                ],
                "body": "Please wire funds promptly."
            }
        }

        # Must NOT raise ValueError: Header values may not contain linefeed or carriage return characters
        try:
            fname, file_bytes = convert_live_message_to_rfc822_bytes(dirty_record, self.test_user_id)
        except ValueError as e:
            self.fail(f"convert_live_message_to_rfc822_bytes raised ValueError with CRLF in headers: {e}")

        self.assertIsInstance(file_bytes, bytes)
        self.assertGreater(len(file_bytes), 0)

        # Parse with SecureEmailParser
        parser = SecureEmailParser(file_bytes)
        parsed = parser.parse()
        headers = parsed.get("headers", {})

        # Verify subject unfolded cleanly without \r or \n
        subj_parsed = str(headers.get("subject", ""))
        self.assertNotIn("\r", subj_parsed)
        self.assertNotIn("\n", subj_parsed)
        self.assertIn("Urgent Action Required: Verify Wire Transfer Immediately", subj_parsed)

        # Verify sender unfolded cleanly
        from_parsed = str(headers.get("from", ""))
        self.assertNotIn("\r", from_parsed)
        self.assertNotIn("\n", from_parsed)
        self.assertIn("cfo-spoofed@corporate.in Bcc: evil-attacker@phish.in", from_parsed)

        # Verify recipient unfolded cleanly
        to_parsed = str(headers.get("to", ""))
        self.assertNotIn("\r", to_parsed)
        self.assertNotIn("\n", to_parsed)
        self.assertEqual(to_parsed, "finance-analyst@corp.in")

        # Verify date unfolded cleanly
        date_parsed = str(headers.get("date", ""))
        self.assertNotIn("\r", date_parsed)
        self.assertNotIn("\n", date_parsed)
        self.assertEqual(date_parsed, "Sun, 20 Sep 2026 12:00:00 +0000")

        # Verify message-id unfolded cleanly
        msgid_parsed = str(headers.get("message-id", ""))
        self.assertNotIn("\r", msgid_parsed)
        self.assertNotIn("\n", msgid_parsed)
        self.assertEqual(msgid_parsed, "<msg-crlf-123@evil.in>")

        # Verify authentication headers unfolded cleanly
        auth_parsed = str(headers.get("authentication-results", ""))
        self.assertNotIn("\r", auth_parsed)
        self.assertNotIn("\n", auth_parsed)
        self.assertIn("spf=pass", auth_parsed)

        dkim_parsed = str(headers.get("dkim-signature", ""))
        self.assertNotIn("\r", dkim_parsed)
        self.assertNotIn("\n", dkim_parsed)
        self.assertIn("v=1; a=rsa-sha256;", dkim_parsed)

        rp_parsed = str(headers.get("return-path", ""))
        self.assertNotIn("\r", rp_parsed)
        self.assertNotIn("\n", rp_parsed)
        self.assertEqual(rp_parsed, "<bounces@corporate.in>")

        # Test Case B: Edge case with multiple consecutive newlines and lone CR
        dirty_record_edge = {
            "id": "crlf_edge_002",
            "subject": "Invoice\r\r\r\n\n\nPayment",
            "sender": "attacker@domain.com\r\r\n",
            "recipient": "victim@domain.com\n\n\n",
            "date": "\r\nSun, 20 Sep 2026 12:00:00 +0000\r\n",
            "message_id": "\r<edge-msg@domain.com>\n",
            "case_data": {
                "headers": {
                    "authentication-results": "\r\n\r\nmx.test.in; spf=pass\r\n\r\n",
                    "dkim-signature": "\n\nv=1;\n\n",
                    "return-path": "\r\n<bounce@domain.com>\r\n"
                }
            }
        }
        _, edge_bytes = convert_live_message_to_rfc822_bytes(dirty_record_edge, self.test_user_id)
        self.assertIsInstance(edge_bytes, bytes)
        edge_parser = SecureEmailParser(edge_bytes)
        edge_parsed = edge_parser.parse()
        edge_headers = edge_parsed.get("headers", {})
        self.assertEqual(str(edge_headers.get("subject", "")), "Invoice Payment")
        self.assertEqual(str(edge_headers.get("from", "")), "attacker@domain.com")
        self.assertEqual(str(edge_headers.get("to", "")), "victim@domain.com")
        self.assertEqual(str(edge_headers.get("return-path", "")), "<bounce@domain.com>")

    # -------------------------------------------------------------------------
    # Requirement 14: Fetch Limit Options [50, 100, 200] and Default = 50
    # -------------------------------------------------------------------------
    def test_14_fetch_limit_options_and_default(self):
        """
        Validates:
        1. Default limit is 50.
        2. Limit options are [50, 100, 200].
        3. get_authorized_live_mail_messages respects limit=50, limit=100, limit=200,
           capping results properly.
        4. UI inspects and verifies Fetch Limit selectbox is offered.
        """
        # 1. Verify module constants
        self.assertEqual(DEFAULT_LIVE_MAIL_LIMIT, 50, "Default live mail limit must be 50")
        self.assertEqual(LIVE_MAIL_LIMIT_OPTIONS, [50, 100, 200], "Live mail limit options must be [50, 100, 200]")
        self.assertEqual(getattr(analyze_view, "DEFAULT_LIVE_MAIL_LIMIT", 50), 50)
        self.assertEqual(getattr(analyze_view, "LIVE_MAIL_LIMIT_OPTIONS", [50, 100, 200]), [50, 100, 200])

        # 2. Verify signature default parameter
        sig = inspect.signature(get_authorized_live_mail_messages)
        self.assertEqual(
            sig.parameters["limit"].default, 50,
            "get_authorized_live_mail_messages default limit parameter must be 50"
        )

        # 3. Verify get_authorized_live_mail_messages capping with a large pool of messages (250 cases)
        large_case_pool = [
            {
                "case_id": f"c_large_{i:03d}",
                "user_id": self.test_user_id,
                "mailbox_id": "mb_main",
                "subject": f"Inbound {i}",
                "sender": f"sender_{i}@domain.in"
            }
            for i in range(250)
        ]

        def mock_get_all_cases(client=None, limit=50):
            return large_case_pool[:limit]

        with patch("core.live_mail_adapter.get_all_cases", side_effect=mock_get_all_cases), \
             patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:

            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            # Default limit (no limit argument passed) -> caps to 50
            msgs_default = get_authorized_live_mail_messages(self.test_user_id, self.mock_client)
            self.assertEqual(len(msgs_default), 50, "Default call must cap at 50 messages")

            # limit=50
            msgs_50 = get_authorized_live_mail_messages(self.test_user_id, self.mock_client, limit=50)
            self.assertEqual(len(msgs_50), 50, "limit=50 must return exactly 50 messages")

            # limit=100
            msgs_100 = get_authorized_live_mail_messages(self.test_user_id, self.mock_client, limit=100)
            self.assertEqual(len(msgs_100), 100, "limit=100 must return exactly 100 messages")

            # limit=200
            msgs_200 = get_authorized_live_mail_messages(self.test_user_id, self.mock_client, limit=200)
            self.assertEqual(len(msgs_200), 200, "limit=200 must return exactly 200 messages")

            # Verify capping even if store returns more
            with patch("core.live_mail_adapter.get_all_cases", return_value=large_case_pool):
                msgs_capped = get_authorized_live_mail_messages(self.test_user_id, self.mock_client, limit=50)
                self.assertEqual(len(msgs_capped), 50, "Store returning excess cases must be capped to limit=50")

        # 4. Verify UI exposes Fetch Limit
        src = inspect.getsource(analyze_view.render)
        self.assertIn("Fetch Limit", src, "render() must contain 'Fetch Limit' selectbox")
        self.assertIn("LIVE_MAIL_LIMIT_OPTIONS", src, "render() must use LIVE_MAIL_LIMIT_OPTIONS")

    # -------------------------------------------------------------------------
    # Requirement 15: Index Clamping on Limit Change
    # -------------------------------------------------------------------------
    def test_15_index_clamping_on_limit_change(self):
        """
        Validates:
        1. When switching from 200 -> 50, if current index was 120, verify it is
           safely clamped to len(messages) - 1 (49) without IndexError.
        2. Edge cases: index beyond range clamped to len - 1, negative clamped to 0.
        3. UI correctly renders without IndexError when index exceeds available messages.
        """
        active_mb = {"id": "mb_clamp_test", "is_active": True, "email_address": "analyst@emailshield.in"}
        messages_50 = [
            {"id": f"msg_50_{i}", "subject": f"Email {i}", "sender": f"s{i}@corp.in"}
            for i in range(50)
        ]

        # Scenario: User was previously viewing index 120 (e.g. limit was 200), now limit is 50
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "live_mail_fetch_limit": 50,
            "current_live_mail_index": 120,
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=messages_50), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.selectbox") as mock_sb:

            # Mock selectbox to return the current index if called for jump
            mock_sb.side_effect = lambda label, *args, **kwargs: (
                50 if "Fetch Limit" in label else kwargs.get("index", 0)
            )

            # Execution must NOT raise IndexError
            try:
                analyze_view.render(self.test_user_id, self.mock_client)
            except IndexError as e:
                self.fail(f"render() raised IndexError during limit change clamping: {e}")

            # Verify index was safely clamped to len(messages) - 1 = 49
            clamped_idx = analyze_view.st.session_state.get("current_live_mail_index")
            self.assertEqual(
                clamped_idx, 49,
                f"Index 120 must be clamped to 49 when switching to 50 messages, got {clamped_idx}"
            )

        # Edge Case B: Single email list (len=1), index was 5 -> clamped to 0
        state_single = {
            "email_analysis_source": "📬 Select from Live Mail",
            "live_mail_fetch_limit": 50,
            "current_live_mail_index": 5,
        }
        single_msg = [{"id": "msg_single_0", "subject": "Single Inbound", "sender": "sec@corp.in"}]
        with patch.dict(analyze_view.st.session_state, state_single, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=single_msg), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.selectbox", return_value=0):

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertEqual(
                analyze_view.st.session_state.get("current_live_mail_index"), 0,
                "Index must clamp to 0 when only 1 email is present"
            )

    # -------------------------------------------------------------------------
    # Requirement 16: Two-Stage Performance (Lazy RFC822 Generation)
    # -------------------------------------------------------------------------
    def test_16_two_stage_performance_lazy_rfc822_generation(self):
        """
        Validates:
        1. Stage 1: Initial listing does NOT generate or download full RFC 822 MIME bytes
           for every message in the list.
        2. Stage 2: 'Analyze This Email' generates/fetches RFC 822 MIME bytes for the
           selected message only.
        """
        active_mb = {"id": "mb_perf_test", "is_active": True, "email_address": "analyst@emailshield.in"}
        sample_50_messages = [
            {
                "id": f"live_msg_perf_{i}",
                "case_id": f"live_msg_perf_{i}",
                "subject": f"Operations Inbound #{i}",
                "sender": f"user{i}@partner.in",
                "recipient": "analyst@emailshield.in",
                "case_data": {
                    "headers": {"subject": f"Operations Inbound #{i}", "from": f"user{i}@partner.in"},
                    "body": f"Sample body text {i}"
                }
            }
            for i in range(50)
        ]

        # Stage 1: Initial Listing - convert_live_message_to_rfc822_bytes must NOT be called
        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "current_live_mail_index": 5,
        }
        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=sample_50_messages), \
             patch("views.analyze.st.button", return_value=False), \
             patch("views.analyze.st.selectbox", return_value=5), \
             patch("views.analyze.convert_live_message_to_rfc822_bytes") as mock_convert:

            analyze_view.render(self.test_user_id, self.mock_client)
            self.assertEqual(
                mock_convert.call_count, 0,
                "Stage 1 initial listing must NEVER invoke convert_live_message_to_rfc822_bytes for list items"
            )
            self.assertIsNone(
                analyze_view.st.session_state.get("current_email_bytes"),
                "current_email_bytes must remain None during listing stage"
            )

        # Stage 2: User clicks 'Analyze This Email' on selected email (index 5)
        selected_msg = sample_50_messages[5]

        def mock_click_analyze(label, **kwargs):
            return label == "🔍 Analyze This Email" or kwargs.get("key", "").startswith("btn_analyze_single_live_")

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=sample_50_messages), \
             patch("views.analyze.st.button", side_effect=mock_click_analyze), \
             patch("views.analyze.st.selectbox", return_value=5), \
             patch("views.analyze.st.rerun"), \
             patch("views.analyze.convert_live_message_to_rfc822_bytes", wraps=convert_live_message_to_rfc822_bytes) as spy_convert:

            analyze_view.render(self.test_user_id, self.mock_client)
            # Must be called exactly once, specifically with selected_msg
            self.assertEqual(
                spy_convert.call_count, 1,
                "Stage 2 'Analyze This Email' must invoke convert_live_message_to_rfc822_bytes exactly ONCE"
            )
            called_msg = spy_convert.call_args[0][0]
            self.assertEqual(called_msg["id"], selected_msg["id"])
            self.assertEqual(called_msg["subject"], selected_msg["subject"])

            # Verify bytes were generated and placed into current_email_bytes
            stored_bytes = analyze_view.st.session_state.get("current_email_bytes")
            self.assertIsNotNone(stored_bytes)
            self.assertIsInstance(stored_bytes, bytes)
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_id"), "live_msg_perf_5")

    # -------------------------------------------------------------------------
    # Requirement 17: Security & Telemetry Invariants
    # -------------------------------------------------------------------------
    def test_17_security_and_telemetry_invariants(self):
        """
        Validates all security and telemetry invariants:
        1. Live telemetry counters (Emails Arrived, Emails Analysed, Last UID, Checkpoint,
           sentinel_telemetry.json) remain 100% UNCHANGED during live mail browsing and analysis.
        2. Tenant isolation: cross-tenant access denied across all live mail queries.
        3. Server-side RLS enforced fail-closed on unauthenticated / untrusted callers.
        """
        telemetry_dir = os.path.join("data", "local", "sentinel_telemetry")
        telemetry_file = os.path.join(telemetry_dir, "sentinel_telemetry.json")

        initial_content = None
        if os.path.exists(telemetry_file):
            try:
                with open(telemetry_file, "r", encoding="utf-8") as f:
                    initial_content = f.read()
            except Exception:
                pass

        # 1. Telemetry untouched during browsing and analysis
        with patch("core.sentinel_stats.record_user_sentinel_poll") as mock_poll, \
             patch("core.sentinel_control.upsert_user_checkpoint") as mock_cp, \
             patch("core.sentinel_control.save_user_mailbox_metadata") as mock_meta, \
             patch("core.telegram_alert.send_telegram_alert") as mock_tg, \
             patch("core.whatsapp_alert.send_whatsapp_alert") as mock_wa:

            # Query authorized messages
            mock_client = MagicMock()
            mock_client.auth.uid.return_value = "tenant_invariants_user"
            with patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
                 patch("core.live_mail_adapter.get_all_cases", return_value=[]):
                msgs = get_authorized_live_mail_messages("tenant_invariants_user", mock_client, limit=50)
                self.assertEqual(msgs, [])

            # Convert and run forensic analysis
            sample_msg = {
                "id": "iso_check_17",
                "subject": "Status Report",
                "sender": "sender@domain.in",
                "case_data": {"headers": {"subject": "Status Report", "from": "sender@domain.in"}}
            }
            _, rfc_bytes = convert_live_message_to_rfc822_bytes(sample_msg, "tenant_invariants_user")
            parser = SecureEmailParser(rfc_bytes)
            _ = parser.parse()

            mock_poll.assert_not_called()
            mock_cp.assert_not_called()
            mock_meta.assert_not_called()
            mock_tg.assert_not_called()
            mock_wa.assert_not_called()

        if initial_content is not None and os.path.exists(telemetry_file):
            with open(telemetry_file, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), initial_content, "sentinel_telemetry.json must not be modified")

        # 2. Strict RLS and Tenant Isolation
        self.assertEqual(get_authorized_live_mail_messages(None, None), [], "Unauthenticated must return []")
        self.assertEqual(get_authorized_live_mail_messages("", None), [], "Empty user must return []")

        with patch("core.live_mail_adapter.is_authorized_caller", return_value=False):
            tampered = get_authorized_live_mail_messages("spoofed_user", MagicMock())
            self.assertEqual(tampered, [], "Unauthorized caller must return []")

        # 3. Cross-Tenant query isolation
        tenant_1 = "tenant_001"
        tenant_2 = "tenant_002"
        all_cases = [
            {"case_id": "c_t1", "user_id": tenant_1, "mailbox_id": "mb_1", "subject": "T1 confidential"},
            {"case_id": "c_t2", "user_id": tenant_2, "mailbox_id": "mb_2", "subject": "T2 confidential"}
        ]
        with patch("core.live_mail_adapter.get_all_cases", return_value=all_cases), \
             patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            client_1 = MagicMock()
            client_1.auth.uid.return_value = tenant_1
            res_1 = get_authorized_live_mail_messages(tenant_1, client_1, limit=50)
            res_ids_1 = [m["id"] for m in res_1]
            self.assertEqual(res_ids_1, ["c_t1"])
            self.assertNotIn("c_t2", res_ids_1, "Tenant 1 must not see Tenant 2's cases")

            # Cross-tenant mailbox ID access attempt
            tamper_mb = get_authorized_live_mail_messages(tenant_1, client_1, mailbox_id="mb_2", limit=50)
            self.assertEqual(tamper_mb, [], "Querying another tenant's mailbox must yield empty list")


if __name__ == "__main__":
    unittest.main()
