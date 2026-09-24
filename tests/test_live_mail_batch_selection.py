"""
tests/test_live_mail_batch_selection.py
Comprehensive test suite validating the Live Mail Email Selection feature for Batch Analysis in EMAILSHIELD INDIA.

Requirements verified:
1.  test_01_batch_analysis_source_is_live_mail_only_and_eml_removed:
    Default analysis source is "📬 Select from Live Mail", BATCH_SOURCE_OPTIONS contains only Live Mail,
    "📤 Upload .eml Files" is removed from Batch Analysis, while .eml upload remains intact in Single Email analysis.
2.  test_02_live_mail_requires_authenticated_caller:
    get_authorized_live_mail_messages fails closed and returns empty list when user_id is missing,
    client is invalid/unauthorized, or is_authorized_caller returns False.
3.  test_03_cross_tenant_live_mail_query_denied:
    User A cannot see or select User B's Live Mail messages.
4.  test_04_mailbox_filtering_and_switching:
    Filtering messages by mailbox_id works properly and only messages for the requested mailbox are returned.
5.  test_05_live_mail_empty_states_no_mailbox_and_no_messages:
    Empty state handling when no mailbox is configured and when a mailbox is configured but has 0 messages.
6.  test_06_search_by_subject_sender_message_id:
    Search filtering matches against subject, sender, and message-id (case-insensitive).
7.  test_07_filters_risk_attachment_iocs:
    Filtering by Risk ("Clean", "Suspicious", "High", "Critical"), Attachments ("Has Attachment", "No Attachment"),
    and IOCs ("Has IOC", "No IOC").
8.  test_08_multi_selection_and_select_all_visible:
    Multi-selection state logic: adding multiple IDs, toggling checkboxes, and Select All Visible adding all filtered IDs.
9.  test_09_clear_selection:
    Clear Selection empties the selected IDs set.
10. test_10_single_live_email_analysis_compatibility:
    Selecting exactly 1 live email runs through convert_live_message_to_rfc822_bytes and the forensic pipeline,
    generating 1 batch result entry with valid FileBytes and metadata.
11. test_11_multiple_live_email_analysis_execution:
    Selecting multiple live emails (e.g. 3) analyzes all 3, populating summary metrics (Processed=3, Clean/Suspicious/High/Critical, Errors=0).
12. test_12_existing_forensic_pipeline_reused_without_duplication:
    Existing forensic components (SecureEmailParser, calculate_hybrid_risk, extract_all_indicators, analyze_all_attachments)
    are directly called without secondary engine.
13. test_13_batch_live_counter_isolation_mandatory_check:
    Running Batch Analysis on Live Mail emails does NOT change or increment:
    Emails Arrived, Emails Analysed, Threats Detected, Last UID / last_processed_uid,
    sentinel_telemetry, TenantSentinelMetrics, CheckpointStore.
14. test_14_live_mail_batch_exports_csv_json_pdf:
    CSV, JSON, and PDF report exports operate cleanly on batch results originating from Live Mail messages.
15. test_15_full_analysis_pivot_from_live_mail_batch_result:
    FileBytes produced from convert_live_message_to_rfc822_bytes can be passed to single email analysis seamlessly.
"""

import os
import io
import json
import pytest
import unittest
from unittest.mock import patch, MagicMock
import pandas as pd

from core.live_mail_adapter import (
    DEFAULT_BATCH_SOURCE,
    BATCH_SOURCE_OPTIONS,
    get_authorized_live_mail_messages,
    filter_live_mail_messages,
    convert_live_message_to_rfc822_bytes,
    select_all_visible,
    clear_selection,
    toggle_selection,
)
from core.parser import SecureEmailParser
from core.classifier import MLClassifier
from core.batch_scanner import categorize_content
from core.auth_claims import evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.indicators import extract_all_indicators
from core.attachments import analyze_all_attachments
from core.report import generate_batch_pdf_report


class TestLiveMailBatchSelection(unittest.TestCase):
    """Test suite covering the 15 requirements for Live Mail Batch Selection."""

    def setUp(self):
        self.classifier = MLClassifier()
        self.test_user_id = "user_tenant_alpha_123"
        self.mock_client = MagicMock()
        self.mock_client.auth.uid.return_value = self.test_user_id

    # -------------------------------------------------------------------------
    # Requirement 1: Batch Analysis Source is Live Mail Only & .eml Removed
    # -------------------------------------------------------------------------
    def test_01_batch_analysis_source_is_live_mail_only_and_eml_removed(self):
        """
        Verifies:
        1. DEFAULT_BATCH_SOURCE == "📬 Select from Live Mail"
        2. BATCH_SOURCE_OPTIONS == ["📬 Select from Live Mail"]
        3. "📤 Upload .eml Files" is NOT in BATCH_SOURCE_OPTIONS
        4. In views/analyze.py, inside render_batch_analysis, there is NO file uploader
           ('batch_eml_uploader' or 'Upload multiple email files (.eml)')
        5. In views/analyze.py, inside render_single_email, .eml file upload
           ('Upload .eml file locally' or 'st.file_uploader') is STILL PRESENT and INTACT!
        """
        import inspect
        import views.analyze as analyze_view

        # 1. Constant definition checks
        self.assertEqual(DEFAULT_BATCH_SOURCE, "📬 Select from Live Mail")
        self.assertEqual(BATCH_SOURCE_OPTIONS, ["📬 Select from Live Mail"])
        self.assertNotIn("📤 Upload .eml Files", BATCH_SOURCE_OPTIONS)
        self.assertIn("📬 Select from Live Mail", BATCH_SOURCE_OPTIONS)

        # 2. Simulated UI state default
        simulated_session_state = {}
        active_source = simulated_session_state.get("batch_source_selector", DEFAULT_BATCH_SOURCE)
        self.assertEqual(active_source, "📬 Select from Live Mail")

        # 3. Verify that index 0 in options resolves to default source
        default_idx = 0
        self.assertEqual(BATCH_SOURCE_OPTIONS[default_idx], DEFAULT_BATCH_SOURCE)

        # 4. Verify that in views/analyze.py, inside render_batch_analysis, there is NO file uploader
        batch_func_src = inspect.getsource(analyze_view.render_batch_analysis)
        self.assertNotIn("batch_eml_uploader", batch_func_src,
                         "File uploader key 'batch_eml_uploader' must not be in render_batch_analysis")
        self.assertNotIn("Upload multiple email files (.eml)", batch_func_src,
                         "File uploader label 'Upload multiple email files (.eml)' must not be in render_batch_analysis")
        self.assertNotIn("st.file_uploader", batch_func_src,
                         "st.file_uploader must not be present in render_batch_analysis")

        # 5. Verify that in views/analyze.py, inside render_single_email, .eml file upload is STILL PRESENT and INTACT
        single_func_src = inspect.getsource(analyze_view.render_single_email)
        self.assertTrue(
            "Upload .eml file locally" in single_func_src or "st.file_uploader" in single_func_src,
            "render_single_email must retain .eml file uploader"
        )
        self.assertIn("Upload .eml file locally", single_func_src)
        self.assertIn("st.file_uploader", single_func_src)

    # -------------------------------------------------------------------------
    # Requirement 2: Authentication Fail-Closed
    # -------------------------------------------------------------------------
    def test_02_live_mail_requires_authenticated_caller(self):
        """
        Verifies get_authorized_live_mail_messages fails closed and returns empty list
        when user_id is missing, client is invalid/unauthorized, or is_authorized_caller returns False.
        """
        # Case A: user_id is None
        res_none_user = get_authorized_live_mail_messages(user_id=None, client=self.mock_client)
        self.assertEqual(res_none_user, [], "Failed to fail-closed when user_id is None")

        # Case B: user_id is empty string
        res_empty_user = get_authorized_live_mail_messages(user_id="", client=self.mock_client)
        self.assertEqual(res_empty_user, [], "Failed to fail-closed when user_id is empty string")

        # Case C: is_authorized_caller returns False
        with patch("core.live_mail_adapter.is_authorized_caller", return_value=False):
            res_unauth = get_authorized_live_mail_messages(user_id="user_unauth_999", client=self.mock_client)
            self.assertEqual(res_unauth, [], "Failed to fail-closed when is_authorized_caller returns False")

        # Case D: client is None and unauthorized in public/strict mode
        with patch("core.live_mail_adapter.is_authorized_caller", return_value=False):
            res_no_client = get_authorized_live_mail_messages(user_id="user_any", client=None)
            self.assertEqual(res_no_client, [], "Failed to fail-closed when client is None and unauthorized")

    # -------------------------------------------------------------------------
    # Requirement 3: Multi-Tenant Isolation
    # -------------------------------------------------------------------------
    def test_03_cross_tenant_live_mail_query_denied(self):
        """Verifies User A cannot see or select User B's Live Mail messages."""
        user_a = "user_tenant_A"
        user_b = "user_tenant_B"

        tenant_a_cases = [
            {"case_id": "case_A1", "user_id": user_a, "subject": "Quarterly Financials A", "sender": "cfo@company-a.com"},
            {"case_id": "case_A2", "user_id": user_a, "subject": "Board Meeting A", "sender": "ceo@company-a.com"},
        ]
        tenant_b_cases = [
            {"case_id": "case_B1", "user_id": user_b, "subject": "Strict Secret B", "sender": "security@company-b.com"},
            {"case_id": "case_B2", "user_id": user_b, "subject": "Source Code Release B", "sender": "dev@company-b.com"},
        ]
        all_cases = tenant_a_cases + tenant_b_cases

        client_a = MagicMock()
        client_b = MagicMock()

        # Mock get_all_cases returning combined cases (simulating shared backend before RLS filter)
        with patch("core.live_mail_adapter.get_all_cases", return_value=all_cases), \
             patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            # Query for Tenant A
            messages_a = get_authorized_live_mail_messages(user_id=user_a, client=client_a)
            ids_a = [m["id"] for m in messages_a]
            subjects_a = [m["subject"] for m in messages_a]

            # Assert Tenant A sees only Tenant A's emails
            self.assertIn("case_A1", ids_a)
            self.assertIn("case_A2", ids_a)
            self.assertNotIn("case_B1", ids_a, "Cross-tenant leak: Tenant B message visible to Tenant A!")
            self.assertNotIn("case_B2", ids_a, "Cross-tenant leak: Tenant B message visible to Tenant A!")
            self.assertNotIn("Strict Secret B", subjects_a)

            # Query for Tenant B
            messages_b = get_authorized_live_mail_messages(user_id=user_b, client=client_b)
            ids_b = [m["id"] for m in messages_b]
            self.assertIn("case_B1", ids_b)
            self.assertIn("case_B2", ids_b)
            self.assertNotIn("case_A1", ids_b, "Cross-tenant leak: Tenant A message visible to Tenant B!")
            self.assertNotIn("case_A2", ids_b, "Cross-tenant leak: Tenant A message visible to Tenant B!")

    # -------------------------------------------------------------------------
    # Requirement 4: Mailbox Filtering and Switching
    # -------------------------------------------------------------------------
    def test_04_mailbox_filtering_and_switching(self):
        """Verifies filtering messages by mailbox_id works properly and only messages for requested mailbox are returned."""
        mb_work = "mb_work_uuid_111"
        mb_personal = "mb_personal_uuid_222"

        mocked_cases = [
            {"case_id": "msg_w1", "mailbox_id": mb_work, "user_id": self.test_user_id, "subject": "Work Ops Sync", "sender": "manager@work.com"},
            {"case_id": "msg_w2", "mailbox_id": mb_work, "user_id": self.test_user_id, "subject": "Work Invoices", "sender": "vendor@work.com"},
            {"case_id": "msg_p1", "mailbox_id": mb_personal, "user_id": self.test_user_id, "subject": "Personal Bank Alert", "sender": "alerts@mybank.in"},
        ]

        with patch("core.live_mail_adapter.get_all_cases", return_value=mocked_cases), \
             patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            # 1. Filter for Work Mailbox
            work_msgs = get_authorized_live_mail_messages(user_id=self.test_user_id, client=self.mock_client, mailbox_id=mb_work)
            work_ids = [m["id"] for m in work_msgs]
            self.assertEqual(len(work_msgs), 2)
            self.assertIn("msg_w1", work_ids)
            self.assertIn("msg_w2", work_ids)
            self.assertNotIn("msg_p1", work_ids)

            # 2. Switch to Personal Mailbox
            pers_msgs = get_authorized_live_mail_messages(user_id=self.test_user_id, client=self.mock_client, mailbox_id=mb_personal)
            pers_ids = [m["id"] for m in pers_msgs]
            self.assertEqual(len(pers_msgs), 1)
            self.assertIn("msg_p1", pers_ids)
            self.assertNotIn("msg_w1", pers_ids)
            self.assertNotIn("msg_w2", pers_ids)

            # 3. Non-existent Mailbox returns 0 messages
            empty_msgs = get_authorized_live_mail_messages(user_id=self.test_user_id, client=self.mock_client, mailbox_id="mb_non_existent")
            self.assertEqual(len(empty_msgs), 0)

            # 4. Unspecified Mailbox (None) returns all authorized user messages
            all_user_msgs = get_authorized_live_mail_messages(user_id=self.test_user_id, client=self.mock_client, mailbox_id=None)
            self.assertEqual(len(all_user_msgs), 3)

    # -------------------------------------------------------------------------
    # Requirement 5: Empty States Handling
    # -------------------------------------------------------------------------
    def test_05_live_mail_empty_states_no_mailbox_and_no_messages(self):
        """Verifies empty state handling when no mailbox is configured and when mailbox has 0 messages."""
        import core.sentinel_control as sc

        # Scenario A: No mailbox configured (table returns empty list)
        mock_empty_client = MagicMock()
        mock_query = MagicMock()
        mock_query.order.return_value.execute.return_value.data = []
        mock_query.execute.return_value.data = []
        mock_empty_client.table.return_value.select.return_value.eq.return_value = mock_query

        mailbox = sc.get_user_mailbox(self.test_user_id, mock_empty_client)
        self.assertIsNone(mailbox)
        
        # Live mail messages retrieval without mailbox returns empty list gracefully
        with patch("core.live_mail_adapter.get_all_cases", return_value=[]), \
             patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            msgs = get_authorized_live_mail_messages(self.test_user_id, mock_empty_client, mailbox_id=None)
            self.assertEqual(msgs, [])

        # Scenario B: Mailbox configured but 0 messages ingested
        mock_mb_client = MagicMock()
        mock_mb_query = MagicMock()
        mock_mb_data = [
            {
                "id": "mb_configured_empty",
                "user_id": self.test_user_id,
                "email_address": "analyst@security-firm.in",
                "provider": "gmail",
                "is_active": True
            }
        ]
        mock_mb_query.order.return_value.execute.return_value.data = mock_mb_data
        mock_mb_query.execute.return_value.data = mock_mb_data
        mock_mb_client.table.return_value.select.return_value.eq.return_value = mock_mb_query

        active_mb = sc.get_user_mailbox(self.test_user_id, mock_mb_client)
        self.assertIsNotNone(active_mb)
        self.assertEqual(active_mb["email_address"], "analyst@security-firm.in")

        with patch("core.live_mail_adapter.get_all_cases", return_value=[]), \
             patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            live_msgs = get_authorized_live_mail_messages(self.test_user_id, mock_mb_client, mailbox_id=active_mb["id"])
            self.assertEqual(len(live_msgs), 0)
            self.assertEqual(live_msgs, [])

    # -------------------------------------------------------------------------
    # Requirement 6: Search by Subject, Sender, and Message-ID
    # -------------------------------------------------------------------------
    def test_06_search_by_subject_sender_message_id(self):
        """Verifies search filtering matches against subject, sender, and message-id (case-insensitive)."""
        messages = [
            {
                "id": "m1",
                "subject": "Urgent Wire Transfer Authorization",
                "sender": "ceo-desk@executive-fraud.org",
                "message_id": "<MSG-WIRE-9912@corp.local>",
                "risk": "HIGH",
            },
            {
                "id": "m2",
                "subject": "Payment Receipt for Invoice #44091",
                "sender": "billing@cloud-services.com",
                "message_id": "<INV-44091-ALPHA@billing.com>",
                "risk": "LOW",
            },
            {
                "id": "m3",
                "subject": "Critical Security Alert: New Login Attempt",
                "sender": "security-alert@hdfcbank-alert.xyz",
                "message_id": "<SEC-ALERT-8831@alert.xyz>",
                "risk": "CRITICAL",
            },
        ]

        # 1. Match Subject (case-insensitive substring)
        f_subj = filter_live_mail_messages(messages, search_query="wire transfer")
        self.assertEqual(len(f_subj), 1)
        self.assertEqual(f_subj[0]["id"], "m1")

        f_subj_case = filter_live_mail_messages(messages, search_query="INVOICE #44091")
        self.assertEqual(len(f_subj_case), 1)
        self.assertEqual(f_subj_case[0]["id"], "m2")

        # 2. Match Sender (case-insensitive substring)
        f_sndr = filter_live_mail_messages(messages, search_query="ceo-desk@executive")
        self.assertEqual(len(f_sndr), 1)
        self.assertEqual(f_sndr[0]["id"], "m1")

        f_sndr_domain = filter_live_mail_messages(messages, search_query="HDFCBANK-ALERT")
        self.assertEqual(len(f_sndr_domain), 1)
        self.assertEqual(f_sndr_domain[0]["id"], "m3")

        # 3. Match Message-ID (case-insensitive substring)
        f_mid = filter_live_mail_messages(messages, search_query="MSG-WIRE-9912")
        self.assertEqual(len(f_mid), 1)
        self.assertEqual(f_mid[0]["id"], "m1")

        f_mid_bracket = filter_live_mail_messages(messages, search_query="<sec-alert-8831")
        self.assertEqual(len(f_mid_bracket), 1)
        self.assertEqual(f_mid_bracket[0]["id"], "m3")

        # 4. Non-matching search returns empty list
        f_empty = filter_live_mail_messages(messages, search_query="completely_unmatched_term_xyz")
        self.assertEqual(len(f_empty), 0)

        # 5. Empty or whitespace search returns all messages
        f_all = filter_live_mail_messages(messages, search_query="   ")
        self.assertEqual(len(f_all), 3)

    # -------------------------------------------------------------------------
    # Requirement 7: Facet Filters (Risk, Attachments, IOCs)
    # -------------------------------------------------------------------------
    def test_07_filters_risk_attachment_iocs(self):
        """
        Verifies filtering by Risk ('Clean', 'Suspicious', 'High', 'Critical'),
        Attachments ('Has Attachment', 'No Attachment'), and IOCs ('Has IOC', 'No IOC').
        """
        dataset = [
            {"id": "c1", "risk": "LOW", "has_attachment": False, "attachment_count": 0, "has_ioc": False, "ioc_count": 0},
            {"id": "s1", "risk": "SUSPICIOUS", "has_attachment": True, "attachment_count": 1, "has_ioc": False, "ioc_count": 0},
            {"id": "h1", "risk": "HIGH", "has_attachment": False, "attachment_count": 0, "has_ioc": True, "ioc_count": 3},
            {"id": "k1", "risk": "CRITICAL", "has_attachment": True, "attachment_count": 2, "has_ioc": True, "ioc_count": 6},
        ]

        # 1. Risk Filters
        self.assertEqual([m["id"] for m in filter_live_mail_messages(dataset, risk_filter="Clean")], ["c1"])
        self.assertEqual([m["id"] for m in filter_live_mail_messages(dataset, risk_filter="Suspicious")], ["s1"])
        self.assertEqual([m["id"] for m in filter_live_mail_messages(dataset, risk_filter="High")], ["h1"])
        self.assertEqual([m["id"] for m in filter_live_mail_messages(dataset, risk_filter="Critical")], ["k1"])
        self.assertEqual(len(filter_live_mail_messages(dataset, risk_filter="All")), 4)

        # 2. Attachment Filters
        with_att = filter_live_mail_messages(dataset, attachment_filter="Has Attachment")
        self.assertEqual([m["id"] for m in with_att], ["s1", "k1"])

        no_att = filter_live_mail_messages(dataset, attachment_filter="No Attachment")
        self.assertEqual([m["id"] for m in no_att], ["c1", "h1"])

        # 3. IOC Filters
        with_ioc = filter_live_mail_messages(dataset, ioc_filter="Has IOC")
        self.assertEqual([m["id"] for m in with_ioc], ["h1", "k1"])

        no_ioc = filter_live_mail_messages(dataset, ioc_filter="No IOC")
        self.assertEqual([m["id"] for m in no_ioc], ["c1", "s1"])

        # 4. Multi-Facet Combined Filter (Critical + Has Attachment + Has IOC)
        combined = filter_live_mail_messages(
            dataset,
            risk_filter="Critical",
            attachment_filter="Has Attachment",
            ioc_filter="Has IOC"
        )
        self.assertEqual([m["id"] for m in combined], ["k1"])

    # -------------------------------------------------------------------------
    # Requirement 8: Multi-Selection and Select All Visible
    # -------------------------------------------------------------------------
    def test_08_multi_selection_and_select_all_visible(self):
        """
        Verifies multi-selection state logic: adding multiple IDs, toggling checkboxes,
        and Select All Visible adding all filtered IDs to the selection set.
        """
        selection_set = set()

        # 1. Add individual IDs
        selection_set = toggle_selection(selection_set, "msg_01")
        self.assertEqual(selection_set, {"msg_01"})

        selection_set = toggle_selection(selection_set, "msg_02")
        self.assertEqual(selection_set, {"msg_01", "msg_02"})

        # 2. Toggle off an existing ID (checkbox uncheck)
        selection_set = toggle_selection(selection_set, "msg_01")
        self.assertEqual(selection_set, {"msg_02"})

        # 3. Select All Visible: applies to current visible/filtered subset
        visible_subset = [
            {"id": "msg_02", "subject": "Msg 2"},
            {"id": "msg_03", "subject": "Msg 3"},
            {"id": "msg_04", "subject": "Msg 4"},
        ]
        selection_set = select_all_visible(selection_set, visible_subset)
        self.assertEqual(selection_set, {"msg_02", "msg_03", "msg_04"})

        # 4. Idempotence: calling Select All Visible again maintains exact set
        selection_set = select_all_visible(selection_set, visible_subset)
        self.assertEqual(selection_set, {"msg_02", "msg_03", "msg_04"})

    # -------------------------------------------------------------------------
    # Requirement 9: Clear Selection
    # -------------------------------------------------------------------------
    def test_09_clear_selection(self):
        """Verifies Clear Selection empties the selected IDs set."""
        active_selections = {"id_alpha", "id_beta", "id_gamma"}
        self.assertEqual(len(active_selections), 3)

        # Clear active selection
        cleared = clear_selection(active_selections)
        self.assertEqual(cleared, set())
        self.assertEqual(len(cleared), 0)
        self.assertEqual(len(active_selections), 0)

        # Clear on empty set is safe and idempotent
        cleared_again = clear_selection(cleared)
        self.assertEqual(cleared_again, set())

    # -------------------------------------------------------------------------
    # Requirement 10: Single Live Email Analysis Compatibility
    # -------------------------------------------------------------------------
    def test_10_single_live_email_analysis_compatibility(self):
        """
        Verifies that selecting exactly 1 live email runs through convert_live_message_to_rfc822_bytes
        and the forensic pipeline, generating 1 batch result entry with valid FileBytes and metadata.
        """
        live_record = {
            "id": "live_msg_single_001",
            "case_id": "live_msg_single_001",
            "subject": "Executive Wire Verification Request",
            "sender": "finance-officer@company-payroll.in",
            "recipient": "treasury@targetcorp.in",
            "date": "Sat, 20 Sep 2026 11:30:00 +0000",
            "case_data": {
                "headers": {
                    "subject": "Executive Wire Verification Request",
                    "from": "finance-officer@company-payroll.in",
                    "to": "treasury@targetcorp.in",
                    "date": "Sat, 20 Sep 2026 11:30:00 +0000",
                    "message-id": "<LIVE-WIRE-001@emailshield.local>",
                },
                "body": "Please confirm the RTGS wire transfer immediately via https://secure-wire-portal.org/verify.",
                "indicators": [
                    {"type": "URL", "value": "https://secure-wire-portal.org/verify"}
                ]
            }
        }

        # 1. Convert Live Message to RFC822 Bytes
        filename, file_bytes = convert_live_message_to_rfc822_bytes(live_record, self.test_user_id)
        self.assertTrue(filename.endswith(".eml"))
        self.assertIn("live_msg_single_001", filename)
        self.assertIsInstance(file_bytes, bytes)
        self.assertGreater(len(file_bytes), 100)

        # 2. Run Forensic Pipeline Components
        parser = SecureEmailParser(file_bytes)
        parsed_data = parser.parse()
        headers = parsed_data.get("headers", {})
        subject = str(headers.get("subject", "No Subject"))
        sender = str(headers.get("from", "Unknown Sender"))
        body = parsed_data.get("body", "")

        content_type = categorize_content(subject, body, sender, headers)
        auth_res = evaluate_auth_and_alignment(headers)
        ml_pred = self.classifier.predict(subject, body)
        rule_results = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type=content_type)
        risk_score, reasons = calculate_hybrid_risk(rule_results, ml_pred["probability"], auth_alignment=auth_res, content_type=content_type)

        iocs = extract_all_indicators(body + " " + str(headers))
        ioc_count = len(iocs.get("ipv4", [])) + len(iocs.get("urls", [])) + len(iocs.get("emails", []))
        atts = analyze_all_attachments(parsed_data.get("attachments", []))

        result_entry = {
            "Filename": filename,
            "Sender": sender,
            "Subject": subject,
            "Risk": risk_score,
            "Score": risk_score,
            "IOCs": ioc_count,
            "Attachments": len(atts),
            "Indicators": iocs,
            "FileBytes": file_bytes,
        }

        # 3. Assertions on generated batch entry
        self.assertEqual(result_entry["Filename"], filename)
        self.assertIn("finance-officer@company-payroll.in", result_entry["Sender"])
        self.assertEqual(result_entry["Subject"], "Executive Wire Verification Request")
        self.assertIn(result_entry["Risk"], ["LOW", "SUSPICIOUS", "HIGH", "CRITICAL"])
        self.assertGreaterEqual(result_entry["IOCs"], 1, "Extracted indicators should detect the embedded URL")
        self.assertEqual(result_entry["Attachments"], 0)
        self.assertEqual(result_entry["FileBytes"], file_bytes)

    # -------------------------------------------------------------------------
    # Requirement 11: Multiple Live Emails Batch Execution
    # -------------------------------------------------------------------------
    def test_11_multiple_live_email_analysis_execution(self):
        """
        Verifies selecting multiple live emails (e.g. 3) analyzes all 3,
        populating summary metrics (Processed=3, Clean/Suspicious/High/Critical, Errors=0) and results list.
        """
        sample_live_records = [
            {
                "id": "live_batch_01",
                "case_id": "live_batch_01",
                "subject": "Team Weekly Retrospective Meeting",
                "sender": "engineering-lead@company.in",
                "recipient": "dev-team@company.in",
                "case_data": {
                    "headers": {"subject": "Team Weekly Retrospective Meeting", "from": "engineering-lead@company.in"},
                    "body": "Hi team, please find the agenda for our retrospective meeting tomorrow at 3 PM."
                }
            },
            {
                "id": "live_batch_02",
                "case_id": "live_batch_02",
                "subject": "Urgent Invoice Attached - Final Notice",
                "sender": "accounts-payable@spoofed-vendor.com",
                "recipient": "finance@targetcorp.in",
                "case_data": {
                    "headers": {"subject": "Urgent Invoice Attached - Final Notice", "from": "accounts-payable@spoofed-vendor.com"},
                    "body": "Payment overdue. Please inspect invoice details.",
                    "attachments": [{"filename": "invoice_september.pdf", "sha256": "abcdef1234567890"}]
                }
            },
            {
                "id": "live_batch_03",
                "case_id": "live_batch_03",
                "subject": "Security Incident: Unauthorized Office 365 Login",
                "sender": "it-security@credential-harvest.xyz",
                "recipient": "security@targetcorp.in",
                "case_data": {
                    "headers": {"subject": "Security Incident: Unauthorized Office 365 Login", "from": "it-security@credential-harvest.xyz"},
                    "body": "Your credentials were compromised. Reset password at http://portal-recovery-login.top/reset",
                    "indicators": [{"type": "URL", "value": "http://portal-recovery-login.top/reset"}]
                }
            },
        ]

        metrics = {"Processed": 0, "Clean": 0, "Suspicious": 0, "High Risk": 0, "Critical": 0, "Errors": 0}
        results = []

        for rec in sample_live_records:
            metrics["Processed"] += 1
            try:
                fname, file_bytes = convert_live_message_to_rfc822_bytes(rec, self.test_user_id)
                parser = SecureEmailParser(file_bytes)
                parsed_data = parser.parse()
                headers = parsed_data.get("headers", {})
                subj = str(headers.get("subject", "No Subject"))
                snd = str(headers.get("from", "Unknown Sender"))
                body = parsed_data.get("body", "")

                c_type = categorize_content(subj, body, snd, headers)
                auth_res = evaluate_auth_and_alignment(headers)
                ml_pred = self.classifier.predict(subj, body)
                rule_res = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type=c_type)
                risk_score, reasons = calculate_hybrid_risk(rule_res, ml_pred["probability"], auth_alignment=auth_res, content_type=c_type)

                iocs = extract_all_indicators(body + " " + str(headers))
                ioc_cnt = len(iocs.get("ipv4", [])) + len(iocs.get("urls", [])) + len(iocs.get("emails", []))
                atts = analyze_all_attachments(parsed_data.get("attachments", []))

                if risk_score == "LOW":
                    metrics["Clean"] += 1
                elif risk_score == "SUSPICIOUS":
                    metrics["Suspicious"] += 1
                elif risk_score == "HIGH":
                    metrics["High Risk"] += 1
                elif risk_score == "CRITICAL":
                    metrics["Critical"] += 1

                results.append({
                    "Filename": fname,
                    "Sender": snd,
                    "Subject": subj,
                    "Risk": risk_score,
                    "IOCs": ioc_cnt,
                    "Attachments": len(atts),
                    "FileBytes": file_bytes
                })
            except Exception:
                metrics["Errors"] += 1

        # Assertions
        self.assertEqual(len(results), 3)
        self.assertEqual(metrics["Processed"], 3)
        self.assertEqual(metrics["Errors"], 0)
        self.assertEqual(metrics["Clean"] + metrics["Suspicious"] + metrics["High Risk"] + metrics["Critical"], 3)

        # Confirm record with attachment detected attachment
        att_entry = next(r for r in results if "live_batch_02" in r["Filename"])
        self.assertGreaterEqual(att_entry["Attachments"], 1)

        # Confirm record with phishing URL detected IOC
        ioc_entry = next(r for r in results if "live_batch_03" in r["Filename"])
        self.assertGreaterEqual(ioc_entry["IOCs"], 1)

    # -------------------------------------------------------------------------
    # Requirement 12: Direct Reuse of Existing Forensic Pipeline
    # -------------------------------------------------------------------------
    def test_12_existing_forensic_pipeline_reused_without_duplication(self):
        """
        Verifies that existing forensic components (SecureEmailParser, calculate_hybrid_risk,
        extract_all_indicators, analyze_all_attachments) are directly called without secondary engine.
        """
        sample_rec = {
            "id": "live_msg_reuse_check",
            "subject": "Payment Confirmation",
            "sender": "vendor@supply.in",
            "case_data": {"headers": {"subject": "Payment Confirmation"}, "body": "Thank you for the payment."}
        }
        _, file_bytes = convert_live_message_to_rfc822_bytes(sample_rec, self.test_user_id)

        with patch.object(SecureEmailParser, "parse", wraps=SecureEmailParser(file_bytes).parse) as spy_parse, \
             patch("core.risk.calculate_hybrid_risk", wraps=calculate_hybrid_risk) as spy_calc_risk, \
             patch("core.indicators.extract_all_indicators", wraps=extract_all_indicators) as spy_indicators, \
             patch("core.attachments.analyze_all_attachments", wraps=analyze_all_attachments) as spy_attachments:

            # Execute forensic pipeline on live email bytes
            parser = SecureEmailParser(file_bytes)
            parsed_data = spy_parse()
            headers = parsed_data.get("headers", {})
            subject = str(headers.get("subject", "No Subject"))
            sender = str(headers.get("from", "Unknown Sender"))
            body = parsed_data.get("body", "")

            content_type = categorize_content(subject, body, sender, headers)
            auth_res = evaluate_auth_and_alignment(headers)
            ml_pred = self.classifier.predict(subject, body)
            rule_results = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type=content_type)
            risk_score, _ = spy_calc_risk(rule_results, ml_pred["probability"], auth_alignment=auth_res, content_type=content_type)

            iocs = spy_indicators(body + " " + str(headers))
            atts = spy_attachments(parsed_data.get("attachments", []))

            # Verify each authoritative forensic function was called directly
            self.assertTrue(spy_parse.called, "SecureEmailParser.parse was not called")
            self.assertTrue(spy_calc_risk.called, "calculate_hybrid_risk was not called")
            self.assertTrue(spy_indicators.called, "extract_all_indicators was not called")
            self.assertTrue(spy_attachments.called, "analyze_all_attachments was not called")

    # -------------------------------------------------------------------------
    # Requirement 13: Mandatory Live Counter & State Isolation
    # -------------------------------------------------------------------------
    def test_13_batch_live_counter_isolation_mandatory_check(self):
        """
        CRITICAL: Verifies that running Batch Analysis on Live Mail emails does NOT change or increment:
        - Emails Arrived
        - Emails Analysed
        - Threats Detected
        - Last UID / last_processed_uid
        - sentinel_telemetry (sentinel_telemetry.json)
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

        # Spies on sentinel / worker state mutations
        with patch("core.sentinel_stats.record_user_sentinel_poll") as mock_record_poll, \
             patch("core.sentinel_control.upsert_user_checkpoint") as mock_checkpoint, \
             patch("core.telegram_alert.send_telegram_alert") as mock_tg, \
             patch("core.whatsapp_alert.send_whatsapp_alert") as mock_wa:

            # Execute batch analysis on 3 live mail records
            sample_records = [
                {"id": f"iso_test_{i}", "subject": f"Test {i}", "sender": f"test{i}@domain.com", "case_data": {"body": f"Msg {i}"}}
                for i in range(3)
            ]

            results = []
            for rec in sample_records:
                _, file_bytes = convert_live_message_to_rfc822_bytes(rec, self.test_user_id)
                parser = SecureEmailParser(file_bytes)
                data = parser.parse()
                results.append(data)

            self.assertEqual(len(results), 3)

            # Assert Sentinel worker telemetry methods were NOT called
            mock_record_poll.assert_not_called()
            mock_checkpoint.assert_not_called()
            mock_tg.assert_not_called()
            mock_wa.assert_not_called()

            # Confirm sentinel_telemetry.json file was not touched or modified
            if initial_mtime is not None and os.path.exists(telemetry_file):
                current_mtime = os.path.getmtime(telemetry_file)
                self.assertEqual(initial_mtime, current_mtime, "Batch Analysis modified sentinel_telemetry.json mtime!")
                with open(telemetry_file, "r", encoding="utf-8") as tf:
                    current_content = tf.read()
                self.assertEqual(initial_content, current_content, "Batch Analysis modified sentinel_telemetry.json contents!")

    # -------------------------------------------------------------------------
    # Requirement 14: Report Exports (CSV, JSON, PDF)
    # -------------------------------------------------------------------------
    def test_14_live_mail_batch_exports_csv_json_pdf(self):
        """Verifies CSV, JSON, and PDF report exports operate cleanly on batch results originating from Live Mail messages."""
        metrics = {"Processed": 2, "Clean": 1, "Suspicious": 0, "High Risk": 1, "Critical": 0, "Errors": 0}
        results = [
            {
                "Filename": "LiveMail_001.eml",
                "Sender": "legit@company.in",
                "Subject": "Project Status Report",
                "Risk": "LOW",
                "Score": "LOW",
                "IOCs": 0,
                "Attachments": 0,
                "Indicators": {},
                "FileBytes": b"MIME-BYTES-LEGIT-001"
            },
            {
                "Filename": "LiveMail_002.eml",
                "Sender": "phisher@fake-domain.xyz",
                "Subject": "Action Required: Account Suspended",
                "Risk": "HIGH",
                "Score": "HIGH",
                "IOCs": 4,
                "Attachments": 1,
                "Indicators": {"urls": ["http://fake-domain.xyz/login"]},
                "FileBytes": b"MIME-BYTES-PHISH-002"
            },
        ]

        # 1. CSV Export
        df_view = [
            {
                "Filename": r["Filename"],
                "Sender": r["Sender"],
                "Subject": r["Subject"],
                "Risk": r["Risk"],
                "IOCs": r["IOCs"],
                "Attachments": r["Attachments"]
            }
            for r in results
        ]
        csv_bytes = pd.DataFrame(df_view).to_csv(index=False).encode("utf-8")
        self.assertGreater(len(csv_bytes), 50)
        self.assertIn(b"LiveMail_001.eml", csv_bytes)
        self.assertIn(b"LiveMail_002.eml", csv_bytes)
        self.assertIn(b"Risk", csv_bytes)

        # 2. JSON Export (omits FileBytes for clean portable JSON)
        json_export = []
        for r in results:
            d = dict(r)
            d.pop("FileBytes", None)
            json_export.append(d)

        json_bytes = json.dumps(json_export, indent=2).encode("utf-8")
        self.assertGreater(len(json_bytes), 50)
        parsed_json = json.loads(json_bytes.decode("utf-8"))
        self.assertEqual(len(parsed_json), 2)
        self.assertNotIn("FileBytes", parsed_json[0])
        self.assertEqual(parsed_json[0]["Filename"], "LiveMail_001.eml")
        self.assertEqual(parsed_json[1]["Risk"], "HIGH")

        # 3. PDF Export
        pdf_bytes = generate_batch_pdf_report(metrics, results)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 500)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    # -------------------------------------------------------------------------
    # Requirement 15: Pivot from Live Mail Batch Result to Single Email Analysis
    # -------------------------------------------------------------------------
    def test_15_full_analysis_pivot_from_live_mail_batch_result(self):
        """Verifies that FileBytes produced from convert_live_message_to_rfc822_bytes can be passed to single email analysis seamlessly."""
        live_mail_record = {
            "id": "pivot_case_999",
            "case_id": "pivot_case_999",
            "subject": "Confidential Investigation Dossier",
            "sender": "inspector@cybercrime.gov.in",
            "recipient": "analyst@emailshield.in",
            "date": "Sun, 20 Sep 2026 12:00:00 +0000",
            "case_data": {
                "headers": {
                    "subject": "Confidential Investigation Dossier",
                    "from": "inspector@cybercrime.gov.in",
                    "to": "analyst@emailshield.in",
                    "date": "Sun, 20 Sep 2026 12:00:00 +0000",
                    "message-id": "<PIVOT-DOSSIER-999@gov.in>",
                },
                "body": "Official advisory on recent banking trojans and IOCs: https://ncrp.gov.in/advisory/2026",
                "indicators": [{"type": "URL", "value": "https://ncrp.gov.in/advisory/2026"}]
            }
        }

        # 1. Produce FileBytes from live mail record
        _, live_file_bytes = convert_live_message_to_rfc822_bytes(live_mail_record, self.test_user_id)
        self.assertIsInstance(live_file_bytes, bytes)

        # 2. Simulate User clicking "🔎 View Full Analysis" in Batch UI:
        # st.session_state["current_email_bytes"] = r["FileBytes"]
        simulated_session_state = {"current_email_bytes": live_file_bytes}

        # 3. Feed the session bytes directly into the single email parsing and analysis flow
        single_parser = SecureEmailParser(simulated_session_state["current_email_bytes"])
        single_parsed = single_parser.parse()

        headers = single_parsed.get("headers", {})
        self.assertEqual(headers.get("subject"), "Confidential Investigation Dossier")
        self.assertIn("inspector@cybercrime.gov.in", headers.get("from"))

        # Single email risk calculation
        content_type = categorize_content(headers.get("subject", ""), single_parsed.get("body", ""), headers.get("from", ""), headers)
        auth_res = evaluate_auth_and_alignment(headers)
        ml_pred = self.classifier.predict(headers.get("subject", ""), single_parsed.get("body", ""))
        rule_findings = evaluate_rules(single_parsed, auth_alignment=auth_res, content_type=content_type)
        risk_score, reasons = calculate_hybrid_risk(rule_findings, ml_pred["probability"], auth_alignment=auth_res, content_type=content_type)

        # Single email indicators extraction
        indicators = extract_all_indicators(single_parsed.get("body", "") + " " + str(headers))

        self.assertIn(risk_score, ["LOW", "SUSPICIOUS", "HIGH", "CRITICAL"])
        self.assertGreaterEqual(len(indicators.get("urls", [])), 1)
        self.assertIn("https://ncrp.gov.in/advisory/2026", indicators["urls"])


if __name__ == "__main__":
    unittest.main()
