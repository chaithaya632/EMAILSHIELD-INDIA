"""
tests/test_live_mail_vertical_list.py
Comprehensive test suite verifying the vertical email cards list, deduplication,
selection tracking, dynamic risk badge updates, and session clearing.
"""

import unittest
from unittest.mock import patch, MagicMock
import html
import uuid

import views.analyze as analyze_view
import core.live_mail_adapter as live_adapter
import app as main_app


class TestLiveMailVerticalList(unittest.TestCase):
    def setUp(self):
        self.test_user_id = str(uuid.uuid4())
        self.mock_client = MagicMock()
        self.mock_client.auth.uid.return_value = self.test_user_id
        self.active_mb = {"id": "mb_test_01", "is_active": True, "email_address": "analyst@emailshield.in"}

    def test_01_adapter_deduplication_and_unverified_risk(self):
        """Verify core/live_mail_adapter deduplicates by id/case_id and sets 'Not analyzed' for unverified cases."""
        cases = [
            {"id": "uid_1", "case_id": "case_1", "subject": "Duplicate 1", "risk_score": None, "user_id": self.test_user_id},
            {"id": "uid_1", "case_id": "case_1", "subject": "Duplicate 1 Again", "risk_score": None, "user_id": self.test_user_id},
            {"id": "uid_2", "case_id": "case_2", "subject": "Closed High Threat", "risk_score": "HIGH", "status": "Closed", "user_id": self.test_user_id},
            {"id": "uid_3", "case_id": "case_3", "subject": "Open High Threat", "risk_score": "HIGH", "status": "Open", "user_id": self.test_user_id},
            {"id": "uid_4", "case_id": "case_4", "subject": "Critical Threat", "threat_verdict": "CRITICAL", "user_id": self.test_user_id},
            {"id": "uid_5", "case_id": "case_5", "subject": "Safe Email", "risk_score": "LOW", "user_id": self.test_user_id},
        ]

        with patch("core.live_mail_adapter.is_authorized_caller", return_value=True), \
             patch("core.live_mail_adapter.get_all_cases", return_value=cases), \
             patch("core.live_mail_adapter.get_local_storage_manager") as mock_lsm:
            mock_mgr = MagicMock()
            mock_mgr.list_cases.return_value = []
            mock_lsm.return_value = mock_mgr

            messages = live_adapter.get_authorized_live_mail_messages(self.test_user_id, self.mock_client)

            # Deduplication: uid_1 should appear only once
            uids = [m["id"] for m in messages]
            self.assertEqual(len(uids), len(set(uids)), "Messages must be deduplicated by id/case_id")
            self.assertEqual(len(messages), 5)

            # Risk checks
            msg_map = {m["id"]: m["risk"] for m in messages}
            self.assertEqual(msg_map["uid_1"], "Not analyzed")
            self.assertEqual(msg_map["uid_2"], "Not analyzed", "Closed high threat must be 'Not analyzed'")
            self.assertEqual(msg_map["uid_3"], "HIGH", "Open high threat must be 'HIGH'")
            self.assertEqual(msg_map["uid_4"], "CRITICAL")
            self.assertEqual(msg_map["uid_5"], "SAFE")

    def test_02_views_analyze_deduplication_and_no_pagination(self):
        """Verify views/analyze deduplicates messages by UID and has NO pagination controls or scroll containers."""
        messages_with_dups = [
            {"id": "dup_uid", "case_id": "c1", "subject": "Subj 1", "sender": "s1@corp.in"},
            {"id": "dup_uid", "case_id": "c1", "subject": "Subj 1 dup", "sender": "s1@corp.in"},
            {"id": "unique_uid", "case_id": "c2", "subject": "Subj 2", "sender": "s2@corp.in"},
        ]

        state = {"email_analysis_source": "📬 Select from Live Mail"}
        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=messages_with_dups), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)

            # Check that header shows 2 loaded (deduped from 3)
            md_texts = [call[0][0] for call in mock_md.call_args_list if call[0]]
            inbox_headers = [t for t in md_texts if "Inbox Messages (2 loaded)" in t]
            self.assertTrue(len(inbox_headers) > 0, "Deduplication must result in 2 loaded messages")

            # Verify NO pagination controls exist
            btn_labels = [call[0][0] for call in mock_btn.call_args_list if call[0]]
            self.assertNotIn("← Previous", btn_labels)
            self.assertNotIn("Next →", btn_labels)

            # Check that no pagination text is rendered
            pagination_texts = [t for t in md_texts if "Showing emails" in t or "Page 1 of" in t or "Page 2 of" in t]
            self.assertEqual(len(pagination_texts), 0, "No pagination text should be rendered")

    def test_03_selection_tracking_and_action_card(self):
        """Verify dedicated selected email action card renders and tracks selected_live_mail_uid."""
        messages = [
            {"id": "msg_alpha", "case_id": "c_alpha", "subject": "Alpha Subject", "sender": "alpha@sec.in"},
            {"id": "msg_beta", "case_id": "c_beta", "subject": "Beta Subject", "sender": "beta@sec.in"},
        ]

        state = {
            "email_analysis_source": "📬 Select from Live Mail",
            "selected_live_mail_uid": "msg_beta"
        }

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.page_header"), \
             patch("views.analyze.st.radio", return_value="📬 Select from Live Mail"), \
             patch("views.analyze.is_authorized_caller", return_value=True), \
             patch("views.analyze.get_user_mailbox", return_value=self.active_mb), \
             patch("views.analyze.get_authorized_live_mail_messages", return_value=messages), \
             patch("views.analyze.st.button", return_value=False) as mock_btn, \
             patch("views.analyze.st.markdown") as mock_md:

            analyze_view.render(self.test_user_id, self.mock_client)

            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_uid"), "msg_beta")
            self.assertEqual(analyze_view.st.session_state.get("selected_live_mail_index"), 1)

            # Verify action card rendered for beta
            md_texts = [call[0][0] for call in mock_md.call_args_list if call[0]]
            selected_cards = [t for t in md_texts if "Currently Selected Email" in t and "Beta Subject" in t]
            self.assertTrue(len(selected_cards) > 0, "Action card must display Beta Subject")

    def test_04_dynamic_risk_badge_and_forensic_results_update(self):
        """Verify dynamic risk badge reflects live_mail_analysis_status and gets updated on forensic completion."""
        # 1. Verify status updating in render_forensic_results
        state = {
            "selected_live_mail_uid": "msg_analyzed_123",
            "live_mail_analysis_status": {}
        }
        mock_agent_out = {
            "normalization_data": {},
            "domain_rep": None,
            "url_analyses": [],
            "rule_findings": [],
            "risk_score": "LOW",
            "reasons": ["Clean message"],
            "ml_pred": {
                "probability": 0.05,
                "assessment": "Benign / Ham",
                "features_used": ["test_feature"],
                "confidence_level": "HIGH CONFIDENCE",
            },
            "briefing": "All checks passed",
            "agent_steps": []
        }
        mock_agent = MagicMock()
        mock_agent.run_investigation.return_value = mock_agent_out

        sample_bytes = (
            b"From: safe-sender@corp.in\r\n"
            b"To: analyst@emailshield.in\r\n"
            b"Subject: Clean Newsletter\r\n\r\n"
            b"Hello, here is your daily news.\r\n"
        )

        with patch.dict(analyze_view.st.session_state, state, clear=True), \
             patch("views.analyze.get_case_record", return_value=None), \
             patch("views.analyze.save_case"), \
             patch("views.analyze.st.tabs", return_value=[MagicMock() for _ in range(8)]):

            analyze_view.render_forensic_results(sample_bytes, self.test_user_id, self.mock_client, forensic_agent=mock_agent)

            # Must update status to 'SAFE' for LOW risk score
            updated_status = analyze_view.st.session_state.get("live_mail_analysis_status", {})
            self.assertEqual(updated_status.get("msg_analyzed_123"), "SAFE")

    def test_05_app_session_clear_purges_live_mail_keys(self):
        """Verify clear_investigator_session in app.py purges all live mail keys."""
        state = {
            "selected_live_mail_uid": "uid_99",
            "selected_live_mail_message_id": "<msg@99>",
            "selected_live_mail_index": 3,
            "live_mail_analysis_status": {"uid_99": "SAFE"},
            "current_live_mail_index": 3,
            "live_jump_num": 4,
            "user_id": self.test_user_id,
        }

        with patch.dict(main_app.st.session_state, state, clear=True):
            main_app.clear_investigator_session()
            for key in [
                "selected_live_mail_uid",
                "selected_live_mail_message_id",
                "selected_live_mail_index",
                "live_mail_analysis_status",
                "current_live_mail_index",
                "live_jump_num",
            ]:
                self.assertNotIn(key, main_app.st.session_state, f"{key} must be purged on session clear")


if __name__ == "__main__":
    unittest.main()
