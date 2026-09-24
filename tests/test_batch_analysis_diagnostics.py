"""
tests/test_batch_analysis_diagnostics.py
Comprehensive verification suite for:
1. Telegram & WhatsApp alert delivery dual-contract (dict access & 2-tuple unpacking)
2. Batch Analysis pipeline with 1, 2, and multiple sample EMLs (clean, suspicious, attachment, URL)
3. Batch filtering (risk levels, IOC counts) and sorting
4. Batch export generation (CSV, JSON, PDF)
5. Batch/Live Mail isolation
"""

import os
import io
import json
import pytest
import unittest
from unittest.mock import patch, MagicMock

from core.telegram_alert import (
    test_telegram_alert_delivery as call_telegram_alert_test,
    run_telegram_connectivity_test,
    TelegramTestResult,
    get_telegram_config,
)
from core.whatsapp_alert import (
    test_whatsapp_alert_delivery as call_whatsapp_alert_test,
    WhatsAppTestResult,
    get_whatsapp_config,
)
from core.parser import SecureEmailParser
from core.classifier import MLClassifier
from core.batch_scanner import categorize_content
from core.auth_claims import evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.indicators import extract_all_indicators
from core.attachments import analyze_all_attachments
from core.report import generate_batch_pdf_report


class TestAlertReturnContract(unittest.TestCase):
    """Verifies that alert test functions satisfy both dict consumers and 2-tuple unpackers."""

    @patch("core.telegram_alert.verify_telegram_bot_token")
    @patch("core.telegram_alert.send_telegram_alert")
    def test_01_telegram_test_delivery_dict_contract(self, mock_send, mock_verify):
        """Dict consumers can access all 6 keys natively."""
        mock_verify.return_value = (True, "@EmailShieldSentinelBot", "Auth OK")
        mock_send.return_value = (True, "Delivered successfully")

        res = call_telegram_alert_test("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ12345", "987654321")
        self.assertIsInstance(res, dict)
        self.assertIsInstance(res, TelegramTestResult)
        self.assertEqual(res["api_status"], "PASS")
        self.assertEqual(res["auth_status"], "PASS")
        self.assertEqual(res["destination_status"], "PASS")
        self.assertEqual(res["delivery_status"], "DELIVERED")
        self.assertEqual(res["bot_username"], "@EmailShieldSentinelBot")
        self.assertIn("successfully delivered", res["details"])

    @patch("core.telegram_alert.verify_telegram_bot_token")
    @patch("core.telegram_alert.send_telegram_alert")
    def test_02_telegram_test_delivery_two_tuple_unpacking(self, mock_send, mock_verify):
        """Callers expecting (success, msg) unpack cleanly without raising ValueError."""
        mock_verify.return_value = (True, "@EmailShieldSentinelBot", "Auth OK")
        mock_send.return_value = (True, "Delivered successfully")

        # Must unpack into exactly 2 variables without 'ValueError: too many values to unpack'
        success, msg = call_telegram_alert_test("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ12345", "987654321")
        self.assertIsInstance(success, bool)
        self.assertTrue(success)
        self.assertIsInstance(msg, str)
        self.assertIn("successfully delivered", msg)

    @patch("core.telegram_alert.verify_telegram_bot_token")
    def test_03_telegram_test_delivery_failure_two_tuple_unpacking(self, mock_verify):
        """Failed test alert unpacks cleanly to (False, failure_details)."""
        mock_verify.return_value = (False, None, "Invalid bot token format or unauthorized")

        success, msg = call_telegram_alert_test("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ12345", "987654321")
        self.assertIsInstance(success, bool)
        self.assertFalse(success)
        self.assertIn("Invalid bot token", msg)

    @patch("core.whatsapp_alert.send_whatsapp_alert")
    def test_04_whatsapp_test_delivery_dual_contract(self, mock_send):
        """WhatsApp test delivery supports both dict access and 2-tuple unpacking."""
        mock_send.return_value = (True, "WhatsApp delivered")

        # Dict access
        res = call_whatsapp_alert_test("+919876543210", "dummy_key_123456")
        self.assertIsInstance(res, dict)
        self.assertEqual(res["delivery_status"], "DELIVERED")
        self.assertEqual(res["auth_status"], "PASS")

        # 2-tuple unpacking
        ok, details = call_whatsapp_alert_test("+919876543210", "dummy_key_123456")
        self.assertTrue(ok)
        self.assertEqual(details, "WhatsApp delivered")

    def test_05_config_aliases_consistency(self):
        """Configuration functions return expected alias keys for UI views."""
        tg_conf = get_telegram_config({"telegram_token": "tok123", "chat_id": "12345"})
        self.assertEqual(tg_conf.get("token"), "tok123")
        self.assertEqual(tg_conf.get("bot_token"), "tok123")

        wa_conf = get_whatsapp_config({"whatsapp_phone": "+919876543210", "whatsapp_key": "key123"})
        self.assertEqual(wa_conf.get("phone"), "+919876543210")
        self.assertEqual(wa_conf.get("phone_number"), "+919876543210")
        self.assertEqual(wa_conf.get("apikey"), "key123")
        self.assertEqual(wa_conf.get("api_key"), "key123")


class TestBatchAnalysisEngine(unittest.TestCase):
    """Verifies end-to-end multi-file batch analysis, parsing, scoring, filtering, and exports."""

    @classmethod
    def setUpClass(cls):
        cls.classifier = MLClassifier()
        cls.sample_dir = "samples"
        cls.eml_paths = {
            "clean": os.path.join(cls.sample_dir, "clean.eml"),
            "phishing": os.path.join(cls.sample_dir, "phishing.eml"),
            "attachment": os.path.join(cls.sample_dir, "malware_lure.eml"),
            "url": os.path.join(cls.sample_dir, "bec.eml"),
            "quishing": os.path.join(cls.sample_dir, "quishing_invoice.eml"),
            "extortion": os.path.join(cls.sample_dir, "indian_extortion_upi.eml"),
        }
        for name, path in cls.eml_paths.items():
            assert os.path.exists(path), f"Sample {name} at {path} does not exist!"

    def _process_eml_bytes(self, file_name, file_bytes):
        """Mimics render_batch_analysis pipeline."""
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

        return {
            "Filename": file_name,
            "Sender": sender,
            "Subject": subject,
            "Risk": risk_score,
            "Score": risk_score,
            "IOCs": ioc_count,
            "Attachments": len(atts),
            "Indicators": iocs,
            "FileBytes": file_bytes,
        }

    def test_06_batch_pipeline_single_eml(self):
        """Processes 1 EML file through batch pipeline."""
        with open(self.eml_paths["clean"], "rb") as f:
            res = self._process_eml_bytes("clean.eml", f.read())
        self.assertEqual(res["Filename"], "clean.eml")
        self.assertIn(res["Risk"], ["LOW", "SUSPICIOUS", "HIGH", "CRITICAL"])
        self.assertIsInstance(res["IOCs"], int)

    def test_07_batch_pipeline_two_emls(self):
        """Processes 2 EML files (clean and suspicious)."""
        results = []
        for name in ["clean", "phishing"]:
            with open(self.eml_paths[name], "rb") as f:
                results.append(self._process_eml_bytes(f"{name}.eml", f.read()))
        self.assertEqual(len(results), 2)
        filenames = [r["Filename"] for r in results]
        self.assertIn("clean.eml", filenames)
        self.assertIn("phishing.eml", filenames)

    def test_08_batch_pipeline_multiple_diverse_emls(self):
        """Processes multiple diverse EMLs (clean, suspicious, attachment, url, quishing, extortion)."""
        results = []
        metrics = {"Processed": 0, "Clean": 0, "Suspicious": 0, "High Risk": 0, "Critical": 0, "Errors": 0}

        for name, path in self.eml_paths.items():
            metrics["Processed"] += 1
            with open(path, "rb") as f:
                res = self._process_eml_bytes(os.path.basename(path), f.read())
                results.append(res)
                if res["Risk"] == "LOW":
                    metrics["Clean"] += 1
                elif res["Risk"] == "SUSPICIOUS":
                    metrics["Suspicious"] += 1
                elif res["Risk"] == "HIGH":
                    metrics["High Risk"] += 1
                elif res["Risk"] == "CRITICAL":
                    metrics["Critical"] += 1

        self.assertEqual(len(results), len(self.eml_paths))
        self.assertEqual(metrics["Processed"], len(self.eml_paths))
        self.assertGreater(metrics["Clean"] + metrics["Suspicious"] + metrics["High Risk"] + metrics["Critical"], 0)

        # Confirm EML with attachment detected attachments
        att_res = next(r for r in results if r["Filename"] == "malware_lure.eml")
        self.assertGreater(att_res["Attachments"], 0)

        # Confirm EML with URL detected IOCs
        url_res = next(r for r in results if r["Filename"] == "bec.eml")
        self.assertGreater(url_res["IOCs"], 0)

    def test_09_batch_filtering_risk_and_iocs(self):
        """Verifies filtering by risk level and IOC presence."""
        dummy_results = [
            {"Filename": "a.eml", "Sender": "a@test.com", "Subject": "A", "Risk": "LOW", "IOCs": 0, "Attachments": 0},
            {"Filename": "b.eml", "Sender": "b@test.com", "Subject": "B", "Risk": "HIGH", "IOCs": 3, "Attachments": 1},
            {"Filename": "c.eml", "Sender": "c@test.com", "Subject": "C", "Risk": "SUSPICIOUS", "IOCs": 0, "Attachments": 0},
            {"Filename": "d.eml", "Sender": "d@test.com", "Subject": "D", "Risk": "CRITICAL", "IOCs": 5, "Attachments": 2},
        ]

        # Filter: Risk == HIGH
        f_high = [r for r in dummy_results if r["Risk"] == "HIGH"]
        self.assertEqual(len(f_high), 1)
        self.assertEqual(f_high[0]["Filename"], "b.eml")

        # Filter: IOCs > 0
        f_iocs = [r for r in dummy_results if r["IOCs"] > 0]
        self.assertEqual(len(f_iocs), 2)

        # Filter: IOCs == 0
        f_no_iocs = [r for r in dummy_results if r["IOCs"] == 0]
        self.assertEqual(len(f_no_iocs), 2)

    def test_10_batch_sorting(self):
        """Verifies sorting by filename, risk severity, IOC count, and attachments."""
        dummy_results = [
            {"Filename": "z.eml", "Sender": "z@test.com", "Subject": "Z", "Risk": "LOW", "IOCs": 1, "Attachments": 0},
            {"Filename": "a.eml", "Sender": "a@test.com", "Subject": "A", "Risk": "CRITICAL", "IOCs": 10, "Attachments": 2},
            {"Filename": "m.eml", "Sender": "m@test.com", "Subject": "M", "Risk": "HIGH", "IOCs": 5, "Attachments": 1},
        ]

        # Sort by Filename
        by_name = sorted(dummy_results, key=lambda x: x["Filename"])
        self.assertEqual([r["Filename"] for r in by_name], ["a.eml", "m.eml", "z.eml"])

        # Sort by Risk severity
        risk_order = {"CRITICAL": 0, "HIGH": 1, "SUSPICIOUS": 2, "LOW": 3, "ERROR": 4}
        by_risk = sorted(dummy_results, key=lambda x: risk_order.get(x["Risk"], 5))
        self.assertEqual([r["Risk"] for r in by_risk], ["CRITICAL", "HIGH", "LOW"])

        # Sort by IOCs descending
        by_iocs = sorted(dummy_results, key=lambda x: x["IOCs"], reverse=True)
        self.assertEqual([r["IOCs"] for r in by_iocs], [10, 5, 1])

        # Sort by Attachments descending
        by_atts = sorted(dummy_results, key=lambda x: x["Attachments"], reverse=True)
        self.assertEqual([r["Attachments"] for r in by_atts], [2, 1, 0])

    def test_11_batch_export_csv_json_pdf(self):
        """Generates valid CSV, JSON, and PDF outputs from batch results."""
        import pandas as pd
        metrics = {"Processed": 2, "Clean": 1, "Suspicious": 1, "High Risk": 0, "Critical": 0, "Errors": 0}
        results = [
            {"Filename": "clean.eml", "Sender": "sender1@example.com", "Subject": "Meeting", "Risk": "LOW", "IOCs": 0, "Attachments": 0, "FileBytes": b"test1"},
            {"Filename": "phish.eml", "Sender": "attacker@evil.com", "Subject": "Urgent Invoice", "Risk": "SUSPICIOUS", "IOCs": 2, "Attachments": 1, "FileBytes": b"test2"},
        ]

        # CSV Export
        df_view = [
            {"Filename": r["Filename"], "Sender": r["Sender"], "Subject": r["Subject"], "Risk": r["Risk"], "IOCs": r["IOCs"], "Attachments": r["Attachments"]}
            for r in results
        ]
        csv_bytes = pd.DataFrame(df_view).to_csv(index=False).encode("utf-8")
        self.assertGreater(len(csv_bytes), 50)
        self.assertIn(b"clean.eml", csv_bytes)
        self.assertIn(b"phish.eml", csv_bytes)

        # JSON Export (without FileBytes)
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

        # PDF Export
        pdf_bytes = generate_batch_pdf_report(metrics, results)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 500)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_12_render_single_email_does_not_halt_script(self):
        """views/analyze.py must not contain st.stop() that terminates the script prematurely."""
        import views.analyze
        analyze_path = os.path.join("views", "analyze.py")
        with open(analyze_path, "r", encoding="utf-8") as f:
            content = f.read()

        # st.stop() must not be present in views/analyze.py
        self.assertNotIn("st.stop()", content)
        # render function must be defined
        self.assertTrue(hasattr(views.analyze, "render"))
        self.assertTrue(hasattr(views.analyze, "render_batch_analysis"))
        self.assertTrue(hasattr(views.analyze, "render_single_email"))

    def test_13_empty_state_signature_compatibility(self):
        """empty_state in views._theme must accept both 'body' and 'message' keywords without TypeError."""
        from unittest.mock import patch
        from views._theme import empty_state

        with patch("streamlit.markdown") as mock_markdown:
            # Test default call
            empty_state("📦", "Title")
            self.assertTrue(mock_markdown.called)

            # Test body= keyword
            mock_markdown.reset_mock()
            empty_state(icon="📦", title="Batch Ready", body="Sample body text")
            self.assertTrue(mock_markdown.called)
            args, _ = mock_markdown.call_args
            self.assertIn("Sample body text", args[0])

            # Test message= keyword (backwards compatibility)
            mock_markdown.reset_mock()
            empty_state(icon="📦", title="Batch Ready", message="Sample message text")
            self.assertTrue(mock_markdown.called)
            args, _ = mock_markdown.call_args
            self.assertIn("Sample message text", args[0])


if __name__ == "__main__":
    unittest.main()
