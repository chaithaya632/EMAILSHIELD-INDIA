"""
tests/test_telegram_alerts.py
Comprehensive Security and Functional Test Suite for Telegram Alerting in EMAILSHIELD INDIA.
Verifies configuration resolution, sanitization, token secrecy, API mocking, and Sentinel integration.
"""

import os
import unittest
from unittest.mock import patch, MagicMock
import requests

from core.telegram_alert import (
    sanitize_telegram_token,
    validate_telegram_token_format,
    validate_telegram_chat_id,
    get_telegram_config,
    verify_telegram_bot_token,
    send_telegram_alert,
    run_telegram_connectivity_test,
)
from core.sentinel import (
    format_threat_alert_text,
    mask_sensitive_subject,
    send_test_alert,
)


DUMMY_VALID_TOKEN = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
DUMMY_CHAT_ID = "987654321"


class TestTelegramConfiguration(unittest.TestCase):
    """Verifies Telegram configuration parsing, validation, and precedence."""

    def test_01_token_format_validation(self):
        """Validates token format regex."""
        self.assertTrue(validate_telegram_token_format(DUMMY_VALID_TOKEN))
        self.assertTrue(validate_telegram_token_format("987654321:abcdefghijklmnopqrstuvwxyz012345678"))
        
        # Invalid tokens
        self.assertFalse(validate_telegram_token_format(None))
        self.assertFalse(validate_telegram_token_format(""))
        self.assertFalse(validate_telegram_token_format("not_a_token"))
        self.assertFalse(validate_telegram_token_format("12345:short"))
        self.assertFalse(validate_telegram_token_format("1234567890"))

    def test_02_chat_id_validation(self):
        """Validates destination chat ID syntax."""
        # Valid numeric IDs
        self.assertTrue(validate_telegram_chat_id("123456789")[0])
        self.assertTrue(validate_telegram_chat_id("-1001234567890")[0])
        self.assertTrue(validate_telegram_chat_id(987654321)[0])
        
        # Valid channel handle
        self.assertTrue(validate_telegram_chat_id("@EmailShieldAlerts")[0])

        # Invalid chat IDs
        self.assertFalse(validate_telegram_chat_id("")[0])
        self.assertFalse(validate_telegram_chat_id(None)[0])
        self.assertFalse(validate_telegram_chat_id("abc")[0])
        self.assertFalse(validate_telegram_chat_id("not a chat id")[0])

    def test_03_config_resolution_precedence(self):
        """Tests configuration resolution hierarchy from env, secrets, and overrides."""
        # 1. Empty environment
        with patch.dict(os.environ, {}, clear=True):
            cfg = get_telegram_config({})
            self.assertFalse(cfg["is_token_configured"])
            self.assertFalse(cfg["is_destination_configured"])
            self.assertFalse(cfg["is_enabled"])

        # 2. Configured via environment variables
        env_mock = {
            "TELEGRAM_BOT_TOKEN": DUMMY_VALID_TOKEN,
            "TELEGRAM_CHAT_ID": DUMMY_CHAT_ID
        }
        with patch.dict(os.environ, env_mock, clear=True):
            cfg = get_telegram_config({"is_enabled": True})
            self.assertTrue(cfg["is_token_configured"])
            self.assertTrue(cfg["is_destination_configured"])
            self.assertTrue(cfg["is_enabled"])
            self.assertEqual(cfg["token"], DUMMY_VALID_TOKEN)
            self.assertEqual(cfg["chat_id"], DUMMY_CHAT_ID)

        # 3. Explicit overrides take precedence
        with patch.dict(os.environ, env_mock, clear=True):
            override_token = "9999999999:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
            override_chat = "111222333"
            cfg_over = get_telegram_config({
                "telegram_token": override_token,
                "telegram_chat_id": override_chat,
                "is_enabled": False
            })
            self.assertEqual(cfg_over["token"], override_token)
            self.assertEqual(cfg_over["chat_id"], override_chat)
            self.assertFalse(cfg_over["is_enabled"])


class TestTelegramSecurity(unittest.TestCase):
    """Verifies that secrets are never leaked in strings, URLs, or error messages."""

    def test_04_token_sanitization_in_plain_text(self):
        """Confirms that raw tokens are scrubbed by sanitize_telegram_token."""
        raw_msg = f"Failed to connect to Telegram with token {DUMMY_VALID_TOKEN} for user 123."
        sanitized = sanitize_telegram_token(raw_msg, DUMMY_VALID_TOKEN)
        self.assertNotIn(DUMMY_VALID_TOKEN, sanitized)
        self.assertIn("[REDACTED_BOT_TOKEN]", sanitized)

    def test_05_url_token_sanitization(self):
        """Confirms that URLs containing /bot<token>/ are scrubbed."""
        raw_url = f"https://api.telegram.org/bot{DUMMY_VALID_TOKEN}/sendMessage?chat_id=123"
        sanitized = sanitize_telegram_token(raw_url, DUMMY_VALID_TOKEN)
        self.assertNotIn(DUMMY_VALID_TOKEN, sanitized)
        self.assertIn("api.telegram.org/bot[REDACTED_BOT_TOKEN]", sanitized)

    def test_06_error_handling_does_not_leak_token(self):
        """Verify network exceptions containing the URL do not leak the token."""
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError(
                f"Failed to establish a connection to https://api.telegram.org/bot{DUMMY_VALID_TOKEN}/sendMessage"
            )
            ok, msg = send_telegram_alert(DUMMY_VALID_TOKEN, DUMMY_CHAT_ID, "Test Message")
            self.assertFalse(ok)
            self.assertNotIn(DUMMY_VALID_TOKEN, msg)
            self.assertIn("[REDACTED_BOT_TOKEN]", msg)

    def test_07_zero_service_role_in_telegram_module(self):
        """Ensure no Supabase service_role is referenced in core/telegram_alert.py."""
        target_path = os.path.join("core", "telegram_alert.py")
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("service_role", content.lower())


class TestTelegramAPIMocking(unittest.TestCase):
    """Verifies Telegram Bot API interaction and 4-phase connectivity testing."""

    @patch("requests.get")
    def test_08_verify_bot_token_success(self, mock_get):
        """Successful getMe call returns bot username."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ok": True,
            "result": {"id": 1234567890, "is_bot": True, "username": "EmailShieldBot"}
        }
        mock_get.return_value = mock_resp

        ok, bot_name, msg = verify_telegram_bot_token(DUMMY_VALID_TOKEN)
        self.assertTrue(ok)
        self.assertEqual(bot_name, "@EmailShieldBot")
        self.assertIn("Authenticated successfully", msg)

    @patch("requests.get")
    def test_09_verify_bot_token_unauthorized(self, mock_get):
        """HTTP 401 returns unauthorized error safely without token."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        ok, bot_name, msg = verify_telegram_bot_token(DUMMY_VALID_TOKEN)
        self.assertFalse(ok)
        self.assertIsNone(bot_name)
        self.assertIn("authentication failed", msg.lower())
        self.assertNotIn(DUMMY_VALID_TOKEN, msg)

    @patch("requests.get")
    def test_10_verify_bot_token_timeout(self, mock_get):
        """Network timeout during getMe is handled safely."""
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
        ok, bot_name, msg = verify_telegram_bot_token(DUMMY_VALID_TOKEN)
        self.assertFalse(ok)
        self.assertIn("timed out", msg.lower())

    @patch("requests.post")
    def test_11_send_telegram_alert_success(self, mock_post):
        """Successful sendMessage call returns True."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"ok": True, "result": {"message_id": 1001}}
        mock_post.return_value = mock_resp

        ok, msg = send_telegram_alert(DUMMY_VALID_TOKEN, DUMMY_CHAT_ID, "Critical alert text")
        self.assertTrue(ok)
        self.assertIn("successfully delivered", msg)

    @patch("requests.post")
    def test_12_send_telegram_alert_chat_not_found(self, mock_post):
        """Chat not found error gives clear user guidance without leaking token."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"ok": False, "description": "Bad Request: chat not found"}
        mock_post.return_value = mock_resp

        ok, msg = send_telegram_alert(DUMMY_VALID_TOKEN, DUMMY_CHAT_ID, "Critical alert text")
        self.assertFalse(ok)
        self.assertIn("Chat not found", msg)
        self.assertIn("START", msg)
        self.assertNotIn(DUMMY_VALID_TOKEN, msg)

    @patch("requests.post")
    def test_13_send_telegram_alert_bot_blocked(self, mock_post):
        """Bot blocked error gives clear user feedback."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"ok": False, "description": "Forbidden: bot was blocked by the user"}
        mock_post.return_value = mock_resp

        ok, msg = send_telegram_alert(DUMMY_VALID_TOKEN, DUMMY_CHAT_ID, "Critical alert text")
        self.assertFalse(ok)
        self.assertIn("Bot was blocked", msg)

    @patch("core.telegram_alert.verify_telegram_bot_token")
    @patch("core.telegram_alert.send_telegram_alert")
    def test_14_test_telegram_alert_delivery_full_pass(self, mock_send, mock_verify):
        """Controlled 4-phase connectivity test all-pass verification."""
        mock_verify.return_value = (True, "@EmailShieldSentinelBot", "Auth OK")
        mock_send.return_value = (True, "Delivered")

        res = run_telegram_connectivity_test(DUMMY_VALID_TOKEN, DUMMY_CHAT_ID)
        self.assertEqual(res["api_status"], "PASS")
        self.assertEqual(res["auth_status"], "PASS")
        self.assertEqual(res["destination_status"], "PASS")
        self.assertEqual(res["delivery_status"], "DELIVERED")
        self.assertEqual(res["bot_username"], "@EmailShieldSentinelBot")

    @patch("core.telegram_alert.verify_telegram_bot_token")
    def test_15_test_telegram_alert_delivery_auth_fail(self, mock_verify):
        """Controlled test short-circuits gracefully on auth failure."""
        mock_verify.return_value = (False, None, "Invalid token")

        res = run_telegram_connectivity_test(DUMMY_VALID_TOKEN, DUMMY_CHAT_ID)
        self.assertEqual(res["auth_status"], "FAIL")
        self.assertEqual(res["destination_status"], "FAIL")
        self.assertEqual(res["delivery_status"], "FAILED")


class TestSentinelHighRiskTelegramIntegration(unittest.TestCase):
    """Verifies that high-risk threat events dispatch properly sanitized Telegram alerts."""

    def test_16_threat_alert_text_redacts_credentials_and_otps(self):
        """High-risk threat alert formatter properly redacts sensitive OTP tokens."""
        raw_subject = "SBI Bank Alert: Your OTP is 948201 for Login"
        masked_sub = mask_sensitive_subject(raw_subject)
        self.assertNotIn("948201", masked_sub)

        threat_payload = {
            "case_id": "CASE-CRITICAL-001",
            "subject": masked_sub,
            "sender": "fraud@sbi-fraud-login.net",
            "sender_location": "Moscow, Russia 🇷🇺",
            "risk_score": "HIGH",
            "risk_score_numeric": 96,
            "risk_reasons": ["Credential harvesting form detected", "DMARC alignment failed"]
        }
        alert_text = format_threat_alert_text(threat_payload)

        self.assertIn("CRITICAL SECURITY ALERT", alert_text)
        self.assertIn("96/100", alert_text)
        self.assertNotIn("948201", alert_text)
        self.assertIn("fraud@sbi-fraud-login.net", alert_text)

    @patch("core.sentinel.send_telegram_alert")
    def test_17_send_test_alert_delegates_to_telegram(self, mock_tg):
        """send_test_alert cleanly formats ping and invokes send_telegram_alert."""
        mock_tg.return_value = (True, "Telegram alert successfully delivered.")
        cfg = {
            "telegram_token": DUMMY_VALID_TOKEN,
            "telegram_chat_id": DUMMY_CHAT_ID,
        }
        ok, msg = send_test_alert("telegram", cfg)
        self.assertTrue(ok)
        mock_tg.assert_called_once()
        args = mock_tg.call_args[0]
        self.assertEqual(args[0], DUMMY_VALID_TOKEN)
        self.assertEqual(args[1], DUMMY_CHAT_ID)
        self.assertIn("SENTINEL TEST PING", args[2])

    @patch("core.sentinel.send_telegram_alert")
    def test_18_sentinel_high_risk_pipeline_triggers_telegram_alert(self, mock_tg):
        """
        Controlled E2E Test:
        Sentinel detects event -> Forensic processing -> HIGH risk -> Existing alert pipeline -> Telegram.
        """
        from core.sentinel import SentinelManager
        mock_tg.return_value = (True, "Telegram alert successfully delivered.")

        manager = SentinelManager()
        manager.config["alert_config"] = {
            "telegram_enabled": True,
            "telegram_token": DUMMY_VALID_TOKEN,
            "telegram_chat_id": DUMMY_CHAT_ID,
        }

        with open(os.path.join("samples", "phishing.eml"), "rb") as f:
            phish_bytes = f.read()

        with patch.object(manager, "_fetch_raw_bytes", return_value=phish_bytes), \
             patch("core.sentinel.save_case"):
            manager._analyze_and_record_email({
                "id": "controlled-msg-001",
                "subject": "Important Account Update Notice",
                "sender": "service@paypal.com",
                "date": "18-Sep-2026 10:00:00"
            })

        mock_tg.assert_called_once()
        sent_token, sent_chat_id, sent_text = mock_tg.call_args[0]
        self.assertEqual(sent_token, DUMMY_VALID_TOKEN)
        self.assertEqual(sent_chat_id, DUMMY_CHAT_ID)
        self.assertIn("EMAILSHIELD CRITICAL SECURITY ALERT", sent_text)
        self.assertIn("CRITICAL", sent_text.upper())

    @patch("core.sentinel.send_telegram_alert")
    def test_19_sentinel_clean_pipeline_does_not_trigger_telegram_alert(self, mock_tg):
        """Clean emails do NOT fire mobile alerts."""
        from core.sentinel import SentinelManager

        manager = SentinelManager()
        manager.config["alert_config"] = {
            "telegram_enabled": True,
            "telegram_token": DUMMY_VALID_TOKEN,
            "telegram_chat_id": DUMMY_CHAT_ID,
        }

        with open(os.path.join("samples", "clean.eml"), "rb") as f:
            clean_bytes = f.read()

        with patch.object(manager, "_fetch_raw_bytes", return_value=clean_bytes), \
             patch("core.sentinel.save_case"):
            manager._analyze_and_record_email({
                "id": "clean-msg-002",
                "subject": "Project Update Discussion",
                "sender": "colleague@trusted-domain.com",
                "date": "18-Sep-2026 10:15:00"
            })

        mock_tg.assert_not_called()


if __name__ == "__main__":
    unittest.main()
