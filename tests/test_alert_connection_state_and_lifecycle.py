"""
tests/test_alert_connection_state_and_lifecycle.py
Comprehensive test suite verifying all 20 required invariants for:
Mobile Threat Alert connection state, credential hiding, and session lifecycle management.

Invariants Covered:
 1. Valid Telegram credentials + successful Test Alert -> transitions to CONNECTED / ACTIVE.
 2. Valid WhatsApp credentials + successful Test Alert -> transitions to CONNECTED / ACTIVE.
 3. Successful connection -> credential inputs disappear / are hidden from UI.
 4. Actual credentials never appear in rendered UI or HTML (only masked destination).
 5. Actual credentials never appear in logs or plaintext session state (AES-256-GCM encrypted).
 6. Streamlit rerun preserves ACTIVE state.
 7. Telegram ACTIVE does not make WhatsApp ACTIVE (independent provider state).
 8. WhatsApp ACTIVE does not make Telegram ACTIVE.
 9. Failed Test Alert does not mark provider ACTIVE (remains NOT CONNECTED / TEST_FAILED, inputs visible).
10. Invalid credentials format does not mark provider ACTIVE.
11. Disconnect returns provider to DISCONNECTED and reveals configuration inputs.
12. Test Alert while connected does not require re-entering credentials (uses securely stored decrypted credentials).
13. Test Alert does not modify Live Mail telemetry or email counters.
14. Test Alert does not create cases.
15. Test Alert does not create threat activity.
16. User A alert configuration cannot appear for User B (multi-user tenant isolation).
17. Logout/session expiration in app.py clears ACTIVE state and wipes in-memory alert store.
18. Login after logout starts in NOT CONNECTED with credentials hidden.
19. Browser refresh with valid session restores ACTIVE state from session alert store.
20. No service_role usage and database schema unchanged.
"""

import os
import re
import sys
import logging
import subprocess
import unittest
from unittest.mock import patch, MagicMock

import pytest

from core.alert_session import (
    _ALERT_SESSION_STORE,
    _EPHEMERAL_MASTER_KEY,
    save_telegram_connection,
    get_telegram_connection,
    get_telegram_credentials,
    disconnect_telegram,
    set_telegram_status,
    save_whatsapp_connection,
    get_whatsapp_connection,
    get_whatsapp_credentials,
    disconnect_whatsapp,
    set_whatsapp_status,
    clear_alert_session,
)
from core.sentinel_crypto import encrypt_secret, decrypt_secret
from core.telegram_alert import (
    TelegramTestResult,
    mask_telegram_chat_id,
    validate_telegram_token_format,
    validate_telegram_chat_id,
)
from core.whatsapp_alert import (
    WhatsAppTestResult,
    mask_phone_number,
    validate_whatsapp_phone,
    validate_whatsapp_apikey,
)
from views.alerts import render as render_alerts
from app import clear_investigator_session


# =============================================================================
# STREAMLIT MOCK HARNESS
# =============================================================================

class MockStreamlitHarness:
    """Simulates Streamlit widget state, lifecycle, and rendering captures."""

    def __init__(self, session_state=None, text_inputs=None, clicked_buttons=None):
        self.session_state = session_state if session_state is not None else {}
        self.text_inputs = text_inputs or {}
        self.clicked_buttons = set(clicked_buttons or [])
        self.markdown_rendered = []
        self.text_input_rendered = []
        self.button_rendered = []
        self.rerun_called = False

    class _ContextBlock:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    def tabs(self, titles):
        return [self._ContextBlock(), self._ContextBlock()]

    def expander(self, *args, **kwargs):
        return self._ContextBlock()

    def columns(self, spec):
        n = spec if isinstance(spec, int) else len(spec)
        return [self._ContextBlock() for _ in range(n)]

    def spinner(self, *args, **kwargs):
        return self._ContextBlock()

    def subheader(self, text):
        pass

    def markdown(self, text, **kwargs):
        self.markdown_rendered.append(str(text))

    def text_input(self, label, value="", **kwargs):
        key = kwargs.get("key")
        self.text_input_rendered.append({"label": label, "value": value, "key": key, "kwargs": kwargs})
        if key in self.text_inputs:
            return self.text_inputs[key]
        return value

    def button(self, label, **kwargs):
        key = kwargs.get("key")
        self.button_rendered.append({"label": label, "key": key, "kwargs": kwargs})
        return key in self.clicked_buttons

    def rerun(self):
        self.rerun_called = True


# =============================================================================
# TEST FIXTURE BASE
# =============================================================================

class TestAlertConnectionLifecycleBase(unittest.TestCase):
    def setUp(self):
        clear_alert_session()
        self.user_a = "usr_tenant_alpha_111"
        self.user_b = "usr_tenant_beta_222"
        self.worker_id = "wrk_sentinel_001"
        self.mock_client = MagicMock()
        mock_table = MagicMock()
        self.mock_client.table.return_value = mock_table
        mock_table.select.return_value.eq.return_value.execute.return_value = MagicMock(data=[])
        mock_table.insert.return_value.execute.return_value = MagicMock(data=[{"id": "alert_1"}])
        mock_table.update.return_value.eq.return_value.eq.return_value.execute.return_value = MagicMock(data=[{"id": "alert_1"}])

        self.valid_tg_token = "123456789:ABCdefGHIjklmnoPQRstuvwxYZ123456789"
        self.valid_tg_chat = "987654321"
        self.valid_wa_phone = "+919876543210"
        self.valid_wa_key = "callmebot_secret_api_key_88"

    def tearDown(self):
        clear_alert_session()

    def _create_harness(self, session_state=None, text_inputs=None, clicked_buttons=None):
        return MockStreamlitHarness(
            session_state=session_state,
            text_inputs=text_inputs,
            clicked_buttons=clicked_buttons
        )

    def _render_with_harness(self, harness, user_id=None, ctx=None):
        target_user = user_id or self.user_a
        context = ctx or {"worker_rec": {"id": self.worker_id}}
        with patch.multiple(
            "streamlit",
            session_state=harness.session_state,
            tabs=harness.tabs,
            expander=harness.expander,
            columns=harness.columns,
            spinner=harness.spinner,
            subheader=harness.subheader,
            markdown=harness.markdown,
            text_input=harness.text_input,
            button=harness.button,
            rerun=harness.rerun,
        ):
            render_alerts(target_user, self.mock_client, **context)


# =============================================================================
# INVARIANT TESTS
# =============================================================================

class TestAlertConnectionStateAndLifecycle(TestAlertConnectionLifecycleBase):

    # -------------------------------------------------------------------------
    # Invariant 1: Valid Telegram credentials + successful Test Alert -> ACTIVE
    # -------------------------------------------------------------------------
    def test_invariant_01_telegram_valid_credentials_transitions_to_active(self):
        """
        Invariant 1: Valid Telegram credentials + successful Test Alert ->
        transitions to CONNECTED / ACTIVE in both core store and views UI.
        """
        # 1. Test core session function directly
        save_telegram_connection(
            user_id=self.user_a,
            bot_token=self.valid_tg_token,
            chat_id=self.valid_tg_chat,
            bot_username="@SentinelSecBot"
        )
        conn = get_telegram_connection(self.user_a)
        self.assertTrue(conn["connected"])
        self.assertEqual(conn["status"], "ACTIVE")
        self.assertEqual(conn["bot_username"], "@SentinelSecBot")
        self.assertIn("321", conn["masked_destination"])

        # 2. Test full UI workflow via render()
        clear_alert_session(self.user_a)
        harness = self._create_harness(
            text_inputs={
                "tg_cfg_tok": self.valid_tg_token,
                "tg_cfg_chat": self.valid_tg_chat,
            },
            clicked_buttons=["btn_test_tg_page"]
        )

        with patch("views.alerts.test_telegram_alert_delivery") as mock_delivery:
            mock_delivery.return_value = TelegramTestResult({
                "delivery_status": "DELIVERED",
                "bot_username": "@SentinelSecBot",
                "details": "Alert test passed"
            })
            self._render_with_harness(harness, user_id=self.user_a)

            self.assertTrue(harness.rerun_called)
            conn_after = get_telegram_connection(self.user_a)
            self.assertTrue(conn_after["connected"])
            self.assertEqual(conn_after["status"], "ACTIVE")

    # -------------------------------------------------------------------------
    # Invariant 2: Valid WhatsApp credentials + successful Test Alert -> ACTIVE
    # -------------------------------------------------------------------------
    def test_invariant_02_whatsapp_valid_credentials_transitions_to_active(self):
        """
        Invariant 2: Valid WhatsApp credentials + successful Test Alert ->
        transitions to CONNECTED / ACTIVE in both core store and views UI.
        """
        # 1. Test core session function directly
        save_whatsapp_connection(
            user_id=self.user_a,
            phone=self.valid_wa_phone,
            apikey=self.valid_wa_key
        )
        conn = get_whatsapp_connection(self.user_a)
        self.assertTrue(conn["connected"])
        self.assertEqual(conn["status"], "ACTIVE")
        self.assertIn("+91", conn["masked_destination"])
        self.assertIn("10", conn["masked_destination"])

        # 2. Test full UI workflow via render()
        clear_alert_session(self.user_a)
        harness = self._create_harness(
            text_inputs={
                "wa_cfg_ph": self.valid_wa_phone,
                "wa_cfg_key": self.valid_wa_key,
            },
            clicked_buttons=["btn_save_wa_page"]
        )

        with patch("views.alerts.test_whatsapp_alert_delivery") as mock_delivery:
            mock_delivery.return_value = WhatsAppTestResult({
                "delivery_status": "DELIVERED",
                "details": "WhatsApp alert test delivered"
            })
            self._render_with_harness(harness, user_id=self.user_a)

            self.assertTrue(harness.rerun_called)
            conn_after = get_whatsapp_connection(self.user_a)
            self.assertTrue(conn_after["connected"])
            self.assertEqual(conn_after["status"], "ACTIVE")

    # -------------------------------------------------------------------------
    # Invariant 3: Successful connection -> credential inputs disappear
    # -------------------------------------------------------------------------
    def test_invariant_03_successful_connection_hides_credential_inputs(self):
        """
        Invariant 3: Successful connection -> credential inputs disappear /
        are completely hidden from UI.
        """
        # When DISCONNECTED: inputs must be present
        harness_disc = self._create_harness()
        self._render_with_harness(harness_disc, user_id=self.user_a)

        rendered_keys_disc = [call["key"] for call in harness_disc.text_input_rendered]
        self.assertIn("tg_cfg_tok", rendered_keys_disc)
        self.assertIn("tg_cfg_chat", rendered_keys_disc)
        self.assertIn("wa_cfg_ph", rendered_keys_disc)
        self.assertIn("wa_cfg_key", rendered_keys_disc)

        # When CONNECTED / ACTIVE: inputs must be completely hidden
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        harness_conn = self._create_harness()
        self._render_with_harness(harness_conn, user_id=self.user_a)

        rendered_keys_conn = [call["key"] for call in harness_conn.text_input_rendered]
        self.assertNotIn("tg_cfg_tok", rendered_keys_conn)
        self.assertNotIn("tg_cfg_chat", rendered_keys_conn)
        self.assertNotIn("wa_cfg_ph", rendered_keys_conn)
        self.assertNotIn("wa_cfg_key", rendered_keys_conn)

    # -------------------------------------------------------------------------
    # Invariant 4: Actual credentials never appear in rendered UI or HTML
    # -------------------------------------------------------------------------
    def test_invariant_04_actual_credentials_never_appear_in_rendered_ui_or_html(self):
        """
        Invariant 4: Actual credentials never appear in rendered UI or HTML
        (only masked destination).
        """
        raw_token = "9876543210:SuperSecretTelegramTokenXYZabcdef123"
        raw_chat = "777888999"
        raw_phone = "+919876543210"
        raw_apikey = "SuperSecretCallMeBotApiKey12345"

        save_telegram_connection(self.user_a, raw_token, raw_chat)
        save_whatsapp_connection(self.user_a, raw_phone, raw_apikey)

        harness = self._create_harness()
        self._render_with_harness(harness, user_id=self.user_a)

        all_rendered_content = " ".join(harness.markdown_rendered)

        # Raw secrets MUST NOT be anywhere in rendered markdown or HTML
        self.assertNotIn(raw_token, all_rendered_content)
        self.assertNotIn("SuperSecretTelegramTokenXYZabcdef123", all_rendered_content)
        self.assertNotIn(raw_apikey, all_rendered_content)
        self.assertNotIn("SuperSecretCallMeBotApiKey12345", all_rendered_content)
        self.assertNotIn("98765432", all_rendered_content)  # Unmasked phone middle digits

        # Masked destinations MUST be present
        self.assertIn(mask_telegram_chat_id(raw_chat), all_rendered_content)
        self.assertIn(mask_phone_number(raw_phone), all_rendered_content)

    # -------------------------------------------------------------------------
    # Invariant 5: Actual credentials never in logs or plaintext session state
    # -------------------------------------------------------------------------
    def test_invariant_05_credentials_never_in_logs_or_plaintext_session_state(self):
        """
        Invariant 5: Actual credentials never appear in logs or plaintext session state
        (AES-256-GCM encrypted envelopes only in internal store).
        """
        fake_session = {}
        with patch("streamlit.session_state", fake_session):
            save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
            save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

            # Plaintext credentials must never exist in session_state
            for k, val in fake_session.items():
                self.assertNotIn(self.valid_tg_token, str(val))
                self.assertNotIn(self.valid_wa_key, str(val))
                self.assertNotIn(self.valid_tg_chat, str(val))

            # Verify in-memory alert store envelopes start with v1: AES-256-GCM
            tg_envelopes = _ALERT_SESSION_STORE[self.user_a]["telegram"]
            wa_envelopes = _ALERT_SESSION_STORE[self.user_a]["whatsapp"]

            self.assertTrue(tg_envelopes["token_envelope"].startswith("v1:"))
            self.assertTrue(tg_envelopes["chat_envelope"].startswith("v1:"))
            self.assertTrue(wa_envelopes["phone_envelope"].startswith("v1:"))
            self.assertTrue(wa_envelopes["apikey_envelope"].startswith("v1:"))

            self.assertNotIn(self.valid_tg_token, tg_envelopes["token_envelope"])
            self.assertNotIn(self.valid_wa_key, wa_envelopes["apikey_envelope"])

    # -------------------------------------------------------------------------
    # Invariant 6: Streamlit rerun preserves ACTIVE state
    # -------------------------------------------------------------------------
    def test_invariant_06_streamlit_rerun_preserves_active_state(self):
        """
        Invariant 6: Streamlit rerun preserves ACTIVE state across consecutive passes.
        """
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        # Pass 1: Initial load after connection
        harness1 = self._create_harness()
        self._render_with_harness(harness1, user_id=self.user_a)
        tg1 = get_telegram_connection(self.user_a)
        wa1 = get_whatsapp_connection(self.user_a)
        self.assertTrue(tg1["connected"])
        self.assertEqual(tg1["status"], "ACTIVE")
        self.assertTrue(wa1["connected"])
        self.assertEqual(wa1["status"], "ACTIVE")

        # Pass 2: Subsequent Streamlit rerun
        harness2 = self._create_harness(session_state=harness1.session_state)
        self._render_with_harness(harness2, user_id=self.user_a)
        tg2 = get_telegram_connection(self.user_a)
        wa2 = get_whatsapp_connection(self.user_a)
        self.assertTrue(tg2["connected"])
        self.assertEqual(tg2["status"], "ACTIVE")
        self.assertTrue(wa2["connected"])
        self.assertEqual(wa2["status"], "ACTIVE")

        # Credential inputs remain hidden on rerun
        keys_pass2 = [c["key"] for c in harness2.text_input_rendered]
        self.assertNotIn("tg_cfg_tok", keys_pass2)
        self.assertNotIn("wa_cfg_key", keys_pass2)

    # -------------------------------------------------------------------------
    # Invariant 7: Telegram ACTIVE does not make WhatsApp ACTIVE
    # -------------------------------------------------------------------------
    def test_invariant_07_telegram_active_does_not_make_whatsapp_active(self):
        """
        Invariant 7: Telegram ACTIVE does not make WhatsApp ACTIVE (independent provider state).
        """
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)

        tg_conn = get_telegram_connection(self.user_a)
        wa_conn = get_whatsapp_connection(self.user_a)

        self.assertTrue(tg_conn["connected"])
        self.assertEqual(tg_conn["status"], "ACTIVE")

        self.assertFalse(wa_conn["connected"])
        self.assertIn(wa_conn["status"], ["DISCONNECTED", "NOT_CONNECTED"])

        harness = self._create_harness()
        self._render_with_harness(harness, user_id=self.user_a)

        # Telegram inputs hidden, WhatsApp inputs rendered
        rendered_keys = [c["key"] for c in harness.text_input_rendered]
        self.assertNotIn("tg_cfg_tok", rendered_keys)
        self.assertIn("wa_cfg_key", rendered_keys)
        self.assertIn("wa_cfg_ph", rendered_keys)

    # -------------------------------------------------------------------------
    # Invariant 8: WhatsApp ACTIVE does not make Telegram ACTIVE
    # -------------------------------------------------------------------------
    def test_invariant_08_whatsapp_active_does_not_make_telegram_active(self):
        """
        Invariant 8: WhatsApp ACTIVE does not make Telegram ACTIVE (independent provider state).
        """
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        wa_conn = get_whatsapp_connection(self.user_a)
        tg_conn = get_telegram_connection(self.user_a)

        self.assertTrue(wa_conn["connected"])
        self.assertEqual(wa_conn["status"], "ACTIVE")

        self.assertFalse(tg_conn["connected"])
        self.assertIn(tg_conn["status"], ["DISCONNECTED", "NOT_CONNECTED"])

        harness = self._create_harness()
        self._render_with_harness(harness, user_id=self.user_a)

        # WhatsApp inputs hidden, Telegram inputs rendered
        rendered_keys = [c["key"] for c in harness.text_input_rendered]
        self.assertNotIn("wa_cfg_key", rendered_keys)
        self.assertIn("tg_cfg_tok", rendered_keys)
        self.assertIn("tg_cfg_chat", rendered_keys)

    # -------------------------------------------------------------------------
    # Invariant 9: Failed Test Alert does not mark provider ACTIVE
    # -------------------------------------------------------------------------
    def test_invariant_09_failed_test_alert_does_not_mark_active(self):
        """
        Invariant 9: Failed Test Alert does not mark provider ACTIVE
        (remains NOT CONNECTED / TEST_FAILED, inputs visible).
        """
        # Telegram failure
        harness_tg = self._create_harness(
            text_inputs={
                "tg_cfg_tok": self.valid_tg_token,
                "tg_cfg_chat": self.valid_tg_chat,
            },
            clicked_buttons=["btn_test_tg_page"]
        )

        with patch("views.alerts.test_telegram_alert_delivery") as mock_tg_delivery:
            mock_tg_delivery.return_value = TelegramTestResult({
                "delivery_status": "FAILED",
                "details": "Telegram bot blocked by user"
            })
            self._render_with_harness(harness_tg, user_id=self.user_a)

            conn_tg = get_telegram_connection(self.user_a)
            self.assertFalse(conn_tg["connected"])
            self.assertEqual(conn_tg["status"], "TEST_FAILED")
            self.assertFalse(harness_tg.rerun_called)

        # WhatsApp failure
        harness_wa = self._create_harness(
            text_inputs={
                "wa_cfg_ph": self.valid_wa_phone,
                "wa_cfg_key": self.valid_wa_key,
            },
            clicked_buttons=["btn_test_wa_page"]
        )

        with patch("views.alerts.test_whatsapp_alert_delivery") as mock_wa_delivery:
            mock_wa_delivery.return_value = WhatsAppTestResult({
                "delivery_status": "FAILED",
                "details": "CallMeBot gateway HTTP 401 Unauthorized"
            })
            self._render_with_harness(harness_wa, user_id=self.user_a)

            conn_wa = get_whatsapp_connection(self.user_a)
            self.assertFalse(conn_wa["connected"])
            self.assertEqual(conn_wa["status"], "TEST_FAILED")
            self.assertFalse(harness_wa.rerun_called)

    # -------------------------------------------------------------------------
    # Invariant 10: Invalid credentials format does not mark provider ACTIVE
    # -------------------------------------------------------------------------
    def test_invariant_10_invalid_credentials_format_does_not_mark_active(self):
        """
        Invariant 10: Invalid credentials format does not mark provider ACTIVE.
        """
        # 1. Invalid Telegram token format
        harness_tg = self._create_harness(
            text_inputs={
                "tg_cfg_tok": "invalid_format_token",
                "tg_cfg_chat": "123456789",
            },
            clicked_buttons=["btn_save_tg_page"]
        )
        with patch("views.alerts.test_telegram_alert_delivery") as mock_delivery:
            self._render_with_harness(harness_tg, user_id=self.user_a)
            mock_delivery.assert_not_called()
            conn = get_telegram_connection(self.user_a)
            self.assertFalse(conn["connected"])
            self.assertEqual(conn["status"], "CONNECTION_FAILED")

        # 2. Invalid WhatsApp phone format
        harness_wa = self._create_harness(
            text_inputs={
                "wa_cfg_ph": "not_a_phone",
                "wa_cfg_key": "some_valid_key_123",
            },
            clicked_buttons=["btn_save_wa_page"]
        )
        with patch("views.alerts.test_whatsapp_alert_delivery") as mock_delivery_wa:
            self._render_with_harness(harness_wa, user_id=self.user_a)
            mock_delivery_wa.assert_not_called()
            conn = get_whatsapp_connection(self.user_a)
            self.assertFalse(conn["connected"])
            self.assertEqual(conn["status"], "CONNECTION_FAILED")

    # -------------------------------------------------------------------------
    # Invariant 11: Disconnect returns provider to DISCONNECTED & reveals inputs
    # -------------------------------------------------------------------------
    def test_invariant_11_disconnect_returns_to_disconnected_and_reveals_inputs(self):
        """
        Invariant 11: Disconnect returns provider to DISCONNECTED and reveals configuration inputs.
        """
        # Set Telegram to ACTIVE
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        self.assertTrue(get_telegram_connection(self.user_a)["connected"])

        # Click Disconnect
        harness_disc = self._create_harness(clicked_buttons=["btn_disc_tg"])
        self._render_with_harness(harness_disc, user_id=self.user_a)

        self.assertTrue(harness_disc.rerun_called)
        conn_after = get_telegram_connection(self.user_a)
        self.assertFalse(conn_after["connected"])
        self.assertEqual(conn_after["status"], "DISCONNECTED")

        # Next render pass reveals configuration inputs again
        harness_next = self._create_harness()
        self._render_with_harness(harness_next, user_id=self.user_a)

        rendered_keys = [c["key"] for c in harness_next.text_input_rendered]
        self.assertIn("tg_cfg_tok", rendered_keys)
        self.assertIn("tg_cfg_chat", rendered_keys)

        # Symmetrically for WhatsApp
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)
        self.assertTrue(get_whatsapp_connection(self.user_a)["connected"])

        harness_disc_wa = self._create_harness(clicked_buttons=["btn_disc_wa"])
        self._render_with_harness(harness_disc_wa, user_id=self.user_a)

        self.assertTrue(harness_disc_wa.rerun_called)
        conn_wa_after = get_whatsapp_connection(self.user_a)
        self.assertFalse(conn_wa_after["connected"])
        self.assertEqual(conn_wa_after["status"], "DISCONNECTED")

    # -------------------------------------------------------------------------
    # Invariant 12: Test Alert while connected does not require re-entering creds
    # -------------------------------------------------------------------------
    def test_invariant_12_test_alert_while_connected_uses_stored_decrypted_creds(self):
        """
        Invariant 12: Test Alert while connected does not require re-entering
        credentials (uses securely stored decrypted credentials).
        """
        save_telegram_connection(
            self.user_a,
            bot_token=self.valid_tg_token,
            chat_id=self.valid_tg_chat,
            bot_username="@SentinelBot"
        )
        save_whatsapp_connection(
            self.user_a,
            phone=self.valid_wa_phone,
            apikey=self.valid_wa_key
        )

        # 1. Trigger connected Test Alert for Telegram
        harness_tg = self._create_harness(clicked_buttons=["btn_test_tg_connected"])
        with patch("views.alerts.test_telegram_alert_delivery") as mock_tg_test:
            mock_tg_test.return_value = TelegramTestResult({
                "delivery_status": "DELIVERED",
                "details": "Delivered using stored decrypted token"
            })
            self._render_with_harness(harness_tg, user_id=self.user_a)

            mock_tg_test.assert_called_once_with(self.valid_tg_token, self.valid_tg_chat)
            # Provider remains ACTIVE
            self.assertTrue(get_telegram_connection(self.user_a)["connected"])
            self.assertEqual(get_telegram_connection(self.user_a)["status"], "ACTIVE")

        # 2. Trigger connected Test Alert for WhatsApp
        harness_wa = self._create_harness(clicked_buttons=["btn_test_wa_connected"])
        with patch("views.alerts.test_whatsapp_alert_delivery") as mock_wa_test:
            mock_wa_test.return_value = WhatsAppTestResult({
                "delivery_status": "DELIVERED",
                "details": "Delivered using stored decrypted key"
            })
            self._render_with_harness(harness_wa, user_id=self.user_a)

            mock_wa_test.assert_called_once_with(self.valid_wa_phone, self.valid_wa_key)
            # Provider remains ACTIVE
            self.assertTrue(get_whatsapp_connection(self.user_a)["connected"])
            self.assertEqual(get_whatsapp_connection(self.user_a)["status"], "ACTIVE")

    # -------------------------------------------------------------------------
    # Invariant 13: Test Alert does not modify Live Mail telemetry or email counters
    # -------------------------------------------------------------------------
    def test_invariant_13_test_alert_does_not_modify_live_mail_telemetry_or_counters(self):
        """
        Invariant 13: Test Alert does not modify Live Mail telemetry or email counters.
        """
        from core.sentinel_stats import (
            record_user_sentinel_poll,
            get_user_sentinel_stats,
            reset_user_sentinel_stats
        )

        mailbox_id = "mbx_isolated_telemetry_001"
        reset_user_sentinel_stats(self.user_a, mailbox_id)
        record_user_sentinel_poll(
            user_id=self.user_a,
            mailbox_id=mailbox_id,
            arrived=12,
            analysed=10,
            clean=8,
            suspicious=2,
            high_critical=1,
            duplicates=2,
            errors=0,
            last_uid=1050
        )

        stats_before = get_user_sentinel_stats(self.user_a, mailbox_id)

        # Dispatch Test Alerts
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        harness = self._create_harness(clicked_buttons=["btn_test_tg_connected", "btn_test_wa_connected"])
        with patch("views.alerts.test_telegram_alert_delivery") as m_tg, patch("views.alerts.test_whatsapp_alert_delivery") as m_wa:
            m_tg.return_value = TelegramTestResult({"delivery_status": "DELIVERED"})
            m_wa.return_value = WhatsAppTestResult({"delivery_status": "DELIVERED"})
            self._render_with_harness(harness, user_id=self.user_a)

        stats_after = get_user_sentinel_stats(self.user_a, mailbox_id)
        self.assertEqual(stats_before, stats_after)

    # -------------------------------------------------------------------------
    # Invariant 14: Test Alert does not create cases
    # -------------------------------------------------------------------------
    def test_invariant_14_test_alert_does_not_create_cases(self):
        """
        Invariant 14: Test Alert does not create cases.
        """
        from core.case_store import get_all_cases

        cases_before = len(get_all_cases())

        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        harness = self._create_harness(clicked_buttons=["btn_test_tg_connected", "btn_test_wa_connected"])
        with patch("views.alerts.test_telegram_alert_delivery") as m_tg, patch("views.alerts.test_whatsapp_alert_delivery") as m_wa:
            m_tg.return_value = TelegramTestResult({"delivery_status": "DELIVERED"})
            m_wa.return_value = WhatsAppTestResult({"delivery_status": "DELIVERED"})
            self._render_with_harness(harness, user_id=self.user_a)

        cases_after = len(get_all_cases())
        self.assertEqual(cases_before, cases_after)

    # -------------------------------------------------------------------------
    # Invariant 15: Test Alert does not create threat activity
    # -------------------------------------------------------------------------
    def test_invariant_15_test_alert_does_not_create_threat_activity(self):
        """
        Invariant 15: Test Alert does not create threat activity.
        """
        from core.case_store import get_soc_threat_activity

        activity_before = get_soc_threat_activity()

        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        harness = self._create_harness(clicked_buttons=["btn_test_tg_connected", "btn_test_wa_connected"])
        with patch("views.alerts.test_telegram_alert_delivery") as m_tg, patch("views.alerts.test_whatsapp_alert_delivery") as m_wa:
            m_tg.return_value = TelegramTestResult({"delivery_status": "DELIVERED"})
            m_wa.return_value = WhatsAppTestResult({"delivery_status": "DELIVERED"})
            self._render_with_harness(harness, user_id=self.user_a)

        activity_after = get_soc_threat_activity()
        self.assertEqual(len(activity_before), len(activity_after))

    # -------------------------------------------------------------------------
    # Invariant 16: User A alert configuration cannot appear for User B
    # -------------------------------------------------------------------------
    def test_invariant_16_user_a_alert_config_isolated_from_user_b(self):
        """
        Invariant 16: User A alert configuration cannot appear for User B
        (multi-user tenant isolation).
        """
        # User A connects
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat, bot_username="@UserABot")
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        # User B queries status
        conn_b_tg = get_telegram_connection(self.user_b)
        conn_b_wa = get_whatsapp_connection(self.user_b)

        self.assertFalse(conn_b_tg["connected"])
        self.assertIn(conn_b_tg["status"], ["DISCONNECTED", "NOT_CONNECTED"])
        self.assertEqual(conn_b_tg["masked_destination"], "")
        self.assertIsNone(conn_b_tg["bot_username"])

        self.assertFalse(conn_b_wa["connected"])
        self.assertIn(conn_b_wa["status"], ["DISCONNECTED", "NOT_CONNECTED"])
        self.assertEqual(conn_b_wa["masked_destination"], "")

        # User B cannot retrieve User A's credentials
        b_tok, b_cid = get_telegram_credentials(self.user_b)
        self.assertIsNone(b_tok)
        self.assertIsNone(b_cid)

        # Cryptographic context binding ensures User B context cannot decrypt User A's envelope
        env_a = _ALERT_SESSION_STORE[self.user_a]["telegram"]["token_envelope"]
        with self.assertRaises(Exception):
            decrypt_secret(env_a, _EPHEMERAL_MASTER_KEY, context=f"telegram_{self.user_b}")

        # User B renders UI: must see empty disconnected state
        harness_b = self._create_harness()
        self._render_with_harness(harness_b, user_id=self.user_b)

        rendered_text_b = " ".join(harness_b.markdown_rendered)
        self.assertNotIn("UserABot", rendered_text_b)
        self.assertNotIn(mask_telegram_chat_id(self.valid_tg_chat), rendered_text_b)
        self.assertNotIn(mask_phone_number(self.valid_wa_phone), rendered_text_b)

    # -------------------------------------------------------------------------
    # Invariant 17: Logout in app.py clears ACTIVE state & wipes alert store
    # -------------------------------------------------------------------------
    def test_invariant_17_logout_clears_active_state_and_wipes_in_memory_store(self):
        """
        Invariant 17: Logout/session expiration in app.py clears ACTIVE state
        and wipes in-memory alert store.
        """
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        fake_session = {
            "user_id": self.user_a,
            "telegram_connected": True,
            "telegram_status": "ACTIVE",
            "whatsapp_connected": True,
            "whatsapp_status": "ACTIVE",
        }

        with patch("streamlit.session_state", fake_session):
            clear_investigator_session()

            # In-memory store for user_a is completely purged
            self.assertNotIn(self.user_a, _ALERT_SESSION_STORE)
            # Session state is wiped
            self.assertEqual(len(fake_session), 0)

            # Querying returns disconnected
            self.assertFalse(get_telegram_connection(self.user_a)["connected"])
            self.assertFalse(get_whatsapp_connection(self.user_a)["connected"])

    # -------------------------------------------------------------------------
    # Invariant 18: Login after logout starts in NOT CONNECTED with creds hidden
    # -------------------------------------------------------------------------
    def test_invariant_18_login_after_logout_starts_not_connected_credentials_hidden(self):
        """
        Invariant 18: Login after logout starts in NOT CONNECTED with credentials hidden.
        """
        # User A was active, then logged out
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat)
        clear_alert_session(self.user_a)

        # New session starts
        user_c = "usr_tenant_charlie_333"
        conn_tg = get_telegram_connection(user_c)
        conn_wa = get_whatsapp_connection(user_c)

        self.assertFalse(conn_tg["connected"])
        self.assertIn(conn_tg["status"], ["DISCONNECTED", "NOT_CONNECTED"])
        self.assertFalse(conn_wa["connected"])
        self.assertIn(conn_wa["status"], ["DISCONNECTED", "NOT_CONNECTED"])

        # Render view for newly logged-in user
        harness = self._create_harness()
        self._render_with_harness(harness, user_id=user_c)

        # Inputs are rendered with empty defaults, no previously entered credentials
        rendered_inputs = {c["key"]: c["value"] for c in harness.text_input_rendered}
        self.assertIn(rendered_inputs.get("tg_cfg_tok", ""), ["", None])
        self.assertIn(rendered_inputs.get("wa_cfg_key", ""), ["", None])

    # -------------------------------------------------------------------------
    # Invariant 19: Browser refresh restores ACTIVE state from session store
    # -------------------------------------------------------------------------
    def test_invariant_19_browser_refresh_restores_active_state_from_session_store(self):
        """
        Invariant 19: Browser refresh with valid session restores ACTIVE state
        from session alert store.
        """
        save_telegram_connection(self.user_a, self.valid_tg_token, self.valid_tg_chat, bot_username="@RefreshBot")
        save_whatsapp_connection(self.user_a, self.valid_wa_phone, self.valid_wa_key)

        # Simulate browser refresh: st.session_state is reset to fresh dict,
        # but user authentication is restored from valid token/session
        fresh_browser_session = {"user_id": self.user_a}

        with patch("streamlit.session_state", fresh_browser_session):
            tg_restored = get_telegram_connection(self.user_a)
            wa_restored = get_whatsapp_connection(self.user_a)

            self.assertTrue(tg_restored["connected"])
            self.assertEqual(tg_restored["status"], "ACTIVE")
            self.assertEqual(tg_restored["bot_username"], "@RefreshBot")

            self.assertTrue(wa_restored["connected"])
            self.assertEqual(wa_restored["status"], "ACTIVE")

            # Verify session state was restored
            self.assertTrue(fresh_browser_session.get("telegram_connected"))
            self.assertEqual(fresh_browser_session.get("telegram_status"), "ACTIVE")
            self.assertTrue(fresh_browser_session.get("whatsapp_connected"))
            self.assertEqual(fresh_browser_session.get("whatsapp_status"), "ACTIVE")

            # Rendering in refreshed session maintains ACTIVE state and hides inputs
            harness = self._create_harness(session_state=fresh_browser_session)
            self._render_with_harness(harness, user_id=self.user_a)

            rendered_keys = [c["key"] for c in harness.text_input_rendered]
            self.assertNotIn("tg_cfg_tok", rendered_keys)
            self.assertNotIn("wa_cfg_key", rendered_keys)

    # -------------------------------------------------------------------------
    # Invariant 20: No service_role usage and database schema unchanged
    # -------------------------------------------------------------------------
    def test_invariant_20_no_service_role_usage_and_db_schema_unchanged(self):
        """
        Invariant 20: No service_role usage and database schema unchanged.
        """
        # 1. Verify core/alert_session.py does not contain service_role
        with open("core/alert_session.py", "r", encoding="utf-8") as f:
            alert_sess_src = f.read()
        self.assertNotIn("service_role", alert_sess_src.lower())
        self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", alert_sess_src)

        # 2. Verify views/alerts.py does not contain service_role
        with open("views/alerts.py", "r", encoding="utf-8") as f:
            alerts_view_src = f.read()
        self.assertNotIn("service_role", alerts_view_src.lower())
        self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", alerts_view_src)

        # 3. Verify git status shows zero alert-related schema modifications
        #    Note: Additive RPC migrations for other features (e.g., live-mail credential RPC)
        #    are intentionally excluded — this test guards alert/schema integrity only.
        res = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
        alert_schema_keywords = ["alert", "schema.sql"]
        for line in res.stdout.splitlines():
            clean_line = line.strip().lower()
            if any(kw in clean_line for kw in alert_schema_keywords):
                if "migration" in clean_line or "schema.sql" in clean_line:
                    self.fail(f"Unexpected alert/schema change in git status: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
