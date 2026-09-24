"""
tests/test_alert_session.py
Unit tests for core.alert_session ephemeral encrypted alert credential storage.
"""

import unittest
from unittest.mock import patch

from core.alert_session import (
    _EPHEMERAL_MASTER_KEY,
    _ALERT_SESSION_STORE,
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
from core.sentinel_crypto import decrypt_secret


class TestAlertSession(unittest.TestCase):
    def setUp(self):
        clear_alert_session()
        self.user_id_1 = "test_user_001"
        self.user_id_2 = "test_user_002"

    def tearDown(self):
        clear_alert_session()

    def test_ephemeral_key_properties(self):
        """Verify module-level master key is exactly 32 bytes."""
        self.assertIsInstance(_EPHEMERAL_MASTER_KEY, bytes)
        self.assertEqual(len(_EPHEMERAL_MASTER_KEY), 32)

    def test_save_and_get_telegram_connection(self):
        """Verify Telegram connection save, encryption, and status retrieval."""
        fake_session = {
            "tg_cfg_tok": "token_widget_val",
            "tg_cfg_chat": "chat_widget_val",
        }

        with patch("streamlit.session_state", fake_session):
            save_telegram_connection(
                user_id=self.user_id_1,
                bot_token="123456789:ABCdefGHIjklmnoPQRstuvwxYZ1234567",
                chat_id="987654321",
                bot_username="@EmailShieldSecBot",
            )

            # Check session_state non-secret keys
            self.assertTrue(fake_session.get("telegram_connected"))
            self.assertEqual(fake_session.get("telegram_status"), "ACTIVE")
            self.assertEqual(fake_session.get("telegram_bot_user"), "@EmailShieldSecBot")
            self.assertIn("321", fake_session.get("telegram_destination"))
            self.assertNotIn("987654", fake_session.get("telegram_destination"))

            # Widget input keys should be popped
            self.assertNotIn("tg_cfg_tok", fake_session)
            self.assertNotIn("tg_cfg_chat", fake_session)

            # Verify store envelopes are encrypted (starts with v1:)
            tg_entry = _ALERT_SESSION_STORE[self.user_id_1]["telegram"]
            self.assertTrue(tg_entry["token_envelope"].startswith("v1:"))
            self.assertTrue(tg_entry["chat_envelope"].startswith("v1:"))
            self.assertNotIn("123456789", tg_entry["token_envelope"])

            # Test get_telegram_connection
            conn = get_telegram_connection(self.user_id_1)
            self.assertTrue(conn["connected"])
            self.assertEqual(conn["status"], "ACTIVE")
            self.assertEqual(conn["bot_username"], "@EmailShieldSecBot")
            self.assertEqual(conn["masked_destination"], tg_entry["destination"])

    def test_telegram_restore_to_session_state(self):
        """Verify get_telegram_connection restores flags to st.session_state if missing."""
        save_telegram_connection(
            user_id=self.user_id_1,
            bot_token="123456789:ABCdefGHIjklmnoPQRstuvwxYZ1234567",
            chat_id="987654321",
            bot_username="@SecBot",
        )

        # Empty session state simulates page refresh/new render pass
        fake_session = {}
        with patch("streamlit.session_state", fake_session):
            conn = get_telegram_connection(self.user_id_1)
            self.assertTrue(conn["connected"])
            self.assertTrue(fake_session.get("telegram_connected"))
            self.assertEqual(fake_session.get("telegram_status"), "ACTIVE")
            self.assertEqual(fake_session.get("telegram_bot_user"), "@SecBot")

    def test_get_telegram_credentials_and_context_binding(self):
        """Verify credential decryption and cryptographic context binding."""
        raw_token = "123456789:ABCdefGHIjklmnoPQRstuvwxYZ1234567"
        raw_chat = "987654321"

        save_telegram_connection(
            user_id=self.user_id_1,
            bot_token=raw_token,
            chat_id=raw_chat,
        )

        dec_tok, dec_chat = get_telegram_credentials(self.user_id_1)
        self.assertEqual(dec_tok, raw_token)
        self.assertEqual(dec_chat, raw_chat)

        # Multi-tenant context check: decrypting user 1's envelope with user 2's context must fail
        env = _ALERT_SESSION_STORE[self.user_id_1]["telegram"]["token_envelope"]
        with self.assertRaises(Exception):
            decrypt_secret(env, _EPHEMERAL_MASTER_KEY, context=f"telegram_{self.user_id_2}")

    def test_disconnect_and_set_status_telegram(self):
        """Verify disconnect_telegram and set_telegram_status."""
        fake_session = {}
        with patch("streamlit.session_state", fake_session):
            save_telegram_connection(
                user_id=self.user_id_1,
                bot_token="123456789:ABCdefGHIjklmnoPQRstuvwxYZ1234567",
                chat_id="987654321",
            )

            set_telegram_status(self.user_id_1, "TEST_FAILED")
            self.assertEqual(fake_session.get("telegram_status"), "TEST_FAILED")
            conn = get_telegram_connection(self.user_id_1)
            self.assertEqual(conn["status"], "TEST_FAILED")

            disconnect_telegram(self.user_id_1)
            self.assertFalse(fake_session.get("telegram_connected"))
            self.assertEqual(fake_session.get("telegram_status"), "DISCONNECTED")
            self.assertEqual(fake_session.get("telegram_destination"), "")
            self.assertNotIn("telegram", _ALERT_SESSION_STORE.get(self.user_id_1, {}))

    def test_whatsapp_lifecycle(self):
        """Verify WhatsApp connection, credential retrieval, context binding, and disconnect."""
        fake_session = {
            "wa_cfg_ph": "+919876543210",
            "wa_cfg_key": "secret_api_key_123",
        }

        with patch("streamlit.session_state", fake_session):
            save_whatsapp_connection(
                user_id=self.user_id_1,
                phone="+919876543210",
                apikey="secret_api_key_123",
            )

            self.assertTrue(fake_session.get("whatsapp_connected"))
            self.assertEqual(fake_session.get("whatsapp_status"), "ACTIVE")
            self.assertIn("+91", fake_session.get("whatsapp_destination"))
            self.assertIn("10", fake_session.get("whatsapp_destination"))
            self.assertNotIn("98765432", fake_session.get("whatsapp_destination"))
            self.assertNotIn("wa_cfg_ph", fake_session)
            self.assertNotIn("wa_cfg_key", fake_session)

            # Test credential decryption
            phone, key = get_whatsapp_credentials(self.user_id_1)
            self.assertEqual(phone, "+919876543210")
            self.assertEqual(key, "secret_api_key_123")

            # Context binding: cross-user decryption failure
            wa_env = _ALERT_SESSION_STORE[self.user_id_1]["whatsapp"]["phone_envelope"]
            with self.assertRaises(Exception):
                decrypt_secret(wa_env, _EPHEMERAL_MASTER_KEY, context=f"whatsapp_{self.user_id_2}")

            # Status update
            set_whatsapp_status(self.user_id_1, "CONNECTION_FAILED")
            self.assertEqual(fake_session.get("whatsapp_status"), "CONNECTION_FAILED")

            # Disconnect
            disconnect_whatsapp(self.user_id_1)
            self.assertFalse(fake_session.get("whatsapp_connected"))
            self.assertEqual(fake_session.get("whatsapp_status"), "DISCONNECTED")
            self.assertNotIn("whatsapp", _ALERT_SESSION_STORE.get(self.user_id_1, {}))

    def test_clear_alert_session_tenant_isolation(self):
        """Verify clearing one tenant's alert session preserves other tenants."""
        save_telegram_connection(self.user_id_1, "token1", "chat1")
        save_telegram_connection(self.user_id_2, "token2", "chat2")

        fake_session = {
            "telegram_connected": True,
            "telegram_status": "ACTIVE",
            "whatsapp_connected": True,
        }
        with patch("streamlit.session_state", fake_session):
            clear_alert_session(user_id=self.user_id_1)

            # User 1 cleared, User 2 intact
            self.assertNotIn(self.user_id_1, _ALERT_SESSION_STORE)
            self.assertIn(self.user_id_2, _ALERT_SESSION_STORE)
            self.assertNotIn("telegram_connected", fake_session)
            self.assertNotIn("whatsapp_connected", fake_session)

        # Global clear (user_id=None) purges all
        clear_alert_session(user_id=None)
        self.assertEqual(len(_ALERT_SESSION_STORE), 0)

    def test_clear_investigator_session_purges_alert_keys(self):
        """Verify app.py clear_investigator_session purges all alert keys and calls clear_alert_session."""
        from app import clear_investigator_session

        save_telegram_connection(self.user_id_1, "token1", "chat1")
        save_whatsapp_connection(self.user_id_1, "+919876543210", "key1")

        fake_session = {
            "user_id": self.user_id_1,
            "telegram_connected": True,
            "telegram_status": "ACTIVE",
            "telegram_destination": "••••••321",
            "telegram_bot_user": "@SecBot",
            "whatsapp_connected": True,
            "whatsapp_status": "ACTIVE",
            "whatsapp_destination": "+91••••••••10",
            "sentinel_tg_token": "legacy_token",
            "sentinel_wa_apikey": "legacy_key",
            "_enc_tg_token": "enc_val",
        }

        with patch("streamlit.session_state", fake_session):
            clear_investigator_session()

            # Store for user_id_1 should be purged
            self.assertNotIn(self.user_id_1, _ALERT_SESSION_STORE)
            # Session state should be empty
            self.assertEqual(len(fake_session), 0)


if __name__ == "__main__":
    unittest.main()
