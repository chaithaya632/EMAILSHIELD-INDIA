"""
tests/test_alerts_view_lifecycle.py
Unit tests for views/alerts.py connection state transitions, credential hiding,
and validation lifecycle for Telegram and WhatsApp channels.
"""

import unittest
from unittest.mock import patch, MagicMock
import views.alerts as alerts
from core.alert_session import clear_alert_session


class TestAlertsViewLifecycle(unittest.TestCase):
    def setUp(self):
        clear_alert_session()
        self.user_id = "test_user_alerts_view"
        self.mock_client = MagicMock()
        self.worker_id = "worker-uuid-1234"
        self.ctx = {
            "worker_rec": {"id": self.worker_id},
        }

    def _setup_mock_st(self, mock_st):
        mock_st.session_state = {}
        mock_st.tabs.side_effect = lambda tabs: [MagicMock() for _ in tabs]
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]

    def tearDown(self):
        clear_alert_session()

    @patch("views.alerts.is_authorized_caller", return_value=True)
    @patch("views.alerts.st")
    def test_telegram_not_active_renders_inputs_and_badge(self, mock_st, mock_auth):
        """When not active, renders NOT CONNECTED badge, credential inputs, and test/save buttons."""
        self._setup_mock_st(mock_st)

        with patch("views.alerts.get_telegram_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}), \
             patch("views.alerts.get_whatsapp_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}):
            
            alerts.render(self.user_id, self.mock_client, **self.ctx)

            # Check text inputs rendered with proper keys and password masking
            text_input_calls = [c[1] for c in mock_st.text_input.call_args_list]
            keys_rendered = [c.get("key") for c in text_input_calls]
            self.assertIn("tg_cfg_tok", keys_rendered)
            self.assertIn("tg_cfg_chat", keys_rendered)

            # Bot token must use type="password"
            for c in text_input_calls:
                if c.get("key") == "tg_cfg_tok":
                    self.assertEqual(c.get("type"), "password")

            # Buttons rendered with exact keys
            button_calls = [c[1] for c in mock_st.button.call_args_list]
            btn_keys = [c.get("key") for c in button_calls]
            self.assertIn("btn_test_tg_page", btn_keys)
            self.assertIn("btn_save_tg_page", btn_keys)

    @patch("views.alerts.is_authorized_caller", return_value=True)
    @patch("views.alerts.st")
    def test_telegram_active_hides_credentials_and_renders_active_controls(self, mock_st, mock_auth):
        """When active, inputs are hidden, ACTIVE badge is rendered with test and disconnect buttons."""
        self._setup_mock_st(mock_st)

        with patch("views.alerts.get_telegram_connection", return_value={
            "connected": True,
            "status": "ACTIVE",
            "masked_destination": "••••••1234",
            "bot_username": "@SecurityBot"
        }), patch("views.alerts.get_whatsapp_connection", return_value={
            "connected": True,
            "status": "ACTIVE",
            "masked_destination": "+91••••••••10"
        }):
            alerts.render(self.user_id, self.mock_client, **self.ctx)

            # Credential inputs MUST NOT be rendered
            text_input_calls = [c[1] for c in mock_st.text_input.call_args_list]
            keys_rendered = [c.get("key") for c in text_input_calls]
            self.assertNotIn("tg_cfg_tok", keys_rendered)
            self.assertNotIn("tg_cfg_chat", keys_rendered)
            self.assertNotIn("wa_cfg_ph", keys_rendered)
            self.assertNotIn("wa_cfg_key", keys_rendered)

            # Connected action buttons rendered
            button_calls = [c[1] for c in mock_st.button.call_args_list]
            btn_keys = [c.get("key") for c in button_calls]
            self.assertIn("btn_test_tg_connected", btn_keys)
            self.assertIn("btn_disc_tg", btn_keys)
            self.assertIn("btn_test_wa_connected", btn_keys)
            self.assertIn("btn_disc_wa", btn_keys)

    @patch("views.alerts.is_authorized_caller", return_value=True)
    @patch("views.alerts.save_user_alert_metadata")
    @patch("views.alerts.save_telegram_connection")
    @patch("views.alerts.test_telegram_alert_delivery")
    @patch("views.alerts.st")
    def test_telegram_save_flow_on_delivered(self, mock_st, mock_test_delivery, mock_save_conn, mock_save_meta, mock_auth):
        """When Telegram test alert delivers successfully, connection is saved and rerun is triggered."""
        self._setup_mock_st(mock_st)
        mock_st.text_input.side_effect = lambda label, **kwargs: (
            "123456789:ABCdefGHIjklmnoPQRstuvwxYZ123456789" if kwargs.get("key") == "tg_cfg_tok"
            else "987654321" if kwargs.get("key") == "tg_cfg_chat"
            else ""
        )
        mock_st.button.side_effect = lambda label, **kwargs: kwargs.get("key") == "btn_save_tg_page"
        mock_test_delivery.return_value = {
            "delivery_status": "DELIVERED",
            "bot_username": "@SecBot",
            "details": "Delivered successfully"
        }

        with patch("views.alerts.get_telegram_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}), \
             patch("views.alerts.get_whatsapp_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}):
            alerts.render(self.user_id, self.mock_client, **self.ctx)

            mock_save_conn.assert_called_once_with(
                self.user_id,
                "123456789:ABCdefGHIjklmnoPQRstuvwxYZ123456789",
                "987654321",
                bot_username="@SecBot"
            )
            mock_save_meta.assert_called_once_with(
                self.user_id,
                self.worker_id,
                "telegram",
                "987654321",
                is_enabled=True,
                high_risk_only=True,
                client=self.mock_client
            )
            mock_st.rerun.assert_called_once()

    @patch("views.alerts.is_authorized_caller", return_value=True)
    @patch("views.alerts.set_telegram_status")
    @patch("views.alerts.error_card")
    @patch("views.alerts.st")
    def test_telegram_validation_failure_sets_status(self, mock_st, mock_err, mock_set_status, mock_auth):
        """Validation failures show error_card and set CONNECTION_FAILED status."""
        self._setup_mock_st(mock_st)
        mock_st.text_input.side_effect = lambda label, **kwargs: ""
        mock_st.button.side_effect = lambda label, **kwargs: kwargs.get("key") == "btn_test_tg_page"

        with patch("views.alerts.get_telegram_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}), \
             patch("views.alerts.get_whatsapp_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}):
            alerts.render(self.user_id, self.mock_client, **self.ctx)

            mock_set_status.assert_called_once_with(self.user_id, "CONNECTION_FAILED")
            mock_err.assert_called_once()
            mock_st.rerun.assert_not_called()

    @patch("views.alerts.is_authorized_caller", return_value=True)
    @patch("views.alerts.save_user_alert_metadata")
    @patch("views.alerts.disconnect_telegram")
    @patch("views.alerts.st")
    def test_telegram_disconnect_flow(self, mock_st, mock_disc, mock_save_meta, mock_auth):
        """Disconnecting Telegram calls disconnect_telegram, disables metadata, and reruns."""
        self._setup_mock_st(mock_st)
        mock_st.button.side_effect = lambda label, **kwargs: kwargs.get("key") == "btn_disc_tg"

        with patch("views.alerts.get_telegram_connection", return_value={"connected": True, "status": "ACTIVE", "masked_destination": "••••••1234"}), \
             patch("views.alerts.get_whatsapp_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}):
            alerts.render(self.user_id, self.mock_client, **self.ctx)

            mock_disc.assert_called_once_with(self.user_id)
            mock_save_meta.assert_called_once_with(
                self.user_id,
                self.worker_id,
                "telegram",
                "",
                is_enabled=False,
                high_risk_only=True,
                client=self.mock_client
            )
            mock_st.rerun.assert_called_once()

    @patch("views.alerts.is_authorized_caller", return_value=True)
    @patch("views.alerts.save_user_alert_metadata")
    @patch("views.alerts.save_whatsapp_connection")
    @patch("views.alerts.test_whatsapp_alert_delivery")
    @patch("views.alerts.st")
    def test_whatsapp_save_flow_on_delivered(self, mock_st, mock_test_delivery, mock_save_conn, mock_save_meta, mock_auth):
        """When WhatsApp test delivery succeeds, connection is saved and metadata recorded."""
        self._setup_mock_st(mock_st)
        mock_st.text_input.side_effect = lambda label, **kwargs: (
            "+919876543210" if kwargs.get("key") == "wa_cfg_ph"
            else "apikey1234" if kwargs.get("key") == "wa_cfg_key"
            else ""
        )
        mock_st.button.side_effect = lambda label, **kwargs: kwargs.get("key") == "btn_save_wa_page"
        mock_test_delivery.return_value = {
            "delivery_status": "DELIVERED",
            "details": "Delivered successfully"
        }

        with patch("views.alerts.get_telegram_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}), \
             patch("views.alerts.get_whatsapp_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}):
            alerts.render(self.user_id, self.mock_client, **self.ctx)

            mock_save_conn.assert_called_once_with(self.user_id, "+919876543210", "apikey1234")
            mock_save_meta.assert_called_once_with(
                self.user_id,
                self.worker_id,
                "whatsapp",
                "+919876543210",
                is_enabled=True,
                high_risk_only=True,
                client=self.mock_client
            )
            mock_st.rerun.assert_called_once()

    @patch("views.alerts.is_authorized_caller", return_value=True)
    @patch("views.alerts.save_user_alert_metadata")
    @patch("views.alerts.disconnect_whatsapp")
    @patch("views.alerts.st")
    def test_whatsapp_disconnect_flow(self, mock_st, mock_disc, mock_save_meta, mock_auth):
        """Disconnecting WhatsApp calls disconnect_whatsapp, disables metadata, and reruns."""
        self._setup_mock_st(mock_st)
        mock_st.button.side_effect = lambda label, **kwargs: kwargs.get("key") == "btn_disc_wa"

        with patch("views.alerts.get_telegram_connection", return_value={"connected": False, "status": "NOT_CONNECTED", "masked_destination": ""}), \
             patch("views.alerts.get_whatsapp_connection", return_value={"connected": True, "status": "ACTIVE", "masked_destination": "+91••••••••10"}):
            alerts.render(self.user_id, self.mock_client, **self.ctx)

            mock_disc.assert_called_once_with(self.user_id)
            mock_save_meta.assert_called_once_with(
                self.user_id,
                self.worker_id,
                "whatsapp",
                "",
                is_enabled=False,
                high_risk_only=True,
                client=self.mock_client
            )
            mock_st.rerun.assert_called_once()


if __name__ == "__main__":
    unittest.main()
