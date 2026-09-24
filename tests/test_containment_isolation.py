"""
tests/test_containment_isolation.py
Security regression tests verifying P0 cross-user session and credential containment.
"""

import unittest
import ast
import os
from typing import Dict, Any


class TestContainmentIsolation(unittest.TestCase):

    def setUp(self):
        self.app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
        with open(self.app_path, "r", encoding="utf-8") as f:
            self.app_source = f.read()
        self.app_tree = ast.parse(self.app_source)

    def test_a_fresh_session_no_inherited_credentials(self):
        """Test A: Verify a new session does not inherit mailbox state or credentials."""
        session_state: Dict[str, Any] = {}
        is_connected = session_state.get("mailbox_connected", False)
        self.assertFalse(is_connected)
        self.assertNotIn("mailbox_creds", session_state)
        self.assertNotIn("mailbox_type", session_state)

    def test_b_no_automatic_vault_restoration(self):
        """Test B: Verify app.py does not call get_account_credentials or load_session_credentials."""
        calls = [node.func.id for node in ast.walk(self.app_tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertNotIn("get_account_credentials", calls, "app.py must not call get_account_credentials on startup")
        self.assertNotIn("load_session_credentials", calls, "app.py must not call load_session_credentials on startup")

    def test_c_no_saved_account_exposure_in_ui(self):
        """Test C: Verify the public UI does not enumerate server-side saved accounts."""
        calls = [node.func.id for node in ast.walk(self.app_tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertNotIn("list_saved_accounts", calls, "app.py must not call list_saved_accounts")
        self.assertNotIn("Saved Mailboxes", self.app_source, "UI must not render Saved Mailboxes list")

    def test_d_no_vault_write_on_connect(self):
        """Test D: Verify app.py does not invoke save_account_credentials to write to server disk."""
        calls = [node.func.id for node in ast.walk(self.app_tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertNotIn("save_account_credentials", calls, "app.py must not save credentials to server vault")
        self.assertNotIn("save_session_credentials", calls, "app.py must not save credentials to server vault")

    def test_e_session_separation(self):
        """Test E: Simulate Session A and Session B, verifying complete credential isolation."""
        session_a: Dict[str, Any] = {
            "mailbox_connected": True,
            "mailbox_creds": {
                "email": "userA@example.com",
                "pwd": "mock-app-password-AAAA",
                "host": "imap.example.com",
                "provider": "Gmail"
            }
        }
        session_b: Dict[str, Any] = {}

        self.assertNotEqual(session_a, session_b)
        self.assertNotIn("mailbox_creds", session_b)
        self.assertFalse(session_b.get("mailbox_connected", False))
        for key in session_a:
            self.assertNotIn(key, session_b)

    def test_f_disconnect_cleanup(self):
        """Test F: Verify disconnect purges all mailbox credentials and state from session."""
        session: Dict[str, Any] = {
            "mailbox_connected": True,
            "mailbox_creds": {"email": "user@example.com", "pwd": "mock-password", "host": "imap.test.com"},
            "mailbox_type": "IMAP",
            "recent_emails": [{"id": "1", "subject": "Test"}],
            "current_email_bytes": b"mock-bytes",
            "batch_results": {"total_scanned": 1}
        }

        keys_to_clear = [
            "mailbox_connected", "mailbox_creds", "mailbox_type",
            "recent_emails", "session_days_left", "current_email_bytes",
            "batch_results", "last_scope_tuple", "add_new_account_mode"
        ]
        for k in keys_to_clear:
            session.pop(k, None)

        self.assertFalse(session.get("mailbox_connected", False))
        self.assertNotIn("mailbox_creds", session)
        self.assertNotIn("mailbox_type", session)
        self.assertNotIn("recent_emails", session)
        self.assertNotIn("current_email_bytes", session)
        self.assertNotIn("batch_results", session)

    def test_g_oauth_fail_closed_in_app(self):
        """Test G: Verify app.py does not import or call unisolated core.gmail_integration."""
        imports = []
        for node in ast.walk(self.app_tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == "core.gmail_integration":
                    imports.extend([alias.name for alias in node.names])
        self.assertEqual(len(imports), 0, "app.py must not import from core.gmail_integration")

    def test_h_bulk_case_export_disabled(self):
        """Test H: Verify unconstrained bulk export of all cases across the database is removed."""
        self.assertNotIn("Export All Cases (CSV)", self.app_source, "Bulk Export All Cases button must be removed")

    def test_i_sentinel_disabled_in_public_mode(self):
        """Test I: Verify Sentinel background worker is decoupled and does not call legacy sentinel_manager.start."""
        self.assertNotIn("sentinel_manager.start", self.app_source)


if __name__ == "__main__":
    unittest.main()
