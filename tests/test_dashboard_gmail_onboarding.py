import os
import ast
import pytest
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
VIEWS_DIR = BASE_DIR / "views"
DASHBOARD_FILE = VIEWS_DIR / "dashboard.py"
APP_FILE = BASE_DIR / "app.py"


class TestDashboardGmailOnboarding(unittest.TestCase):

    def setUp(self):
        # Read files for static analysis
        if DASHBOARD_FILE.exists():
            with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
                self.dashboard_code = f.read()
            self.dashboard_ast = ast.parse(self.dashboard_code)
        else:
            self.dashboard_code = ""
            self.dashboard_ast = ast.parse("")

        if APP_FILE.exists():
            with open(APP_FILE, "r", encoding="utf-8") as f:
                self.app_code = f.read()
        else:
            self.app_code = ""

    def test_unconnected_user_sees_gmail_onboarding_card(self):
        """
        1. Inspects views/dashboard.py AST/source to ensure:
           - Prominent card with `Connect your Gmail` is displayed when `not mailbox_rec or not mailbox_rec.get("email_address")`.
           - Input field `Gmail address` is present.
           - Input field `Gmail App Password` is present.
        """
        # We look for simple string representations in the file
        self.assertIn("Connect your Gmail", self.dashboard_code, "Onboarding card title not found.")
        self.assertIn("Gmail address", self.dashboard_code, "Input field Gmail address not found.")
        self.assertIn("Gmail App Password", self.dashboard_code, "Input field Gmail App Password not found.")
        self.assertIn("not mailbox_rec", self.dashboard_code, "Condition for unconnected user not found.")

    def test_normal_gmail_password_never_requested(self):
        """
        2. Verifies the string `Gmail Password` (without App) is NOT used as an input label in views/dashboard.py.
           Verifies the explanation `Never enter your normal Google account password here` is present.
        """
        # Ensure 'Gmail Password' without 'App' is not the literal string, though 'Gmail App Password' has it.
        # Check that it asks specifically to not use the normal password
        self.assertIn("Never enter your normal Google account password here", self.dashboard_code,
                      "Missing warning about normal Google account password.")
        
        # A simple check to ensure no raw request for Gmail Password.
        lines = self.dashboard_code.splitlines()
        for line in lines:
            if "Gmail Password" in line and "App" not in line:
                # Need to be careful here depending on context, let's just fail if found in a literal label context
                if "text_input(" in line or "label=" in line:
                    self.fail("Normal 'Gmail Password' requested without specifying 'App'.")

    def test_app_password_input_is_password_type(self):
        """
        3. Verifies that `Gmail App Password` input uses `type=\"password\"`.
        """
        self.assertIn('type="password"', self.dashboard_code.replace("'", '"'), 
                      "App password input must use type='password'")
        # Ensure it's used with the App password input
        # We can look for text_input near type="password" or type='password'
        self.assertTrue('type="password"' in self.dashboard_code or "type='password'" in self.dashboard_code)

    def test_app_password_guide_and_steps_present(self):
        """
        4. Verifies the expander `How do I get an App Password?` contains instructions 
           for 2-Step Verification, Google Account security link, and never sharing the App Password.
        """
        self.assertIn("How do I get an App Password?", self.dashboard_code, "Expander for App Password missing.")
        self.assertIn("2-Step Verification", self.dashboard_code, "Instructions for 2-Step Verification missing.")
        self.assertIn("Google Account security", self.dashboard_code, "Google Account security link/instructions missing.")
        self.assertIn("never share", self.dashboard_code.lower(), "Warning to never share the App Password missing.")

    def test_connected_user_view_renders_mailbox_and_controls(self):
        """
        5. Verifies that when a mailbox is present:
           - Renders `Gmail Connected`
           - Uses `mask_email_address`
           - Provides `Pause`, `Resume`, `Deactivate` lifecycle controls.
           - Provides `Manage Mailbox` shortcut to Settings.
        """
        self.assertIn("Gmail Connected", self.dashboard_code, "Connected state rendering missing.")
        self.assertIn("mask_email_address", self.dashboard_code, "mask_email_address function not used.")
        self.assertIn("Pause", self.dashboard_code, "Pause control missing.")
        self.assertIn("Resume", self.dashboard_code, "Resume control missing.")
        self.assertIn("Deactivate", self.dashboard_code, "Deactivate control missing.")
        self.assertIn("Manage Mailbox", self.dashboard_code, "Manage Mailbox shortcut missing.")

    def test_safe_error_mapping_and_no_credential_leak(self):
        """
        6. Verifies that views/dashboard.py handles connection errors cleanly using safe error cards 
           and does not print raw exceptions or password strings.
        """
        self.assertIn("error", self.dashboard_code.lower(), "No error handling found.")
        # Ensure no `print(e)` or `st.error(e)` which could leak raw exceptions
        self.assertNotIn("st.error(e)", self.dashboard_code)
        self.assertNotIn("st.write(e)", self.dashboard_code)
        self.assertNotIn("print(password)", self.dashboard_code)
        self.assertNotIn("st.write(password)", self.dashboard_code)

    def test_batch_and_single_shortcuts_present(self):
        """
        7. Verifies shortcuts to Analyze Email and Batch Analysis exist.
        """
        self.assertIn("Analyze Email", self.dashboard_code, "Shortcut to Analyze Email missing.")
        self.assertIn("Batch Analysis", self.dashboard_code, "Shortcut to Batch Analysis missing.")

    def test_worker_private_key_not_in_dashboard(self):
        """
        8. Asserts `SENTINEL_WORKER_PRIVATE_KEY` is completely absent from views/dashboard.py and app.py.
        """
        self.assertNotIn("SENTINEL_WORKER_PRIVATE_KEY", self.dashboard_code, 
                         "SENTINEL_WORKER_PRIVATE_KEY found in views/dashboard.py")
        self.assertNotIn("SENTINEL_WORKER_PRIVATE_KEY", self.app_code, 
                         "SENTINEL_WORKER_PRIVATE_KEY found in app.py")

    def test_worker_foreign_key_safety(self):
        """
        9. Verifies that views/dashboard.py resolves the authoritative worker record
           via `upsert_user_worker` / `get_user_worker` before connecting the mailbox,
           preventing `fk_sentinel_mailbox_worker` foreign key constraint violation.
        """
        self.assertIn("upsert_user_worker", self.dashboard_code,
                      "views/dashboard.py must use upsert_user_worker to ensure worker record exists.")
        
        # Also verify core/sentinel_control.py handles worker resolution
        from core.sentinel_control import connect_user_sentinel_mailbox
        import inspect
        sig = inspect.signature(connect_user_sentinel_mailbox)
        self.assertIn("worker_id", sig.parameters)


if __name__ == "__main__":
    unittest.main()
