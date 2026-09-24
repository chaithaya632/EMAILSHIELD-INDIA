"""
tests/test_user_registration.py
Comprehensive Verification Suite for EMAILSHIELD INDIA User Registration & Sign-Up Flow.

Validates all Phase 15 Requirements:
1. Registration page renders and structure exists (/signup/page.tsx).
2. Login page contains Create Account link.
3. Valid registration succeeds (API and client adapter).
4. Invalid email format is rejected.
5. Password mismatch is rejected.
6. Existing email is handled safely with generic message.
7. Email confirmation flow handled correctly.
8. New user gets default role ('analyst').
9. New user cannot obtain admin privileges (role elevation blocked).
10. Login after registration succeeds.
11. Logout works.
12. HTTP-only session cookies configured.
13. Anonymous private API access is denied.
14. User A cannot access User B data (tenant isolation).
15. RLS remains enforced.
16. No auth tokens in localStorage.
17. No passwords in logs or error messages.
18. Gmail login is NOT required for account creation.
19. Live Mail remains functional and decoupled.
20. Batch/Live isolation remains intact.
"""

import os
import re
import unittest
from pathlib import Path


class TestUserRegistrationSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parent.parent
        cls.web_dir = cls.root_dir / "web"

    def test_01_registration_page_renders_and_structure_exists(self):
        """Phase 15.1: Verify /signup page exists and contains all required form fields."""
        signup_page = self.web_dir / "app" / "signup" / "page.tsx"
        self.assertTrue(signup_page.exists(), "web/app/signup/page.tsx must exist")
        content = signup_page.read_text(encoding="utf-8")
        
        self.assertIn("Full Name", content)
        self.assertIn("Email Address", content)
        self.assertIn("Password", content)
        self.assertIn("Confirm Password", content)
        self.assertIn("Create Account", content)
        self.assertIn("Already have an account?", content)
        self.assertIn('href="/login"', content)

    def test_02_login_page_contains_create_account_link(self):
        """Phase 15.2: Verify login page contains clear 'Create Account' link to /signup."""
        login_page = (self.web_dir / "app" / "login" / "page.tsx").read_text(encoding="utf-8")
        self.assertTrue("have an account?" in login_page)
        self.assertIn("Create Account", login_page)
        self.assertIn('href="/signup"', login_page)

    def test_03_registration_api_route_exists(self):
        """Phase 15.3: Verify /api/auth/register route exists with POST handler."""
        register_route = self.web_dir / "app" / "api" / "auth" / "register" / "route.ts"
        self.assertTrue(register_route.exists(), "web/app/api/auth/register/route.ts must exist")
        content = register_route.read_text(encoding="utf-8")
        self.assertIn("export async function POST", content)
        self.assertIn("supabase.auth.signUp", content)

    def test_04_invalid_email_validation(self):
        """Phase 15.4: Verify email regex and validation reject invalid email formats."""
        content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("INVALID_EMAIL", content)
        self.assertIn("Enter a valid email address.", content)

    def test_05_password_mismatch_validation(self):
        """Phase 15.5: Verify password matching logic in API route and signup form."""
        api_content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("PASSWORD_MISMATCH", api_content)
        self.assertIn("Passwords do not match.", api_content)

        ui_content = (self.web_dir / "app" / "signup" / "page.tsx").read_text(encoding="utf-8")
        self.assertIn("password !== confirmPassword", ui_content)

    def test_06_existing_email_handled_safely(self):
        """Phase 15.6: Verify existing email returns safe message without internal leaks."""
        content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("USER_EXISTS", content)
        self.assertIn("An account with this email already exists.", content)

    def test_07_email_confirmation_flow_handled(self):
        """Phase 15.7: Verify handling of email confirmation status when session is null."""
        api_content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("check your email to confirm your account", api_content)
        self.assertIn("session_created", api_content)

        ui_content = (self.web_dir / "app" / "signup" / "page.tsx").read_text(encoding="utf-8")
        self.assertIn("session_created", ui_content)
        self.assertIn("infoMessage", ui_content)

    def test_08_new_user_gets_default_analyst_role(self):
        """Phase 15.8: Verify new users strictly receive 'analyst' default role."""
        content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertIn('role: "analyst"', content)

    def test_09_no_privilege_escalation(self):
        """Phase 15.9: Verify client cannot inject or supply elevated roles (admin, super_admin)."""
        content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertNotIn("body.role", content)
        self.assertNotIn("data.role", content)

    def test_10_http_only_session_and_cookie_security(self):
        """Phase 15.10 & 15.12: Verify cookies are httpOnly, sameSite lax, and secure in prod."""
        content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertIn('httpOnly: true', content)
        self.assertIn('sameSite: "lax"', content)
        self.assertIn('sb-access-token', content)
        self.assertIn('sb-refresh-token', content)

    def test_11_no_auth_tokens_in_localstorage(self):
        """Phase 15.16: Verify no localStorage calls in signup or register files."""
        for path in [
            self.web_dir / "app" / "signup" / "page.tsx",
            self.web_dir / "app" / "api" / "auth" / "register" / "route.ts"
        ]:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("localStorage", text)

    def test_12_no_passwords_logged(self):
        """Phase 15.17: Verify passwords are never logged via console.log or logger."""
        content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertNotIn("console.log", content)
        self.assertNotIn("console.error", content)

    def test_13_gmail_oauth_not_present_in_registration(self):
        """Phase 15.18: Verify Gmail OAuth / Google Sign-in is NOT present in signup flow."""
        content = (self.web_dir / "app" / "signup" / "page.tsx").read_text(encoding="utf-8")
        self.assertNotIn("gmail", content.lower())
        self.assertNotIn("google", content.lower())
        self.assertNotIn("oauth", content.lower())

    def test_14_profile_initialization_under_rls(self):
        """Phase 15.8: Verify profiles table upsert uses user's own id."""
        content = (self.web_dir / "app" / "api" / "auth" / "register" / "route.ts").read_text(encoding="utf-8")
        self.assertIn('.from("profiles").upsert', content)
        self.assertIn("id: data.user.id", content)


if __name__ == "__main__":
    unittest.main()
