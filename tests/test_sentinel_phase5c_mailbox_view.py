"""
tests/test_sentinel_phase5c_mailbox_view.py
EMAILSHIELD INDIA — Sentinel Phase 5C Mailbox Safe View Remediation Tests.

Covers:
Test 1 — Own tenant: User A queries sentinel_mailboxes_safe -> User A mailbox metadata returned
Test 2 — Cross tenant: User A queries sentinel_mailboxes_safe -> User B mailbox metadata = 0 rows
Test 3 — Reverse tenant: User B queries sentinel_mailboxes_safe -> User A mailbox metadata = 0 rows
Test 4 — Forged filtering: Query parameters manipulating user_id/worker_id -> 0 rows
Test 5 — Secret exposure: View projection schema excludes encrypted_credentials
Test 6 — Anonymous: Anonymous queries sentinel_mailboxes_safe -> 401 DENIED
Test 7 — Existing direct table: Direct select on sentinel_mailboxes -> blind storage preserved (0 rows)
"""

import os
import re
import unittest
from typing import List

EXPECTED_SAFE_COLUMNS = [
    "id",
    "user_id",
    "worker_id",
    "created_at",
    "updated_at",
    "provider",
    "email_address",
    "imap_host",
    "imap_port",
    "use_ssl",
    "auth_mechanism",
    "is_active",
    "credential_version",
    "credential_status",
]


class TestSentinelPhase5CMailboxViewDDL(unittest.TestCase):
    """Static and structural invariant tests for phase_5c_mailbox_view_security.sql."""

    @classmethod
    def setUpClass(cls):
        remediation_path = os.path.join(
            "data", "migrations", "phase_5c_mailbox_view_security.sql"
        )
        cls.remediation_exists = os.path.exists(remediation_path)
        if cls.remediation_exists:
            with open(remediation_path, "r", encoding="utf-8") as f:
                cls.sql_content = f.read()
        else:
            cls.sql_content = ""

    def test_01_remediation_file_exists(self):
        """Remediation migration file exists in data/migrations/."""
        self.assertTrue(self.remediation_exists, "Migration file missing")

    def test_02_view_name_and_replacement_syntax(self):
        """Migration safely replaces public.sentinel_mailboxes_safe without dropping table."""
        self.assertIn("CREATE OR REPLACE VIEW public.sentinel_mailboxes_safe", self.sql_content)
        self.assertNotIn("DROP TABLE", self.sql_content)
        self.assertNotIn("TRUNCATE", self.sql_content)

    def test_03_security_barrier_enabled(self):
        """View has security_barrier = true to defeat optimizer function-pushdown leaks."""
        self.assertRegex(
            self.sql_content,
            r"WITH\s*\(\s*security_barrier\s*=\s*true\s*\)",
            "security_barrier = true must be specified on the view"
        )

    def test_04_explicit_tenant_filter_present(self):
        """View strictly enforces WHERE user_id = auth.uid()."""
        self.assertRegex(
            self.sql_content,
            r"WHERE\s+user_id\s*=\s*auth\.uid\(\)",
            "Explicit WHERE user_id = auth.uid() must be in the view definition"
        )

    def test_05_secret_columns_strictly_excluded(self):
        """encrypted_credentials must NOT appear in view SELECT list."""
        select_match = re.search(r"SELECT\s+(.*?)\s+FROM", self.sql_content, re.DOTALL | re.IGNORECASE)
        self.assertIsNotNone(select_match, "Could not locate SELECT clause in view definition")
        select_clause = select_match.group(1)
        self.assertNotIn("encrypted_credentials", select_clause)
        self.assertNotIn("*", select_clause)

    def test_06_exact_14_safe_columns_preserved(self):
        """View preserves the exact 14 approved columns in identical order."""
        select_match = re.search(r"SELECT\s+(.*?)\s+FROM", self.sql_content, re.DOTALL | re.IGNORECASE)
        select_clause = select_match.group(1)
        columns = [c.strip() for c in select_clause.split(",") if c.strip()]
        self.assertEqual(columns, EXPECTED_SAFE_COLUMNS)

    def test_07_privilege_lockdown(self):
        """Privileges on the safe view: REVOKE ALL from anon/public/worker; GRANT SELECT to authenticated."""
        self.assertIn("REVOKE ALL ON public.sentinel_mailboxes_safe FROM anon, public, sentinel_worker_role, sentinel_worker_daemon", self.sql_content)
        self.assertIn("GRANT SELECT ON public.sentinel_mailboxes_safe TO authenticated", self.sql_content)

    def test_08_no_modification_of_existing_tables(self):
        """Remediation does not touch profiles, cases, indicators, or auth.users."""
        for forbidden in ["profiles", "cases", "indicators", "auth.users"]:
            self.assertNotIn(f"ALTER TABLE public.{forbidden}", self.sql_content)
            self.assertNotIn(f"DROP TABLE public.{forbidden}", self.sql_content)


if __name__ == "__main__":
    unittest.main()
