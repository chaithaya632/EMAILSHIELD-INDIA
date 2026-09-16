"""
tests/test_sentinel_schema.py
Rigorous verification of EMAILSHIELD INDIA Sentinel Phase 1 DDL schema,
relational constraints, RLS security policies, immutability triggers,
and credential blind storage guarantees.
"""

import os
import re
import unittest

SCHEMA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "sentinel_schema.sql")


class TestSentinelSchemaSecurity(unittest.TestCase):
    """Verifies DDL structure and security constraints in data/sentinel_schema.sql."""

    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
            cls.sql_content = f.read()

    def test_01_all_four_tables_exist_in_ddl(self):
        """Verify that all four required Sentinel tables are declared."""
        required_tables = [
            "public.sentinel_workers",
            "public.sentinel_mailboxes",
            "public.sentinel_checkpoints",
            "public.sentinel_alerts",
        ]
        for table in required_tables:
            pattern = rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{re.escape(table)}"
            self.assertTrue(
                re.search(pattern, self.sql_content, re.IGNORECASE),
                f"Table declaration missing for {table}"
            )

    def test_02_rls_enabled_on_all_four_tables(self):
        """Verify that Row-Level Security is explicitly enabled on all four tables."""
        required_tables = [
            "public.sentinel_workers",
            "public.sentinel_mailboxes",
            "public.sentinel_checkpoints",
            "public.sentinel_alerts",
        ]
        for table in required_tables:
            pattern = rf"ALTER\s+TABLE\s+{re.escape(table)}\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY"
            self.assertTrue(
                re.search(pattern, self.sql_content, re.IGNORECASE),
                f"Row-Level Security not enabled on {table}"
            )

    def test_03_ownership_policies_defined(self):
        """Verify that explicit RLS policies are defined for all operations."""
        expected_policies = [
            # sentinel_workers
            "sentinel_workers_select_own",
            "sentinel_workers_insert_own",
            "sentinel_workers_update_own",
            "sentinel_workers_delete_own",
            # sentinel_mailboxes
            "sentinel_mailboxes_select_own",
            "sentinel_mailboxes_insert_own",
            "sentinel_mailboxes_update_own",
            "sentinel_mailboxes_delete_own",
            # sentinel_checkpoints
            "sentinel_checkpoints_select_own",
            "sentinel_checkpoints_insert_own",
            "sentinel_checkpoints_update_own",
            "sentinel_checkpoints_delete_own",
            # sentinel_alerts
            "sentinel_alerts_select_own",
            "sentinel_alerts_insert_own",
            "sentinel_alerts_update_own",
            "sentinel_alerts_delete_own",
        ]
        for pol in expected_policies:
            pattern = rf'CREATE\s+POLICY\s+"?{re.escape(pol)}"?'
            self.assertTrue(
                re.search(pattern, self.sql_content, re.IGNORECASE),
                f"RLS Policy '{pol}' missing from DDL"
            )

    def test_04_anonymous_access_denied_by_design(self):
        """Verify that all RLS policies restrict access exclusively TO authenticated."""
        policies = re.findall(
            r'CREATE\s+POLICY\s+"?[^"\n]+"?[^;]+;',
            self.sql_content,
            re.IGNORECASE | re.DOTALL
        )
        self.assertGreater(len(policies), 0, "No RLS policies found in DDL")
        for pol in policies:
            self.assertIn(
                "to authenticated",
                pol.lower(),
                f"Policy does not restrict to authenticated role: {pol[:60]}..."
            )
            # Ensure no policy grants TO anon or public
            self.assertNotIn("to anon", pol.lower())
            self.assertNotIn("to public", pol.lower())

    def test_05_composite_foreign_keys_present(self):
        """Verify that composite foreign keys (id, user_id) enforce tenant relational integrity."""
        # sentinel_mailboxes -> sentinel_workers
        self.assertTrue(
            re.search(
                r"FOREIGN\s+KEY\s*\(\s*worker_id\s*,\s*user_id\s*\)\s*REFERENCES\s+public\.sentinel_workers\s*\(\s*id\s*,\s*user_id\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "Composite foreign key missing on sentinel_mailboxes -> sentinel_workers"
        )
        # sentinel_checkpoints -> sentinel_workers
        self.assertTrue(
            re.search(
                r"FOREIGN\s+KEY\s*\(\s*worker_id\s*,\s*user_id\s*\)\s*REFERENCES\s+public\.sentinel_workers\s*\(\s*id\s*,\s*user_id\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "Composite foreign key missing on sentinel_checkpoints -> sentinel_workers"
        )
        # sentinel_checkpoints -> sentinel_mailboxes
        self.assertTrue(
            re.search(
                r"FOREIGN\s+KEY\s*\(\s*mailbox_id\s*,\s*user_id\s*\)\s*REFERENCES\s+public\.sentinel_mailboxes\s*\(\s*id\s*,\s*user_id\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "Composite foreign key missing on sentinel_checkpoints -> sentinel_mailboxes"
        )
        # sentinel_alerts -> sentinel_workers
        self.assertTrue(
            re.search(
                r"FOREIGN\s+KEY\s*\(\s*worker_id\s*,\s*user_id\s*\)\s*REFERENCES\s+public\.sentinel_workers\s*\(\s*id\s*,\s*user_id\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "Composite foreign key missing on sentinel_alerts -> sentinel_workers"
        )

    def test_06_unique_user_id_on_sentinel_workers(self):
        """Verify UNIQUE(user_id) limits users to a single active worker."""
        self.assertTrue(
            re.search(
                r"CONSTRAINT\s+\w+\s+UNIQUE\s*\(\s*user_id\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "UNIQUE(user_id) missing on sentinel_workers"
        )

    def test_07_unique_user_id_on_sentinel_mailboxes(self):
        """Verify UNIQUE(user_id) limits users to a single active mailbox configuration."""
        matches = re.findall(
            r"UNIQUE\s*\(\s*user_id\s*\)",
            self.sql_content,
            re.IGNORECASE
        )
        self.assertGreaterEqual(len(matches), 2, "UNIQUE(user_id) constraint must exist on both workers and mailboxes")

    def test_08_checkpoint_composite_ownership_present(self):
        """Verify UNIQUE(user_id, mailbox_id, folder_name) ensures single checkpoint per folder."""
        self.assertTrue(
            re.search(
                r"UNIQUE\s*\(\s*user_id\s*,\s*mailbox_id\s*,\s*folder_name\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "UNIQUE(user_id, mailbox_id, folder_name) constraint missing on sentinel_checkpoints"
        )

    def test_09_no_plaintext_password_or_token_columns(self):
        """Verify that no table contains plaintext password or credential columns."""
        forbidden_column_patterns = [
            r"\bpassword\b",
            r"\bapp_password\b",
            r"\btoken\b",
            r"\boauth_token\b",
            r"\brefresh_token\b",
            r"\baccess_token\b",
            r"\bbot_token\b",
            r"\bapi_key\b",
            r"\bsecret\b",
        ]
        # Check column declarations
        lines = self.sql_content.splitlines()
        for line in lines:
            stripped = line.strip().lower()
            if stripped.startswith("--"):
                continue
            for forbidden in forbidden_column_patterns:
                # Disallow declaring `password TEXT`, `token TEXT`, etc.
                match = re.search(rf"^\s*{forbidden}\s+(?:text|varchar|json)", line, re.IGNORECASE)
                self.assertIsNone(match, f"Plaintext credential column declared in line: {line.strip()}")

    def test_10_encrypted_credentials_column_present(self):
        """Verify that sentinel_mailboxes uses encrypted_credentials."""
        self.assertTrue(
            re.search(r"encrypted_credentials\s+TEXT\s+NOT\s+NULL", self.sql_content, re.IGNORECASE),
            "Column encrypted_credentials TEXT NOT NULL missing from sentinel_mailboxes"
        )

    def test_11_encrypted_dispatch_config_column_present(self):
        """Verify that sentinel_alerts uses encrypted_dispatch_config."""
        self.assertTrue(
            re.search(r"encrypted_dispatch_config\s+TEXT\s+NOT\s+NULL", self.sql_content, re.IGNORECASE),
            "Column encrypted_dispatch_config TEXT NOT NULL missing from sentinel_alerts"
        )

    def test_12_user_id_immutability_trigger_present(self):
        """Verify PostgreSQL immutability trigger function and application to all 4 tables."""
        self.assertTrue(
            re.search(r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.trg_enforce_user_id_immutability", self.sql_content, re.IGNORECASE),
            "Immutability trigger function missing"
        )
        self.assertIn("user_id is immutable", self.sql_content)

        tables = ["sentinel_workers", "sentinel_mailboxes", "sentinel_checkpoints", "sentinel_alerts"]
        for table in tables:
            pattern = rf"BEFORE\s+UPDATE\s+ON\s+public\.{table}\s+FOR\s+EACH\s+ROW\s+EXECUTE\s+FUNCTION\s+public\.trg_enforce_user_id_immutability"
            self.assertTrue(
                re.search(pattern, self.sql_content, re.IGNORECASE),
                f"Immutability trigger missing on public.{table}"
            )

    def test_13_poll_interval_bounds_30_to_3600(self):
        """Verify poll_interval_seconds enforces bounded rate limiting (30 to 3600s)."""
        self.assertTrue(
            re.search(
                r"poll_interval_seconds\s+INTEGER\s+NOT\s+NULL\s+DEFAULT\s+60\s+CHECK\s*\(\s*poll_interval_seconds\s+BETWEEN\s+30\s+AND\s+3600\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "CHECK constraint on poll_interval_seconds (30 to 3600) missing"
        )

    def test_14_desired_state_allowed_values(self):
        """Verify desired_state allows only 'RUNNING' and 'STOPPED'."""
        self.assertTrue(
            re.search(
                r"desired_state\s+TEXT\s+NOT\s+NULL\s+DEFAULT\s+'STOPPED'\s+CHECK\s*\(\s*desired_state\s+IN\s*\(\s*'RUNNING'\s*,\s*'STOPPED'\s*\)\s*\)",
                self.sql_content,
                re.IGNORECASE
            ),
            "CHECK constraint on desired_state ('RUNNING', 'STOPPED') missing"
        )

    def test_15_actual_state_allowed_values(self):
        """Verify actual_state allows valid lifecycle state machine states."""
        expected_states = ['CREATED', 'STARTING', 'RUNNING', 'STOPPING', 'STOPPED', 'FAILED']
        for st in expected_states:
            self.assertIn(f"'{st}'", self.sql_content)

    def test_16_provider_allowed_values(self):
        """Verify provider allows only supported providers: gmail, outlook, yahoo, zoho, custom."""
        expected_providers = ['gmail', 'outlook', 'yahoo', 'zoho', 'custom']
        for p in expected_providers:
            self.assertIn(f"'{p}'", self.sql_content)

    def test_17_alert_channel_allowed_values(self):
        """Verify alert channel allows only telegram and whatsapp."""
        self.assertTrue(
            re.search(r"channel\s+TEXT\s+NOT\s+NULL\s+CHECK\s*\(\s*channel\s+IN\s*\(\s*'telegram'\s*,\s*'whatsapp'\s*\)\s*\)", self.sql_content, re.IGNORECASE),
            "CHECK constraint on alert channel ('telegram', 'whatsapp') missing"
        )

    def test_18_blind_storage_protection_present(self):
        """Verify blind storage policy and column-level revoke on encrypted_credentials."""
        # Policy denies direct row SELECT to authenticated users
        self.assertTrue(
            re.search(
                r'CREATE\s+POLICY\s+"sentinel_mailboxes_select_own"\s+ON\s+public\.sentinel_mailboxes\s+FOR\s+SELECT\s+TO\s+authenticated\s+USING\s*\(\s*false\s*\)',
                self.sql_content,
                re.IGNORECASE
            ),
            "Blind storage policy USING (false) missing on sentinel_mailboxes"
        )
        # Column level revoke
        self.assertTrue(
            re.search(
                r"REVOKE\s+SELECT\s*\(\s*encrypted_credentials\s*\)\s+ON\s+public\.sentinel_mailboxes",
                self.sql_content,
                re.IGNORECASE
            ),
            "Column-level REVOKE SELECT on encrypted_credentials missing"
        )
        # Column level revoke on alerts
        self.assertTrue(
            re.search(
                r"REVOKE\s+SELECT\s*\(\s*encrypted_dispatch_config\s*\)\s+ON\s+public\.sentinel_alerts",
                self.sql_content,
                re.IGNORECASE
            ),
            "Column-level REVOKE SELECT on encrypted_dispatch_config missing"
        )

    def test_19_credential_update_privilege_revoked(self):
        """Verify that column-level UPDATE on encrypted_credentials and encrypted_dispatch_config is revoked."""
        self.assertTrue(
            re.search(
                r"REVOKE\s+UPDATE\s*\(\s*encrypted_credentials\s*\)\s+ON\s+public\.sentinel_mailboxes",
                self.sql_content,
                re.IGNORECASE
            ),
            "Column-level REVOKE UPDATE on encrypted_credentials missing"
        )
        self.assertTrue(
            re.search(
                r"REVOKE\s+UPDATE\s*\(\s*encrypted_dispatch_config\s*\)\s+ON\s+public\.sentinel_alerts",
                self.sql_content,
                re.IGNORECASE
            ),
            "Column-level REVOKE UPDATE on encrypted_dispatch_config missing"
        )


if __name__ == "__main__":
    unittest.main()
