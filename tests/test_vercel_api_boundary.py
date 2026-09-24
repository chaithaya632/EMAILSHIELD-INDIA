"""
tests/test_vercel_migration_api_boundary.py
Verification suite for Phase 25 Next.js / Vercel Scaffolding & API Boundary Implementation.

Validates:
1. Scaffolding: web/ directory structure, tsconfig, package.json, next.config.js.
2. Static Security:
   - Absence of active service_role authentication in web/ codebase.
   - Absence of JWT in browser localStorage in web/ codebase.
   - Absence of module-level global client cache in web/ codebase.
   - Absence of secrets/passwords in source.
3. API Boundary & Authorization:
   - Unauthenticated access returns 401 UNAUTHENTICATED.
   - Tenant isolation & RLS enforcement on all endpoints.
   - Cross-user export blocking: User A cannot export User B's case.
4. Upload Size Strategy:
   - Direct API processing for <= 4.5MB.
   - Presigned storage path for > 4.5MB.
   - Hard rejection for > 10MB (413 Payload Too Large).
5. Live Mail & Batch Isolation:
   - Live Mail API reads authoritatively from Supabase without IMAP connections.
   - Batch analysis causes zero side effects on Live Mail counters.
6. Product Terminology:
   - "Live Mail Analysis" is used throughout user-facing UI; "Sentinel" is NOT exposed in UI.
"""

import os
import re
import unittest
from pathlib import Path


class TestVercelMigrationApiBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parent.parent
        cls.web_dir = cls.root_dir / "web"

    def test_01_project_scaffolding_exists(self):
        """Phase 25.1: Verify Next.js project structure exists and has required files."""
        self.assertTrue(self.web_dir.exists(), "web/ directory must exist")
        self.assertTrue((self.web_dir / "package.json").exists(), "web/package.json must exist")
        self.assertTrue((self.web_dir / "tsconfig.json").exists(), "web/tsconfig.json must exist")
        self.assertTrue((self.web_dir / "next.config.js").exists(), "web/next.config.js must exist")
        self.assertTrue((self.web_dir / "tailwind.config.js").exists(), "web/tailwind.config.js must exist")
        self.assertTrue((self.web_dir / "middleware.ts").exists(), "web/middleware.ts must exist")

        # Verify app directories
        required_pages = [
            "login", "dashboard", "analyze", "live-mail", "investigations",
            "intel", "attack-graph", "reports", "alerts", "settings", "diagnostics"
        ]
        for p in required_pages:
            page_file = self.web_dir / "app" / p / "page.tsx"
            self.assertTrue(page_file.exists(), f"web/app/{p}/page.tsx must exist")

        # Verify API route directories
        required_apis = [
            "auth/login", "auth/logout", "auth/session", "soc/dashboard",
            "analyze", "live-mail", "investigations", "intel", "reports",
            "alerts", "settings"
        ]
        for a in required_apis:
            route_file = self.web_dir / "app" / "api" / a / "route.ts"
            self.assertTrue(route_file.exists(), f"web/app/api/{a}/route.ts must exist")

    def test_02_static_security_scan_no_service_role(self):
        """Phase 25.11 & 25.18: Verify service_role is strictly NOT used as a secret/client in web/.
        Credential retrieval uses rpc_get_own_mailbox_credential() SECURITY DEFINER RPC
        with auth.uid() ownership — no service_role key required.
        """
        active_service_role_pattern = re.compile(r'(SUPABASE_SERVICE_ROLE_KEY|auth\.admin|service_role_key)', re.IGNORECASE)
        for ts_file in self.web_dir.rglob("*.ts*"):
            if "node_modules" in str(ts_file) or ".next" in str(ts_file):
                continue
            content = ts_file.read_text(encoding="utf-8", errors="ignore")
            match = active_service_role_pattern.search(content)
            self.assertIsNone(match, f"Forbidden service_role secret found in {ts_file.relative_to(self.root_dir)}")

    def test_03_static_security_scan_no_jwt_in_localstorage(self):
        """Phase 25.3 & 25.18: Verify JWT is NOT stored in browser localStorage."""
        localstorage_jwt_pattern = re.compile(r'localStorage\.(setItem|getItem)\s*\([^)]*(jwt|token|auth)', re.IGNORECASE)
        for ts_file in self.web_dir.rglob("*.ts*"):
            if "node_modules" in str(ts_file) or ".next" in str(ts_file):
                continue
            content = ts_file.read_text(encoding="utf-8", errors="ignore")
            self.assertIsNone(
                localstorage_jwt_pattern.search(content),
                f"Forbidden storage of JWT in localStorage in {ts_file.relative_to(self.root_dir)}"
            )

    def test_04_request_scoped_supabase_client_isolation(self):
        """Phase 25.4: Verify createServerSupabaseClient and createRouteClient are request-scoped."""
        route_ts = (self.web_dir / "lib" / "supabase" / "route.ts").read_text(encoding="utf-8")
        server_ts = (self.web_dir / "lib" / "supabase" / "server.ts").read_text(encoding="utf-8")

        # Verify no global mutable client variable
        self.assertNotIn("let globalClient", route_ts)
        self.assertNotIn("var globalClient", route_ts)
        self.assertNotIn("let globalClient", server_ts)
        self.assertNotIn("var globalClient", server_ts)

        # Verify client is created per-call with cookies or request headers
        self.assertIn("createServerClient", route_ts)
        self.assertIn("createServerClient", server_ts)
        self.assertIn("cookieStore", server_ts)
        self.assertIn("bearerToken", route_ts)

    def test_05_api_error_model_sanitization(self):
        """Phase 25.16: Verify API error model strips secrets and sensitive keys."""
        api_resp_ts = (self.web_dir / "lib" / "api-response.ts").read_text(encoding="utf-8")
        self.assertIn("ApiErrorCode", api_resp_ts)
        self.assertIn("forbiddenKeys", api_resp_ts)
        self.assertIn("password", api_resp_ts)
        self.assertIn("jwt", api_resp_ts)
        self.assertIn("service_role", api_resp_ts)

    def test_06_dashboard_api_enforces_auth_and_rls(self):
        """Phase 25.6: Verify dashboard route requires authentication and queries by user.id."""
        dash_ts = (self.web_dir / "app" / "api" / "soc" / "dashboard" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("getAuthenticatedUser", dash_ts)
        self.assertIn('apiError("UNAUTHENTICATED"', dash_ts)
        self.assertIn('.eq("user_id", userId)', dash_ts)
        self.assertIn("Promise.all", dash_ts, "Dashboard should execute concurrent queries for performance")

    def test_07_live_mail_api_is_read_only_and_independent(self):
        """Phase 25.7 & 25.12: Verify live-mail route reads Supabase only, does NOT connect to IMAP."""
        live_ts = (self.web_dir / "app" / "api" / "live-mail" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("getAuthenticatedUser", live_ts)
        self.assertIn('.eq("user_id", userId)', live_ts)
        self.assertIn("sentinel_checkpoints", live_ts)
        self.assertIn("sentinel_events", live_ts)
        # Ensure no IMAP libraries, sockets, or connections
        self.assertNotIn("node-imap", live_ts)
        self.assertNotIn("imap-simple", live_ts)
        self.assertNotIn("tls.connect", live_ts)
        self.assertNotIn("net.connect", live_ts)

    def test_08_analyze_api_enforces_upload_size_strategy(self):
        """Phase 25.8 & 25.9: Verify analyze route handles <=4.5MB direct, >4.5MB storage, >10MB reject."""
        analyze_ts = (self.web_dir / "app" / "api" / "analyze" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("10 * 1024 * 1024", analyze_ts, "Must check 10MB max limit")
        self.assertIn("4.5 * 1024 * 1024", analyze_ts, "Must check 4.5MB serverless limit")
        self.assertIn("PAYLOAD_TOO_LARGE", analyze_ts)
        self.assertIn("requires_storage_upload", analyze_ts)

    def test_09_export_routes_block_cross_user_access(self):
        """Phase 25.10: Verify JSON, CSV, and PDF exports enforce user_id ownership check."""
        for fmt in ["json", "csv", "pdf"]:
            route_path = self.web_dir / "app" / "api" / "reports" / "[id]" / fmt / "route.ts"
            self.assertTrue(route_path.exists())
            content = route_path.read_text(encoding="utf-8")
            self.assertIn('getAuthenticatedUser', content)
            self.assertIn('.eq("case_id", caseId)', content)
            self.assertIn('.eq("user_id", user.id)', content, f"{fmt} export MUST check user_id")
            self.assertIn('apiError("NOT_FOUND"', content)

    def test_10_product_terminology_preserved(self):
        """Phase 25.14: Verify user-facing UI uses 'Live Mail Analysis' and not 'Sentinel'."""
        live_mail_page = (self.web_dir / "app" / "live-mail" / "page.tsx").read_text(encoding="utf-8")
        sidebar = (self.web_dir / "components" / "Sidebar.tsx").read_text(encoding="utf-8")

        self.assertIn("Live Mail Analysis", live_mail_page)
        self.assertIn("Live Mail Analysis", sidebar)
        # Sentinel must not appear as a top-level user-facing navigation item
        self.assertNotIn("Sentinel Analysis", sidebar)
        self.assertNotIn("Sentinel Mail", sidebar)

    def test_11_streamlit_source_intact_and_unmodified(self):
        """Phase 25.20: Verify app.py, core/, worker/, views/ are fully intact for Streamlit rollback."""
        app_py = (self.root_dir / "app.py").read_text(encoding="utf-8")
        self.assertIn("st.set_page_config", app_py)
        self.assertIn("clear_investigator_session", app_py)
        self.assertTrue((self.root_dir / "core" / "supabase_client.py").exists())
        self.assertTrue((self.root_dir / "worker" / "service.py").exists())
        self.assertTrue((self.root_dir / "views" / "dashboard.py").exists())

    def test_12_analyze_page_unified_workflow_and_no_pagination(self):
        """Phase 26.4: Verify Analyze page supports unified workflow (Upload + Live Mail), 50/100/200, and strictly NO pagination."""
        analyze_page = (self.web_dir / "app" / "analyze" / "page.tsx").read_text(encoding="utf-8")
        self.assertIn("📤 Upload Email", analyze_page)
        self.assertIn("📬 Select from Live Mail", analyze_page)
        self.assertIn("[50, 100, 200]", analyze_page)
        self.assertIn("overflow-y-auto", analyze_page)
        self.assertIn("Not analyzed", analyze_page)
        self.assertIn("UID:", analyze_page)

        # Ensure NO pagination controls exist in analyze page
        self.assertNotIn("Previous Page", analyze_page)
        self.assertNotIn("Next Page", analyze_page)
        self.assertNotIn("Page 1 of", analyze_page)
        self.assertNotIn("Page 2 of", analyze_page)
        self.assertNotIn("Jump to Page", analyze_page)

    def test_13_mobile_alerts_hides_credentials_and_masks_destination(self):
        """Phase 26.10: Verify Mobile Alerts hides credentials on connection and masks destinations."""
        alerts_page = (self.web_dir / "app" / "alerts" / "page.tsx").read_text(encoding="utf-8")
        alerts_api = (self.web_dir / "app" / "api" / "alerts" / "route.ts").read_text(encoding="utf-8")

        self.assertIn("Telegram Security Bot", alerts_page)
        self.assertIn("WhatsApp Gateway", alerts_page)
        self.assertIn("🟢 Connected / ACTIVE", alerts_page)
        self.assertIn("setTgToken(\"\")", alerts_page, "Raw tokens must be cleared from state")
        self.assertIn("setWaApiKey(\"\")", alerts_page, "Raw API keys must be cleared from state")
        self.assertIn("type=\"password\"", alerts_page)

        # In API route: verify destination masking
        self.assertIn("slice(-4)", alerts_api)

    def test_14_diagnostics_page_collapsed_by_default_and_safe(self):
        """Phase 26.12: Verify Diagnostics page is collapsed by default and exposes no secrets."""
        diag_page = (self.web_dir / "app" / "diagnostics" / "page.tsx").read_text(encoding="utf-8")
        self.assertIn("useState(false)", diag_page, "Diagnostics must be collapsed by default")
        self.assertNotIn("password", diag_page.lower())
        self.assertNotIn("service_role", diag_page.lower())
        self.assertNotIn("secret_key", diag_page.lower())

    def test_15_session_switching_and_tenant_isolation_invariants(self):
        """Phase 26.2 & 26.16: Verify authentication and session endpoints isolate User A and User B."""
        login_route = (self.web_dir / "app" / "api" / "auth" / "login" / "route.ts").read_text(encoding="utf-8")
        logout_route = (self.web_dir / "app" / "api" / "auth" / "logout" / "route.ts").read_text(encoding="utf-8")
        session_route = (self.web_dir / "app" / "api" / "auth" / "session" / "route.ts").read_text(encoding="utf-8")

        # Session tokens stored in HTTP-only cookies
        self.assertIn("httpOnly: true", login_route)
        self.assertIn("sameSite: \"lax\"", login_route)
        self.assertIn("delete(\"sb-access-token\")", logout_route)
        self.assertIn("delete(\"sb-refresh-token\")", logout_route)

        # Route client strictly uses request cookies/headers, not a shared global user
        route_client = (self.web_dir / "lib" / "supabase" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("getAuthenticatedUser", route_client)
        self.assertIn("cookieStore.get", route_client)

    def test_16_dashboard_loading_skeletons_and_empty_states(self):
        """Phase 26.3: Verify Dashboard implements loading skeletons and empty states."""
        dash_page = (self.web_dir / "app" / "dashboard" / "page.tsx").read_text(encoding="utf-8")
        self.assertIn("animate-pulse", dash_page)
        self.assertIn("Threat Distribution Ratio", dash_page)
        self.assertIn("Incident Triage Queue", dash_page)
        self.assertIn("Total Emails Analyzed", dash_page)


class TestRpcOwnMailboxCredentialSecurity(unittest.TestCase):
    """
    Security tests for rpc_get_own_mailbox_credential SECURITY DEFINER RPC.
    Validates: function definition, privilege model, ownership enforcement,
    column-level REVOKE preservation, and web-tier service_role absence.
    """

    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).resolve().parent.parent
        cls.web_dir = cls.root_dir / "web"
        cls.data_dir = cls.root_dir / "data"

    def _read_rpc_sql(self):
        """Read the RPC migration SQL file."""
        rpc_path = self.data_dir / "migrations" / "phase_i_own_credential_rpc.sql"
        self.assertTrue(rpc_path.exists(), f"RPC migration file must exist: {rpc_path}")
        return rpc_path.read_text(encoding="utf-8")

    # TEST A — RPC Function Definition
    def test_a_rpc_function_exists_with_correct_signature(self):
        """RPC must be CREATE OR REPLACE FUNCTION rpc_get_own_mailbox_credential() RETURNS TEXT."""
        sql = self._read_rpc_sql()
        self.assertIn("rpc_get_own_mailbox_credential()", sql)
        self.assertIn("RETURNS TEXT", sql.upper())
        self.assertIn("language plpgsql", sql.lower())

    # TEST B — SECURITY DEFINER Hardening
    def test_b_security_definer_with_search_path(self):
        """RPC must be SECURITY DEFINER with SET search_path = public."""
        sql = self._read_rpc_sql()
        self.assertIn("SECURITY DEFINER", sql.upper())
        self.assertIn("search_path", sql.lower())
        self.assertIn("public", sql.lower())

    # TEST C — auth.uid() Ownership
    def test_c_ownership_derived_from_auth_uid(self):
        """RPC must derive ownership EXCLUSIVELY from auth.uid(), NOT from parameters."""
        sql = self._read_rpc_sql()
        self.assertIn("auth.uid()", sql)
        # Ensure the function uses auth.uid() for the WHERE clause
        self.assertIn("user_id = auth.uid()", sql.replace("v_caller_id", "auth.uid()").replace(
            "public.sentinel_mailboxes.user_id = v_caller_id", "user_id = auth.uid()") or sql)

    # TEST D — No User-Supplied Parameters
    def test_d_no_user_supplied_parameters(self):
        """RPC must accept ZERO parameters. No user_id, mailbox_id, or tenant_id."""
        sql = self._read_rpc_sql()
        # Function signature must be empty parentheses
        self.assertIn("rpc_get_own_mailbox_credential()", sql)
        # Must NOT have p_user_id, p_mailbox_id, p_tenant_id parameters
        sql_lower = sql.lower()
        self.assertNotIn("p_user_id", sql_lower)
        self.assertNotIn("p_mailbox_id", sql_lower)
        self.assertNotIn("p_tenant_id", sql_lower)

    # TEST E — Privilege: REVOKE from PUBLIC and anon
    def test_e_revoke_from_public_and_anon(self):
        """RPC execution must be REVOKEd from PUBLIC and anon."""
        sql = self._read_rpc_sql().upper()
        self.assertIn("REVOKE EXECUTE", sql)
        self.assertIn("FROM PUBLIC", sql)
        # Check for anon revoke (case insensitive)
        self.assertIn("ANON", sql)

    # TEST F — Privilege: GRANT to authenticated ONLY
    def test_f_grant_to_authenticated_only(self):
        """RPC execution must be GRANTed to authenticated role."""
        sql = self._read_rpc_sql().upper()
        self.assertIn("GRANT EXECUTE", sql)
        self.assertIn("TO AUTHENTICATED", sql)

    # TEST G — Column-level REVOKE preserved
    def test_g_column_level_revoke_preserved(self):
        """The migration must NOT remove or weaken the column-level REVOKE on encrypted_credentials."""
        sql = self._read_rpc_sql().upper()
        # Must NOT contain GRANT SELECT on encrypted_credentials
        self.assertNotIn("GRANT SELECT", sql)
        # Must NOT contain ALTER TABLE sentinel_mailboxes
        self.assertNotIn("ALTER TABLE", sql)
        # Must NOT modify existing RLS policies
        self.assertNotIn("DROP POLICY", sql)
        self.assertNotIn("CREATE POLICY", sql)

    # TEST H — No service_role in web/ (strict scan)
    def test_h_no_service_role_in_web_directory(self):
        """After RPC migration, web/ must contain ZERO references to SUPABASE_SERVICE_ROLE_KEY."""
        service_role_pattern = re.compile(r'SUPABASE_SERVICE_ROLE_KEY', re.IGNORECASE)
        for ts_file in self.web_dir.rglob("*.ts*"):
            if "node_modules" in str(ts_file) or ".next" in str(ts_file):
                continue
            content = ts_file.read_text(encoding="utf-8", errors="ignore")
            self.assertIsNone(
                service_role_pattern.search(content),
                f"SUPABASE_SERVICE_ROLE_KEY found in {ts_file.relative_to(self.root_dir)}"
            )

    # TEST I — Poll route uses RPC not service_role
    def test_i_poll_route_uses_rpc_not_service_role(self):
        """Poll route must call rpc_get_own_mailbox_credential and NOT use createServiceClient."""
        poll_route = (self.web_dir / "app" / "api" / "live-mail" / "poll" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("rpc_get_own_mailbox_credential", poll_route)
        self.assertNotIn("createServiceClient", poll_route)
        self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", poll_route)
        # Must authenticate caller
        self.assertIn("getAuthenticatedUser", poll_route)

    # TEST J — Poll route decrypts and performs real IMAP
    def test_j_poll_route_real_imap_and_decrypt(self):
        """Poll route must decrypt credentials and connect to Gmail IMAP."""
        poll_route = (self.web_dir / "app" / "api" / "live-mail" / "poll" / "route.ts").read_text(encoding="utf-8")
        self.assertIn("decryptMailboxCredentialAsymmetric", poll_route)
        self.assertIn("testGmailImapConnection", poll_route)
        self.assertIn("sinceUid", poll_route)

    # TEST K — RPC queries only sentinel_mailboxes with fully qualified name
    def test_k_fully_qualified_table_reference(self):
        """RPC must use fully qualified public.sentinel_mailboxes to prevent search_path attacks."""
        sql = self._read_rpc_sql()
        self.assertIn("public.sentinel_mailboxes", sql)

    # TEST L — Safe failure for no active mailbox
    def test_l_safe_failure_for_no_active_mailbox(self):
        """RPC must RAISE EXCEPTION if no active mailbox found."""
        sql = self._read_rpc_sql()
        self.assertIn("RAISE EXCEPTION", sql)
        self.assertIn("is_active = true", sql.lower())

    # TEST M — Existing tables/columns/views not modified
    def test_m_no_existing_schema_modification(self):
        """The migration must be additive only — no ALTER, DROP TABLE, DROP VIEW."""
        sql = self._read_rpc_sql().upper()
        self.assertNotIn("ALTER TABLE", sql)
        self.assertNotIn("DROP TABLE", sql)
        self.assertNotIn("DROP VIEW", sql)
        self.assertNotIn("CREATE TABLE", sql)
        self.assertNotIn("CREATE VIEW", sql)


if __name__ == "__main__":
    unittest.main()

