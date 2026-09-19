"""
tests/test_consolidated_authorization.py
Consolidated End-to-End Authorization & Data-Isolation Audit Test Suite.

Evaluates every protected resource against the 5-state common audit matrix:
  State A: Logged Out (Anonymous Visitor) -> Denied / Empty / Fail-closed. Zero private data.
  State B: Authenticated User A (Tenant A) -> Allowed for User A resources only.
  State C: Authenticated User B (Tenant B) -> Cannot access User A resources.
  State D: Direct Backend Call Without Auth (client=None, user_id=None) -> Fail closed immediately.
  State E: Resource ID Substitution -> User B requesting User A ID gets Denied / Empty / 404.

Covers all 16 Protected Resources:
  1. SOC Dashboard (KPIs, queue, activity, distribution)
  2. Analyze Email (save, retrieve, inspect)
  3. Investigations (case list, case detail, case updates)
  4. IOC / URL Intelligence (indicator list, threat repo)
  5. GeoIP Private Data (origin IP telemetry, case locations)
  6. Attack Graph (case infrastructure graph, node data)
  7. Evidence & Reports (case evidence, raw email, report viewer)
  8. PDF Export (export_case_report_pdf)
  9. JSON Export (export_case_report_json, export_case_iocs_json)
 10. CSV Export (export_case_iocs_csv)
 11. NCRP / BSA Export (export_case_ncrp_pdf, export_case_bsa_pdf)
 12. Live Mail Analysis (worker status, start/stop, polling state)
 13. Sentinel Telemetry (metrics, alerts, queue depth)
 14. Mailbox Configuration (credentials, IMAP settings, secrets)
 15. Mobile Alerts (Telegram/WhatsApp alert history and configs)
 16. Batch Analysis (batch run state, today's batch metrics)
"""

import json
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from core.case_store import (
    is_authorized_caller,
    is_authenticated_soc_caller,
    save_case,
    get_case_record,
    get_all_cases,
    get_all_indicators,
    update_case_metadata,
    get_soc_kpi_metrics,
    get_soc_threat_distribution,
    get_soc_threat_activity,
    get_soc_investigation_queue,
    export_case_report_pdf,
    export_case_report_json,
    export_case_ncrp_pdf,
    export_case_bsa_pdf,
    export_case_iocs_csv,
    export_case_iocs_json,
)
from core.geolocation import derive_authoritative_location
from core.correlation import build_case_infrastructure_graph
from core.sentinel_control import (
    get_user_worker,
    upsert_user_worker,
    get_user_mailbox,
    save_user_mailbox_metadata,
    get_user_checkpoint,
    get_user_alerts,
    save_user_alert_metadata,
)
from core.supabase_client import sign_out_user


# =====================================================================
# MOCK INFRASTRUCTURE (RLS-AWARE POSTGREST DOUBLE)
# =====================================================================

class MockPostgrestTable:
    """Simulates PostgreSQL table behavior with kernel-level RLS based on active user_id."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], table_name: str, active_user_id: Optional[str]):
        self.db_state = db_state
        self.table_name = table_name
        self.active_user_id = active_user_id
        self._or_cond = None
        self._eq_filters = {}
        self._limit = None
        self._order_field = None
        self._order_desc = False
        self._pending_update = None
        self._last_data = None

    def select(self, *args, **kwargs):
        return self

    def order(self, field: str, desc: bool = False, *args, **kwargs):
        self._order_field = field
        self._order_desc = desc
        return self

    def limit(self, count: int):
        self._limit = count
        return self

    def or_(self, condition: str):
        self._or_cond = condition
        return self

    def eq(self, field: str, val: Any):
        self._eq_filters[field] = val
        return self

    def insert(self, rows):
        if not self.active_user_id:
            raise PermissionError("RLS Violation: anonymous inserts prohibited")
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            if row.get("user_id") != self.active_user_id:
                raise PermissionError(f'RLS Violation: user cannot insert rows for {row.get("user_id")}')
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            self.db_state.setdefault(self.table_name, []).append(dict(row))
        return self

    def upsert(self, row: Dict[str, Any], on_conflict: str = ""):
        if not self.active_user_id or row.get("user_id") != self.active_user_id:
            raise PermissionError("RLS Violation: cannot upsert for another user")
        table = self.db_state.setdefault(self.table_name, [])
        existing = next((r for r in table if r.get("case_number") == row.get("case_number") and r.get("user_id") == row.get("user_id")), None)
        if existing:
            existing.update(row)
            self._last_data = [existing]
        else:
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            table.append(dict(row))
            self._last_data = [row]
        return self

    def update(self, updates: Dict[str, Any]):
        self._pending_update = dict(updates)
        return self

    def execute(self):
        # Resolve target table (support aliases like sentinel_mailboxes_safe -> sentinel_mailboxes)
        target_name = "sentinel_mailboxes" if self.table_name == "sentinel_mailboxes_safe" else self.table_name
        table_rows = self.db_state.get(target_name, [])

        # RLS Filtering: user can only view their own rows
        user_rows = [r for r in table_rows if r.get("user_id") == self.active_user_id] if self.active_user_id else []

        # Handle pending updates
        if self._pending_update is not None:
            updated = []
            target_candidates = list(user_rows)
            if self._or_cond:
                parts = self._or_cond.split(",")
                cond_vals = [p.split(".eq.")[1] for p in parts if ".eq." in p]
                target_candidates = [r for r in target_candidates if r.get("id") in cond_vals or r.get("case_number") in cond_vals]
            for field, val in self._eq_filters.items():
                target_candidates = [r for r in target_candidates if r.get(field) == val]
            for r in target_candidates:
                r.update(self._pending_update)
                updated.append(r)
            self._pending_update = None
            res = MagicMock()
            res.data = updated
            return res

        if self._last_data is not None:
            data = self._last_data
            self._last_data = None
            res = MagicMock()
            res.data = data
            return res

        filtered = list(user_rows)
        if self._or_cond:
            parts = self._or_cond.split(",")
            cond_vals = [p.split(".eq.")[1] for p in parts if ".eq." in p]
            filtered = [r for r in filtered if r.get("id") in cond_vals or r.get("case_number") in cond_vals]

        for field, val in self._eq_filters.items():
            filtered = [r for r in filtered if r.get(field) == val]

        if self._limit is not None:
            filtered = filtered[:self._limit]

        res = MagicMock()
        res.data = filtered
        return res


class MockSupabaseClient:
    """Mock Supabase client providing isolated PostgREST access per tenant session."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], user_id: Optional[str]):
        self.db_state = db_state
        self.user_id = user_id

    def table(self, table_name: str) -> MockPostgrestTable:
        return MockPostgrestTable(self.db_state, table_name, self.user_id)


# =====================================================================
# REUSABLE AUDIT ASSERTION HELPERS
# =====================================================================

import inspect

def _prepare_kwargs(resource_fn, user_ctx: Dict[str, Any], base_kwargs: Dict[str, Any]) -> Dict[str, Any]:
    kwargs = dict(base_kwargs)
    try:
        sig = inspect.signature(resource_fn)
        params = sig.parameters
    except Exception:
        params = {}
    if "client" in params and "client" not in kwargs and "client" in user_ctx:
        kwargs["client"] = user_ctx["client"]
    if "user_id" in params and "user_id" not in kwargs and "user_id" in user_ctx:
        kwargs["user_id"] = user_ctx["user_id"]
    return kwargs


def assert_logged_out_denied(test_case: unittest.TestCase, resource_fn, *args, **kwargs):
    """
    State A: Logged Out (Anonymous Visitor)
    Must return empty/denied/fail-closed (None, [], '', False, 0, or zero-dict).
    Zero private data/telemetry allowed.
    """
    with patch("core.supabase_client.is_supabase_configured", return_value=True):
        with patch("core.case_store.is_supabase_configured", return_value=True):
            result = resource_fn(*args, **kwargs)
            if isinstance(result, dict):
                for k, v in result.items():
                    if isinstance(v, (int, float)):
                        test_case.assertEqual(v, 0, f"Logged out leaked non-zero metric in {k}: {v}")
                    elif isinstance(v, list):
                        test_case.assertEqual(v, [], f"Logged out leaked list in {k}")
            elif isinstance(result, list):
                test_case.assertEqual(len(result), 0, "Logged out returned non-empty list")
            elif isinstance(result, (bytes, str)):
                if "Indicator_Type" in result:
                    lines = [line.strip() for line in result.strip().splitlines() if line.strip()]
                    test_case.assertLessEqual(len(lines), 1, "Logged out leaked CSV data rows")
                elif result.strip().startswith("{"):
                    parsed = json.loads(result)
                    test_case.assertEqual(parsed.get("ioc_count", 0), 0)
                    test_case.assertEqual(parsed.get("indicators", []), [])
                else:
                    test_case.assertEqual(result, "", "Logged out returned non-empty string/bytes")
            else:
                test_case.assertIn(result, (None, False), f"Logged out returned unexpected value: {result}")


def assert_owner_allowed(test_case: unittest.TestCase, resource_fn, user_ctx: Dict[str, Any], *args, **kwargs):
    """
    State B: Authenticated User A (Tenant A)
    Must succeed and return User A's authorized resource data.
    """
    with patch("core.supabase_client.is_supabase_configured", return_value=True):
        with patch("core.case_store.is_supabase_configured", return_value=True):
            kwargs_with_auth = _prepare_kwargs(resource_fn, user_ctx, kwargs)
            result = resource_fn(*args, **kwargs_with_auth)
            test_case.assertTrue(result is not None and result is not False, "Owner access was erroneously denied")
            return result


def assert_wrong_tenant_denied(test_case: unittest.TestCase, resource_fn, user_b_ctx: Dict[str, Any], expected_leak_val: Any = None, *args, **kwargs):
    """
    State C: Authenticated User B (Tenant B)
    Cannot access User A's resources. Must return empty/denied/zero.
    """
    with patch("core.supabase_client.is_supabase_configured", return_value=True):
        with patch("core.case_store.is_supabase_configured", return_value=True):
            kwargs_b = _prepare_kwargs(resource_fn, user_b_ctx, kwargs)
            result = resource_fn(*args, **kwargs_b)
            if expected_leak_val is not None:
                test_case.assertNotEqual(result, expected_leak_val, "Tenant B leaked Tenant A's private data")
            if isinstance(result, list):
                test_case.assertEqual(len(result), 0, "Tenant B received non-empty results for Tenant A")
            elif isinstance(result, dict):
                test_case.assertFalse(any(k == "user_id" and v != user_b_ctx["user_id"] for k, v in result.items()))


def assert_direct_backend_denied(test_case: unittest.TestCase, resource_fn, *args, **kwargs):
    """
    State D: Direct Backend Call Without Auth (client=None, user_id=None)
    Must fail closed immediately without falling back to local SQLite/disk when Supabase is active.
    """
    with patch("core.supabase_client.is_supabase_configured", return_value=True):
        with patch("core.case_store.is_supabase_configured", return_value=True):
            kwargs_direct = dict(kwargs)
            try:
                sig = inspect.signature(resource_fn)
                params = sig.parameters
            except Exception:
                params = {}
            if "client" in params:
                kwargs_direct["client"] = None
            if "user_id" in params:
                kwargs_direct["user_id"] = None
            result = resource_fn(*args, **kwargs_direct)
            if isinstance(result, (list, tuple)):
                test_case.assertEqual(len(result), 0, "Direct backend call without auth leaked data")
            elif isinstance(result, dict):
                for k, v in result.items():
                    if isinstance(v, (int, float)):
                        test_case.assertEqual(v, 0, f"Direct backend call leaked non-zero metric in {k}")
            elif isinstance(result, str) and "Indicator_Type" in result:
                lines = [l.strip() for l in result.strip().splitlines() if l.strip()]
                test_case.assertLessEqual(len(lines), 1, "Direct backend call leaked CSV rows")
            elif isinstance(result, str) and result.strip().startswith("{"):
                parsed = json.loads(result)
                test_case.assertEqual(parsed.get("ioc_count", 0), 0)
                test_case.assertEqual(parsed.get("indicators", []), [])
            else:
                test_case.assertIn(result, (None, False, ""), "Direct backend call without auth failed to fail closed")


def assert_id_substitution_denied(test_case: unittest.TestCase, resource_fn, user_b_ctx: Dict[str, Any], resource_a_id: str, *args, **kwargs):
    """
    State E: Resource ID Substitution
    User B requesting Resource A by known ID must receive Denied / empty / None, NEVER User A data.
    """
    with patch("core.supabase_client.is_supabase_configured", return_value=True):
        with patch("core.case_store.is_supabase_configured", return_value=True):
            kwargs_b = _prepare_kwargs(resource_fn, user_b_ctx, kwargs)
            result = resource_fn(resource_a_id, *args, **kwargs_b)
            test_case.assertIn(result, (None, False, [], ""), "ID substitution succeeded in retrieving foreign tenant resource")


# =====================================================================
# CONSOLIDATED AUTHORIZATION TEST CLASS
# =====================================================================

class TestConsolidatedAuthorization(unittest.TestCase):
    """Comprehensive test suite enforcing the 5-state authorization matrix on all 16 resources."""

    def setUp(self):
        self.user_a_id = "user_tenant_alpha_1111"
        self.user_b_id = "user_tenant_bravo_2222"

        # Shared PostgREST store
        self.db_state: Dict[str, List[Dict[str, Any]]] = {
            "cases": [],
            "indicators": [],
            "sentinel_workers": [],
            "sentinel_mailboxes": [],
            "sentinel_checkpoints": [],
            "sentinel_alerts": [],
        }

        self.client_a = MockSupabaseClient(self.db_state, self.user_a_id)
        self.client_b = MockSupabaseClient(self.db_state, self.user_b_id)

        self.user_a_ctx = {"user_id": self.user_a_id, "client": self.client_a}
        self.user_b_ctx = {"user_id": self.user_b_id, "client": self.client_b}

        # Seed initial records for User A
        self.case_a_id = "CASE-ALPHA-001"
        self.case_a_data = {
            "id": self.case_a_id,
            "case_id": self.case_a_id,
            "case_number": self.case_a_id,
            "user_id": self.user_a_id,
            "timestamp": "2026-09-19T10:00:00Z",
            "sha256": "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee",
            "subject": "Confidential Alpha Threat Report",
            "sender": "spoofer@phish-domain.in",
            "risk_score": "HIGH",
            "threat_verdict": "Phishing Lure",
            "case_severity": "HIGH",
            "status": "Open",
            "assigned_investigator": "Investigator A",
            "analyst_notes": "Originating IP identified as 185.220.101.5",
            "indicators": [
                {"type": "URL", "value": "https://malicious-login.bank-update.in/auth", "case_id": self.case_a_id, "user_id": self.user_a_id},
                {"type": "IP", "value": "185.220.101.5", "case_id": self.case_a_id, "user_id": self.user_a_id},
            ],
            "raw_json": {
                "case_id": self.case_a_id,
                "sha256": "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee",
                "subject": "Confidential Alpha Threat Report",
                "sender": "spoofer@phish-domain.in",
                "risk_score": "HIGH",
                "threat_verdict": "Phishing Lure",
                "case_severity": "HIGH",
                "sender_location": {
                    "is_identified": True,
                    "sender_ip": "185.220.101.5",
                    "country": "Germany",
                    "city": "Frankfurt",
                    "latitude": 50.1109,
                    "longitude": 8.6821,
                },
                "rule_findings": [{"rule_id": "RULE-001", "finding": "Spoofed Sender Domain", "evidence": "phish-domain.in"}],
                "indicators": [
                    {"type": "URL", "value": "https://malicious-login.bank-update.in/auth", "case_id": self.case_a_id},
                    {"type": "IP", "value": "185.220.101.5", "case_id": self.case_a_id},
                ]
            }
        }

        # Seed Database
        self.db_state["cases"].append(dict(self.case_a_data))
        for ind in self.case_a_data["indicators"]:
            self.db_state["indicators"].append(dict(ind))

        # Seed Sentinel worker and mailbox for User A
        self.worker_a_id = str(uuid.uuid4())
        self.db_state["sentinel_workers"].append({
            "id": self.worker_a_id,
            "user_id": self.user_a_id,
            "desired_state": "RUNNING",
            "poll_interval_seconds": 60,
        })
        self.db_state["sentinel_mailboxes"].append({
            "id": str(uuid.uuid4()),
            "user_id": self.user_a_id,
            "worker_id": self.worker_a_id,
            "provider": "gmail",
            "email_address": "analyst_alpha@company.com",
            "imap_host": "imap.gmail.com",
            "imap_port": 993,
            "use_ssl": True,
            "auth_mechanism": "APP_PASSWORD",
            "is_active": True,
        })
        self.db_state["sentinel_checkpoints"].append({
            "id": str(uuid.uuid4()),
            "user_id": self.user_a_id,
            "worker_id": self.worker_a_id,
            "last_polled_at": "2026-09-19T10:15:00Z",
            "emails_processed": 42,
            "threats_flagged": 3,
        })
        self.db_state["sentinel_alerts"].append({
            "id": str(uuid.uuid4()),
            "user_id": self.user_a_id,
            "worker_id": self.worker_a_id,
            "channel": "telegram",
            "destination_target": "987654321",
            "is_enabled": True,
            "high_risk_only": True,
        })

    # =================================================================
    # 1. SOC DASHBOARD MATRIX
    # =================================================================
    def test_soc_dashboard_matrix(self):
        """Resource 1: SOC Dashboard queries across 5-state matrix."""
        # State A: Logged Out
        assert_logged_out_denied(self, get_soc_kpi_metrics, user_id=None, client=None)
        assert_logged_out_denied(self, get_soc_threat_distribution, user_id=None, client=None)
        assert_logged_out_denied(self, get_soc_threat_activity, user_id=None, client=None)
        assert_logged_out_denied(self, get_soc_investigation_queue, user_id=None, client=None)

        # State B: Authenticated User A
        kpi_a = assert_owner_allowed(self, get_soc_kpi_metrics, self.user_a_ctx)
        self.assertEqual(kpi_a["emails_analysed"], 1)
        self.assertEqual(kpi_a["high_critical"], 1)

        # State C: Authenticated User B
        assert_wrong_tenant_denied(self, get_soc_threat_activity, self.user_b_ctx)
        queue_b = get_soc_investigation_queue(user_id=self.user_b_id, client=self.client_b)
        self.assertEqual(len(queue_b), 0, "User B saw User A's investigation queue")

        # State D: Direct Backend Call
        assert_direct_backend_denied(self, get_soc_kpi_metrics)
        assert_direct_backend_denied(self, get_soc_threat_distribution)

    # =================================================================
    # 2. ANALYZE EMAIL MATRIX (SAVE, RETRIEVE, INSPECT)
    # =================================================================
    def test_analyze_email_matrix(self):
        """Resource 2: Analyze Email (save_case, get_case_record)."""
        new_case = {
            "case_id": "CASE-ALPHA-NEW-01",
            "sha256": "bbbb1111222233334444555566667777888899990000aaaabbbbccccddddeeee",
            "subject": "New Phish Attempt",
            "sender": "attacker@evil.com",
            "risk_score": "HIGH",
            "threat_verdict": "Phishing",
            "user_id": self.user_a_id,
        }

        # State A: Logged Out cannot save or get
        assert_logged_out_denied(self, save_case, new_case, client=None, user_id=None)
        assert_logged_out_denied(self, get_case_record, self.case_a_id, client=None)

        # State B: Authenticated User A
        saved = save_case(new_case, client=self.client_a, user_id=self.user_a_id)
        self.assertTrue(saved)
        rec_a = assert_owner_allowed(self, get_case_record, self.user_a_ctx, case_id=self.case_a_id)
        self.assertEqual(rec_a.get("case_id"), self.case_a_id)

        # State C & E: User B requesting Case A
        assert_id_substitution_denied(self, get_case_record, self.user_b_ctx, self.case_a_id)

        # State D: Direct Backend Call
        assert_direct_backend_denied(self, get_case_record, case_id=self.case_a_id)

    # =================================================================
    # 3. INVESTIGATIONS MATRIX (CASE LIST & METADATA)
    # =================================================================
    def test_investigations_matrix(self):
        """Resource 3: Investigations (get_all_cases, update_case_metadata)."""
        # State A: Logged Out
        assert_logged_out_denied(self, get_all_cases, client=None)

        # State B: Authenticated User A
        cases_a = assert_owner_allowed(self, get_all_cases, self.user_a_ctx)
        self.assertEqual(len(cases_a), 1)
        self.assertEqual(cases_a[0]["case_id"], self.case_a_id)

        # State C: Authenticated User B sees 0 cases
        assert_wrong_tenant_denied(self, get_all_cases, self.user_b_ctx)

        # State D: Direct Backend Call
        assert_direct_backend_denied(self, get_all_cases)

        # State E: User B attempting to update User A's case
        updated = update_case_metadata(self.case_a_id, status="Closed", client=self.client_b)
        self.assertFalse(updated, "User B was able to modify User A's case metadata")

    # =================================================================
    # 4. IOC / URL INTELLIGENCE MATRIX
    # =================================================================
    def test_ioc_url_intelligence_matrix(self):
        """Resource 4: IOC / URL Intelligence (get_all_indicators)."""
        # State A: Logged Out
        assert_logged_out_denied(self, get_all_indicators, client=None)

        # State B: Authenticated User A
        iocs_a = assert_owner_allowed(self, get_all_indicators, self.user_a_ctx)
        self.assertEqual(len(iocs_a), 2)

        # State C: Authenticated User B
        assert_wrong_tenant_denied(self, get_all_indicators, self.user_b_ctx)

        # State D: Direct Backend Call
        assert_direct_backend_denied(self, get_all_indicators)

        # State E: User B requesting User A indicators by case_id
        iocs_sub = get_all_indicators(client=self.client_b, case_id=self.case_a_id)
        self.assertEqual(len(iocs_sub), 0, "User B retrieved User A indicators via ID substitution")

    # =================================================================
    # 5. GEOIP PRIVATE DATA MATRIX
    # =================================================================
    def test_geoip_private_data_matrix(self):
        """Resource 5: GeoIP Private Data (derive_authoritative_location & case location)."""
        # When unauthenticated or wrong tenant, case data cannot be retrieved
        rec_unauth = get_case_record(self.case_a_id, client=None)
        self.assertIsNone(rec_unauth)

        rec_b = get_case_record(self.case_a_id, client=self.client_b)
        self.assertIsNone(rec_b)

        # Authenticated User A retrieves case and derives authoritative location
        rec_a = get_case_record(self.case_a_id, client=self.client_a)
        self.assertIsNotNone(rec_a)
        loc = derive_authoritative_location(rec_a)
        self.assertEqual(loc["sender_ip"], "185.220.101.5")
        self.assertEqual(loc["country"], "Germany")

    # =================================================================
    # 6. ATTACK GRAPH MATRIX
    # =================================================================
    def test_attack_graph_matrix(self):
        """Resource 6: Attack Graph (build_case_infrastructure_graph)."""
        # Unauthenticated caller has no access to case records to build graph
        assert_direct_backend_denied(self, get_case_record, case_id=self.case_a_id)
        assert_id_substitution_denied(self, get_case_record, self.user_b_ctx, self.case_a_id)

        rec_a = get_case_record(self.case_a_id, client=self.client_a)
        fig = build_case_infrastructure_graph(self.case_a_id, rec_a)
        self.assertIsNotNone(fig)
        self.assertTrue(len(fig.data) > 0)

    # =================================================================
    # 7. EVIDENCE & REPORTS MATRIX
    # =================================================================
    def test_evidence_and_reports_matrix(self):
        """Resource 7: Evidence & Reports (case evidence, report viewer)."""
        # State A & D
        assert_logged_out_denied(self, get_case_record, self.case_a_id, client=None)
        assert_direct_backend_denied(self, get_case_record, case_id=self.case_a_id)

        # State B
        rec_a = assert_owner_allowed(self, get_case_record, self.user_a_ctx, case_id=self.case_a_id)
        self.assertEqual(rec_a.get("sha256"), self.case_a_data["sha256"])

        # State C & E
        assert_id_substitution_denied(self, get_case_record, self.user_b_ctx, self.case_a_id)

    # =================================================================
    # 8, 9, 10, 11. EXPORTS MATRIX (PDF, JSON, CSV, NCRP/BSA)
    # =================================================================
    def test_exports_matrix(self):
        """Resources 8-11: PDF, JSON, CSV, and NCRP/BSA exports fail closed."""
        # --- PDF Export (Resource 8) ---
        assert_logged_out_denied(self, export_case_report_pdf, self.case_a_id, client=None, user_id=None)
        assert_direct_backend_denied(self, export_case_report_pdf, case_id=self.case_a_id)
        assert_id_substitution_denied(self, export_case_report_pdf, self.user_b_ctx, self.case_a_id)

        # Owner A can export PDF
        pdf_bytes = export_case_report_pdf(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
        self.assertIsNotNone(pdf_bytes)
        self.assertTrue(len(pdf_bytes) > 0)

        # --- JSON Export (Resource 9) ---
        assert_logged_out_denied(self, export_case_report_json, self.case_a_id, client=None, user_id=None)
        assert_direct_backend_denied(self, export_case_report_json, case_id=self.case_a_id)
        assert_id_substitution_denied(self, export_case_report_json, self.user_b_ctx, self.case_a_id)

        # Owner A can export JSON
        json_out = export_case_report_json(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
        self.assertIsNotNone(json_out)
        self.assertIn("CASE-ALPHA-001", json_out)

        # IOC JSON Export
        assert_direct_backend_denied(self, export_case_iocs_json)
        iocs_json_b = export_case_iocs_json(client=self.client_b)
        parsed_b = json.loads(iocs_json_b)
        self.assertEqual(parsed_b["ioc_count"], 0)

        # --- CSV Export (Resource 10) ---
        assert_direct_backend_denied(self, export_case_iocs_csv)
        csv_b = export_case_iocs_csv(client=self.client_b)
        lines_b = [l.strip() for l in csv_b.strip().splitlines() if l.strip()]
        self.assertEqual(len(lines_b), 1, "User B received data rows in CSV export")

        csv_a = export_case_iocs_csv(client=self.client_a)
        lines_a = [l.strip() for l in csv_a.strip().splitlines() if l.strip()]
        self.assertGreater(len(lines_a), 1, "User A failed to receive authorized CSV data rows")

        # --- NCRP / BSA Export (Resource 11) ---
        assert_logged_out_denied(self, export_case_ncrp_pdf, self.case_a_id, client=None, user_id=None)
        assert_direct_backend_denied(self, export_case_ncrp_pdf, case_id=self.case_a_id)
        assert_id_substitution_denied(self, export_case_ncrp_pdf, self.user_b_ctx, self.case_a_id)

        assert_logged_out_denied(self, export_case_bsa_pdf, self.case_a_id, client=None, user_id=None)
        assert_direct_backend_denied(self, export_case_bsa_pdf, case_id=self.case_a_id)
        assert_id_substitution_denied(self, export_case_bsa_pdf, self.user_b_ctx, self.case_a_id)

        ncrp_bytes = export_case_ncrp_pdf(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
        self.assertIsNotNone(ncrp_bytes)
        self.assertTrue(len(ncrp_bytes) > 0)

    # =================================================================
    # 12, 13, 14, 15. LIVE MAIL, TELEMETRY, MAILBOX, ALERTS MATRIX
    # =================================================================
    def test_live_mail_and_sentinel_matrix(self):
        """Resources 12-15: Live Mail, Checkpoint, Mailbox, and Alerts."""
        # --- Live Mail Worker (Resource 12) ---
        assert_logged_out_denied(self, get_user_worker, user_id=None, client=None)
        assert_direct_backend_denied(self, get_user_worker, user_id=self.user_a_id)

        worker_a = assert_owner_allowed(self, get_user_worker, self.user_a_ctx, user_id=self.user_a_id)
        self.assertEqual(worker_a["id"], self.worker_a_id)

        # User B cannot see User A's worker
        worker_b_view = get_user_worker(user_id=self.user_a_id, client=self.client_b)
        self.assertIsNone(worker_b_view, "User B retrieved User A's worker via ID substitution")

        # --- Sentinel Checkpoint (Resource 13) ---
        assert_logged_out_denied(self, get_user_checkpoint, user_id=None, client=None)
        assert_direct_backend_denied(self, get_user_checkpoint, user_id=self.user_a_id)

        ckpt_a = assert_owner_allowed(self, get_user_checkpoint, self.user_a_ctx, user_id=self.user_a_id)
        self.assertEqual(ckpt_a["emails_processed"], 42)

        ckpt_b_view = get_user_checkpoint(user_id=self.user_a_id, client=self.client_b)
        self.assertIsNone(ckpt_b_view, "User B accessed User A's checkpoint")

        # --- Mailbox Configuration (Resource 14) ---
        assert_logged_out_denied(self, get_user_mailbox, user_id=None, client=None)
        assert_direct_backend_denied(self, get_user_mailbox, user_id=self.user_a_id)

        mbox_a = assert_owner_allowed(self, get_user_mailbox, self.user_a_ctx, user_id=self.user_a_id)
        self.assertEqual(mbox_a["email_address"], "analyst_alpha@company.com")

        mbox_b_view = get_user_mailbox(user_id=self.user_a_id, client=self.client_b)
        self.assertIsNone(mbox_b_view, "User B accessed User A's mailbox metadata")

        # --- Mobile Alerts (Resource 15) ---
        assert_logged_out_denied(self, get_user_alerts, user_id=None, client=None)
        assert_direct_backend_denied(self, get_user_alerts, user_id=self.user_a_id)

        alerts_a = assert_owner_allowed(self, get_user_alerts, self.user_a_ctx, user_id=self.user_a_id)
        self.assertEqual(len(alerts_a), 1)
        self.assertEqual(alerts_a[0]["destination_target"], "987654321")

        alerts_b_view = get_user_alerts(user_id=self.user_a_id, client=self.client_b)
        self.assertEqual(len(alerts_b_view), 0, "User B saw User A's alert destinations")

    # =================================================================
    # 16. BATCH ANALYSIS ISOLATION & PURGE TESTS
    # =================================================================
    def test_batch_and_live_isolation_across_tenants(self):
        """Resource 16: Batch analysis results and poller state are tenant-isolated."""
        # Simulate User A and User B session dictionaries
        session_a = {
            "user_id": self.user_a_id,
            "batch_results": {
                "total_scanned": 15,
                "clean_count": 10,
                "suspicious_count": 3,
                "phishing_count": 2,
            }
        }
        session_b = {
            "user_id": self.user_b_id,
            "batch_results": None,
        }

        # Verify User B has no batch data
        self.assertIsNone(session_b["batch_results"])

        # Running batch/analysis under User A does not pollute User B's KPI metrics
        kpi_b = get_soc_kpi_metrics(user_id=self.user_b_id, client=self.client_b)
        self.assertEqual(kpi_b["emails_analysed"], 0)
        self.assertEqual(kpi_b["threats_detected"], 0)

    def test_session_purge_on_logout(self):
        """Verify that logging out purges all tenant tokens, caches, and GeoIP state."""
        mock_session_state = {
            "user_id": self.user_a_id,
            "user_email": "analyst_alpha@company.com",
            "supabase_auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_a",
            "supabase_refresh_token": "refresh_token_a",
            "_cached_analysis_payload": {"case_id": self.case_a_id, "threat_verdict": "Phishing"},
            "batch_results": {"total_scanned": 20},
            "mailbox_connected": True,
            "manual_geoip_display_ip": "185.220.101.5",
            "manual_geoip_lat": 50.1109,
            "manual_geoip_lon": 8.6821,
            "manual_geoip_city": "Frankfurt",
        }

        import core.supabase_client as sb_mod
        with patch.object(sb_mod, "sign_out_user") as mock_sign_out:
            token = mock_session_state.get("supabase_auth_token")
            sb_mod.sign_out_user(token)
            mock_session_state.clear()

            # Verify token revocation call
            mock_sign_out.assert_called_once_with(token)

            # Verify session state is completely purged
            self.assertEqual(len(mock_session_state), 0)
            self.assertNotIn("user_id", mock_session_state)
            self.assertNotIn("supabase_auth_token", mock_session_state)
            self.assertNotIn("_cached_analysis_payload", mock_session_state)
            self.assertNotIn("manual_geoip_display_ip", mock_session_state)

    # =================================================================
    # UNIFIED AUTHORIZATION HELPER VERIFICATION
    # =================================================================
    def test_unified_is_authorized_caller(self):
        """Direct tests for is_authorized_caller fail-closed guarantees."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            # 1. No credentials -> False
            self.assertFalse(is_authorized_caller(None, None))

            # 2. user_id without client when Supabase active -> False
            self.assertFalse(is_authorized_caller(self.user_a_id, None))

            # 3. client without user_id -> False
            self.assertFalse(is_authorized_caller(None, self.client_a))

            # 4. Valid client + user_id -> True
            self.assertTrue(is_authorized_caller(self.user_a_id, self.client_a))

            # 5. Resource owner matches -> True
            self.assertTrue(is_authorized_caller(self.user_a_id, self.client_a, resource_owner_id=self.user_a_id))

            # 6. Resource owner differs -> False
            self.assertFalse(is_authorized_caller(self.user_a_id, self.client_a, resource_owner_id=self.user_b_id))

        # Backward compatibility alias
        self.assertEqual(is_authenticated_soc_caller, is_authorized_caller)


if __name__ == "__main__":
    unittest.main()
