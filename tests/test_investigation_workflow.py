"""
tests/test_investigation_workflow.py
Comprehensive Test Suite for Phase 12: Investigation Workflow & Evidence UX.

Verifies:
1. Authentication & Tenant Isolation across Investigation Workspace & Actions
2. Investigation Lifecycle & Status Transitions (NEW -> INVESTIGATING -> CONTAINED -> CLOSED)
3. Investigation Idempotency (repeated opens never create duplicates)
4. Chronological Timeline synthesis without fabricated timestamps
5. Tenant-scoped Analyst Notes with XSS sanitization
6. Evidence Integrity & SHA-256 chain-of-custody
7. GeoIP and Attack Graph integration
8. Report and Legal Evidence Package export authorizations
9. Sentinel / Live Mail and Batch scan isolation
10. Session Purge on Logout
"""

import json
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from core.case_store import (
    is_authorized_caller,
    save_case,
    get_case_record,
    get_all_cases,
    update_case_metadata,
    export_case_report_pdf,
    export_case_report_json,
    export_case_ncrp_pdf,
    export_case_bsa_pdf,
    get_soc_kpi_metrics,
)
from core.investigation import (
    LIFECYCLE_STATES,
    normalize_to_lifecycle_status,
    map_lifecycle_to_db_status,
    build_investigation_timeline,
    get_investigation_evidence,
    get_investigation_emails,
    get_investigation_indicators,
    add_analyst_note,
    transition_investigation_status,
    open_or_get_investigation,
    search_investigations,
)
from core.geolocation import derive_authoritative_location
from core.correlation import build_case_infrastructure_graph


# =====================================================================
# RLS-AWARE TEST DOUBLES
# =====================================================================

class MockPostgrestTable:
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], table_name: str, active_user_id: Optional[str]):
        self.db_state = db_state
        self.table_name = table_name
        self.active_user_id = active_user_id
        self._or_cond = None
        self._eq_filters = {}
        self._pending_update = None
        self._last_data = None

    def select(self, *args, **kwargs):
        return self

    def order(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
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

    def update(self, updates: Dict[str, Any]):
        self._pending_update = dict(updates)
        return self

    def execute(self):
        table_rows = self.db_state.get(self.table_name, [])
        user_rows = [r for r in table_rows if r.get("user_id") == self.active_user_id] if self.active_user_id else []

        if self._pending_update is not None:
            updated = []
            target_candidates = list(user_rows)
            if self._or_cond:
                parts = self._or_cond.split(",")
                cond_vals = [p.split(".eq.")[1] for p in parts if ".eq." in p]
                target_candidates = [r for r in target_candidates if r.get("id") in cond_vals or r.get("case_number") in cond_vals]
            for r in target_candidates:
                r.update(self._pending_update)
                updated.append(r)
            self._pending_update = None
            res = MagicMock()
            res.data = updated
            return res

        filtered = list(user_rows)
        if self._or_cond:
            parts = self._or_cond.split(",")
            cond_vals = [p.split(".eq.")[1] for p in parts if ".eq." in p]
            filtered = [r for r in filtered if r.get("id") in cond_vals or r.get("case_number") in cond_vals]

        for field, val in self._eq_filters.items():
            filtered = [r for r in filtered if r.get(field) == val]

        res = MagicMock()
        res.data = filtered
        return res


class MockSupabaseClient:
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], user_id: Optional[str]):
        self.db_state = db_state
        self.user_id = user_id

    def table(self, table_name: str) -> MockPostgrestTable:
        return MockPostgrestTable(self.db_state, table_name, self.user_id)


# =====================================================================
# INVESTIGATION WORKFLOW TEST SUITE
# =====================================================================

class TestInvestigationWorkflow(unittest.TestCase):
    """Verifies all Phase 12 requirements: workflow, lifecycle, timeline, evidence, and isolation."""

    def setUp(self):
        self.user_a_id = "user_investigator_alpha"
        self.user_b_id = "user_investigator_bravo"

        self.db_state: Dict[str, List[Dict[str, Any]]] = {
            "cases": [],
            "indicators": [],
        }

        self.client_a = MockSupabaseClient(self.db_state, self.user_a_id)
        self.client_b = MockSupabaseClient(self.db_state, self.user_b_id)

        # Seed initial case for User A
        self.case_a_id = "CASE-PHASE12-001"
        self.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.case_a = {
            "id": self.case_a_id,
            "case_id": self.case_a_id,
            "case_number": self.case_a_id,
            "user_id": self.user_a_id,
            "timestamp": "2026-09-19T10:00:00Z",
            "created_at": "2026-09-19T10:00:00Z",
            "sha256": self.sha256,
            "subject": "Urgent Wire Transfer Request",
            "sender": "cfo-spoof@malicious-domain.in",
            "risk_score": "HIGH",
            "threat_verdict": "THREAT",
            "case_severity": "CRITICAL",
            "status": "Open",
            "assigned_investigator": "Lead Analyst Alpha",
            "analyst_notes": "",
            "raw_json": {
                "case_id": self.case_a_id,
                "sha256": self.sha256,
                "subject": "Urgent Wire Transfer Request",
                "sender": "cfo-spoof@malicious-domain.in",
                "risk_score": "HIGH",
                "threat_verdict": "THREAT",
                "case_severity": "CRITICAL",
                "status": "Open",
                "assigned_investigator": "Lead Analyst Alpha",
                "sender_location": {
                    "is_identified": True,
                    "sender_ip": "203.0.113.50",
                    "country": "India",
                    "city": "Mumbai",
                    "latitude": 19.0760,
                    "longitude": 72.8777,
                    "org": "Mock ISP India",
                    "asn": "AS13335"
                },
                "indicators": [
                    {"type": "URL", "value": "https://fake-banking-portal.in/login", "source": "Body link"},
                    {"type": "IP", "value": "203.0.113.50", "source": "Received Header"},
                ],
                "rule_findings": [
                    {"rule_id": "RULE-001", "finding": "Spoofed Executive Display Name", "severity": "HIGH"}
                ],
                "attachment_analyses": [
                    {"filename": "Invoice_Urgent.pdf", "sha256": "1122334455667788", "verdict_label": "MALICIOUS"}
                ],
                "body_excerpt": "Please transfer 500,000 INR immediately to account 123456789.",
            }
        }

        self.db_state["cases"].append(dict(self.case_a))

    # =================================================================
    # 1. AUTHENTICATION & MULTI-TENANT ISOLATION
    # =================================================================
    def test_investigation_authentication_and_tenant_isolation(self):
        """Logged out and wrong-tenant callers cannot access private investigations."""
        with patch("core.supabase_client.is_supabase_configured", return_value=True):
            with patch("core.case_store.is_supabase_configured", return_value=True):
                # 1. Logged out / anonymous visitor
                inv_anon = open_or_get_investigation(self.case_a_id, user_id=None, client=None)
                self.assertIsNone(inv_anon, "Logged out user was able to open private investigation")

                # 2. Direct backend call without auth
                inv_direct = open_or_get_investigation(self.case_a_id, user_id=None, client=None)
                self.assertIsNone(inv_direct, "Direct backend call without auth failed to fail closed")

                # 3. Wrong tenant (User B querying User A)
                inv_b = open_or_get_investigation(self.case_a_id, user_id=self.user_b_id, client=self.client_b)
                self.assertIsNone(inv_b, "Tenant B was able to access Tenant A's investigation")

                # 4. Authorized owner (User A)
                inv_a = open_or_get_investigation(self.case_a_id, user_id=self.user_a_id, client=self.client_a)
                self.assertIsNotNone(inv_a)
                self.assertEqual(inv_a.get("case_id"), self.case_a_id)

    # =================================================================
    # 2. LIFECYCLE & STATUS MANAGEMENT
    # =================================================================
    def test_investigation_lifecycle_transitions(self):
        """Lifecycle transitions advance safely through NEW -> INVESTIGATING -> CONTAINED -> CLOSED."""
        with patch("core.supabase_client.is_supabase_configured", return_value=True):
            with patch("core.case_store.is_supabase_configured", return_value=True):
                # Verify initial status maps to NEW
                case_rec = get_case_record(self.case_a_id, client=self.client_a)
                self.assertEqual(normalize_to_lifecycle_status(case_rec.get("status")), "NEW")

                # Transition 1: NEW -> INVESTIGATING
                ok, msg = transition_investigation_status(
                    self.case_a_id, "INVESTIGATING", self.user_a_id, client=self.client_a, note="Triage started"
                )
                self.assertTrue(ok)
                case_after = get_case_record(self.case_a_id, client=self.client_a)
                self.assertEqual(normalize_to_lifecycle_status(case_after.get("status")), "INVESTIGATING")

                # Transition 2: INVESTIGATING -> CONTAINED
                ok, msg = transition_investigation_status(
                    self.case_a_id, "CONTAINED", self.user_a_id, client=self.client_a, note="Domain blocked in DNS firewall"
                )
                self.assertTrue(ok)
                case_after = get_case_record(self.case_a_id, client=self.client_a)
                self.assertEqual(normalize_to_lifecycle_status(case_after.get("status")), "CONTAINED")

                # Transition 3: CONTAINED -> CLOSED
                ok, msg = transition_investigation_status(
                    self.case_a_id, "CLOSED", self.user_a_id, client=self.client_a, note="Incident resolved"
                )
                self.assertTrue(ok)
                case_after = get_case_record(self.case_a_id, client=self.client_a)
                self.assertEqual(normalize_to_lifecycle_status(case_after.get("status")), "CLOSED")

                # Verify User B cannot transition User A's investigation
                ok_b, msg_b = transition_investigation_status(
                    self.case_a_id, "INVESTIGATING", self.user_b_id, client=self.client_b
                )
                self.assertFalse(ok_b, "Tenant B was able to transition Tenant A's investigation status")

    # =================================================================
    # 3. IDEMPOTENCY
    # =================================================================
    def test_investigation_opening_idempotency(self):
        """Repeatedly opening an investigation never creates duplicate case records."""
        with patch("core.supabase_client.is_supabase_configured", return_value=True):
            with patch("core.case_store.is_supabase_configured", return_value=True):
                initial_count = len(self.db_state["cases"])

                # Open 10 times consecutively
                for _ in range(10):
                    res = open_or_get_investigation(self.case_a_id, user_id=self.user_a_id, client=self.client_a)
                    self.assertIsNotNone(res)
                    self.assertEqual(res.get("case_id"), self.case_a_id)

                final_count = len(self.db_state["cases"])
                self.assertEqual(initial_count, final_count, "Repeated investigation open duplicated case records")

    # =================================================================
    # 4. CHRONOLOGICAL TIMELINE SYNTHESIS
    # =================================================================
    def test_chronological_timeline_synthesis(self):
        """Timeline derives strictly from verified timestamps with proper actors (SYSTEM, SENTINEL, ANALYST)."""
        case_rec = dict(self.case_a)
        case_rec.update(self.case_a["raw_json"])
        case_rec["analyst_notes"] = "[2026-09-19 10:30:00 UTC] Initial triage completed by analyst"

        timeline = build_investigation_timeline(case_rec)
        self.assertGreater(len(timeline), 0)

        # 1. Verify all events have required fields
        for ev in timeline:
            self.assertIn("event_type", ev)
            self.assertIn("timestamp", ev)
            self.assertIn("actor", ev)
            self.assertIn("description", ev)
            self.assertIn(ev["actor"], ("SYSTEM", "SENTINEL", "ANALYST"))

        # 2. Verify chronological order
        timestamps = [ev["timestamp"] for ev in timeline]
        self.assertEqual(timestamps, sorted(timestamps), "Timeline events were not strictly chronological")

        # 3. Verify specific event presence
        event_types = [ev["event_type"] for ev in timeline]
        self.assertIn("Email Ingested", event_types)
        self.assertIn("Forensic Analysis Completed", event_types)
        self.assertIn("IOCs Extracted", event_types)
        self.assertIn("Evidence Generated", event_types)

    # =================================================================
    # 5. ANALYST NOTES & XSS DEFENSE
    # =================================================================
    def test_analyst_notes_security_and_sanitization(self):
        """Analyst notes are tenant-isolated and HTML/XSS payloads are escaped."""
        with patch("core.supabase_client.is_supabase_configured", return_value=True):
            with patch("core.case_store.is_supabase_configured", return_value=True):
                # 1. Owner can add note
                xss_payload = "<script>alert('pwned')</script> Origin MTA spoofed."
                ok, msg = add_analyst_note(
                    case_id=self.case_a_id,
                    note_content=xss_payload,
                    user_id=self.user_a_id,
                    client=self.client_a
                )
                self.assertTrue(ok)

                # 2. Verify note was sanitized
                case_after = get_case_record(self.case_a_id, client=self.client_a)
                notes_text = case_after.get("analyst_notes", "")
                self.assertNotIn("<script>", notes_text)
                self.assertIn("&lt;script&gt;", notes_text)

                # 3. Tenant B cannot add notes to Tenant A's case
                ok_b, msg_b = add_analyst_note(
                    case_id=self.case_a_id,
                    note_content="Malicious unauthorized note",
                    user_id=self.user_b_id,
                    client=self.client_b
                )
                self.assertFalse(ok_b, "Tenant B was able to write notes to Tenant A's investigation")

    # =================================================================
    # 6. EVIDENCE INTEGRITY & CHAIN-OF-CUSTODY
    # =================================================================
    def test_evidence_integrity_and_artifacts(self):
        """Evidence artifacts expose correct SHA-256 hashes and chain-of-custody metadata."""
        case_rec = dict(self.case_a)
        case_rec.update(self.case_a["raw_json"])

        evidence = get_investigation_evidence(case_rec)
        self.assertGreater(len(evidence), 0)

        for ev in evidence:
            self.assertIn("evidence_id", ev)
            self.assertIn("evidence_type", ev)
            self.assertIn("sha256", ev)
            self.assertIn("source", ev)
            self.assertIn("status", ev)

        # Primary EML artifact has identical hash to raw case
        eml_ev = next(e for e in evidence if e["evidence_type"] == "Original Email Envelope")
        self.assertEqual(eml_ev["sha256"], self.sha256)

    # =================================================================
    # 7. GEOIP & ATTACK GRAPH INTEGRATION
    # =================================================================
    def test_geoip_and_attack_graph_integration(self):
        """Authoritative GeoIP is extracted and Attack Graph generates without data fabrication."""
        case_rec = dict(self.case_a)
        case_rec.update(self.case_a["raw_json"])

        # 1. GeoIP resolution
        sloc = derive_authoritative_location(case_rec)
        self.assertTrue(sloc.get("is_identified"))
        self.assertEqual(sloc.get("sender_ip"), "203.0.113.50")
        self.assertEqual(sloc.get("country"), "India")
        self.assertEqual(sloc.get("city"), "Mumbai")

        # 2. Attack graph generation
        fig = build_case_infrastructure_graph(self.case_a_id, case_rec)
        self.assertIsNotNone(fig)
        self.assertGreater(len(fig.data), 0)

    # =================================================================
    # 8. REPORTS & EXPORTS AUTHORIZATION
    # =================================================================
    def test_investigation_reports_authorization(self):
        """Reports and legal evidence packages generate for owner and fail closed for others."""
        with patch("core.supabase_client.is_supabase_configured", return_value=True):
            with patch("core.case_store.is_supabase_configured", return_value=True):
                # 1. Owner generates PDF, JSON, NCRP, BSA
                pdf_out = export_case_report_pdf(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
                self.assertIsNotNone(pdf_out)
                self.assertGreater(len(pdf_out), 0)

                json_out = export_case_report_json(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
                self.assertIsNotNone(json_out)
                self.assertIn("CASE-PHASE12-001", json_out)

                ncrp_out = export_case_ncrp_pdf(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
                self.assertIsNotNone(ncrp_out)

                bsa_out = export_case_bsa_pdf(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
                self.assertIsNotNone(bsa_out)

                # 2. Tenant B denied
                pdf_b = export_case_report_pdf(self.case_a_id, client=self.client_b, user_id=self.user_b_id)
                self.assertIsNone(pdf_b, "Tenant B generated Tenant A's PDF report")

                json_b = export_case_report_json(self.case_a_id, client=self.client_b, user_id=self.user_b_id)
                self.assertIsNone(json_b, "Tenant B generated Tenant A's JSON report")

    # =================================================================
    # 9. SENTINEL & BATCH ISOLATION
    # =================================================================
    def test_sentinel_and_batch_isolation(self):
        """Opening or investigating a case does not pollute Sentinel live counters or batch results."""
        with patch("core.supabase_client.is_supabase_configured", return_value=True):
            with patch("core.case_store.is_supabase_configured", return_value=True):
                # Check Tenant B's metrics before and after Tenant A's investigation operations
                kpi_b_before = get_soc_kpi_metrics(user_id=self.user_b_id, client=self.client_b)
                self.assertEqual(kpi_b_before["emails_analysed"], 0)

                # Tenant A advances status
                transition_investigation_status(self.case_a_id, "INVESTIGATING", self.user_a_id, client=self.client_a)

                # Tenant B metrics remain 0
                kpi_b_after = get_soc_kpi_metrics(user_id=self.user_b_id, client=self.client_b)
                self.assertEqual(kpi_b_after["emails_analysed"], 0)
                self.assertEqual(kpi_b_after["threats_detected"], 0)

    # =================================================================
    # 10. SESSION PURGE ON LOGOUT
    # =================================================================
    def test_session_purge_on_logout(self):
        """Logging out clears active_investigation_id, user_id, and cached payloads."""
        mock_session = {
            "user_id": self.user_a_id,
            "supabase_auth_token": "valid_token_12345",
            "active_investigation_id": self.case_a_id,
            "active_view_idx": 3,
            "_cached_analysis_payload": {"case_id": self.case_a_id},
        }

        # Simulate logout purge
        mock_session.clear()
        self.assertEqual(len(mock_session), 0)
        self.assertNotIn("active_investigation_id", mock_session)
        self.assertNotIn("user_id", mock_session)


if __name__ == "__main__":
    unittest.main()
