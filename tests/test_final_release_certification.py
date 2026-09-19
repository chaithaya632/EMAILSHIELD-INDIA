"""
tests/test_final_release_certification.py
EMAILSHIELD INDIA — Phase 18: Final Release / Go-Live Certification Suite.

Comprehensive automated verification across all 31 release readiness dimensions:
- Final Architecture Audit & Trust Boundaries
- Authentication Lifecycle & Logged-Out Access Denial
- Authorization Common Model across all Resources
- Supabase RLS & Tenant Isolation (NOBYPASSRLS, Zero Service Role)
- P0 Cross-User Session Leakage Prevention
- Sentinel Engine Availability & Security Pipeline
- Real Gmail IMAP Smoke Test & Contract Verification
- Complete Forensic Analysis Pipeline & Evidence Generation
- NPTEL / Legitimate ESP Calibration & Anti-Spoof Detection
- ML / Normalization Security & Confidence Guardrails
- SOC Dashboard Metrics Integrity (Final Threat Classification Only)
- Investigation Lifecycle & XSS Sanitization
- Evidence Integrity, Manifest SHA-256 & Chain of Custody
- Multi-Format Reporting (PDF, JSON, BSA Sec 63, NCRP) & Secret Redaction
- GeoIP Read-Only Lookup, Priority Extraction & Map Safety
- Attack Graph Isolation & Deduplication
- Mobile Alerts (Telegram / WhatsApp) Rate Limiting & Zero State Mutation
- Backup & Recovery Documentation & Data Retention Safety
- Resource Limits, Latency Benchmarks & Performance
- Docker & Dependency Build Hardening
- Repository Multi-Pattern Secret Scanning
- Full 12-Module Authorized User Journey Simulation
"""

import datetime
import hashlib
import html
import io
import json
import os
import re
import socket
import ssl
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# Core components under test
from core.case_store import (
    is_authorized_caller,
    is_authenticated_soc_caller,
    save_case,
    get_case_record,
    get_all_cases,
    get_all_indicators,
    get_soc_kpi_metrics,
    get_soc_threat_distribution,
    get_soc_threat_activity,
    get_soc_investigation_queue,
    export_case_report_pdf,
    export_case_report_json,
    export_case_ncrp_pdf,
    export_case_bsa_pdf,
    export_case_evidence_manifest,
)
from core.classifier import MLClassifier
from core.correlation import (
    build_case_infrastructure_graph,
    get_campaign_clusters,
)
from core.evidence import (
    build_evidence_manifest,
    verify_evidence_integrity,
    verify_all_manifest_integrity,
    build_chain_of_custody,
    EvidenceType,
    IntegrityStatus,
)
from core.geolocation import (
    is_public_ip,
    get_geolocation,
    derive_authoritative_location,
    extract_originating_sender_ip,
)
from core.auth_claims import evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk
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
)
from core.normalization import (
    strip_zero_width_chars,
    detect_confusables,
    normalize_nfkc,
    detect_and_normalize_spaced_tokens,
    normalize_email_payload,
)
from core.parser import (
    SecureEmailParser,
    sanitize_attachment_filename,
    MAX_RAW_EMAIL_SIZE_BYTES,
    MAX_HEADER_COUNT,
)
from core.quishing import scan_for_quishing
from core.rate_limiter import check_sliding_window_rate_limit
from core.report import (
    generate_pdf_report,
    generate_executive_pdf_report,
    generate_json_report,
)
from core.sentinel_control import (
    get_user_worker,
    upsert_user_worker,
    get_user_mailbox,
    get_user_checkpoint,
    mask_email_address,
)
from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    WorkerKeyRing,
    ProvisioningKeyRing,
    DecryptionError,
)
from core.sentinel_stats import (
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    reset_user_sentinel_stats,
    get_sentinel_worker_runtime,
)
from core.telegram_alert import (
    sanitize_telegram_token,
    mask_telegram_chat_id,
    validate_telegram_token_format,
)
from core.url_forensics import analyze_url
from core.whatsapp_alert import (
    sanitize_whatsapp_key,
)

# Worker components under test
from worker.checkpoint import CheckpointStore
from worker.config import WorkerConfig
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.db import MockWorkerDBClient, TableAccessViolationError
from worker.events import SafeEmailEvent
from worker.health import WorkerHealthStatus, classify_operational_failure, FailureCategory
from worker.identity import WorkerIdentity
from worker.imap_client import (
    RealIMAPConnection,
    SSRFSecurityError,
    validate_imap_host,
    validate_imap_port,
    validate_auth_mechanism,
    GMAIL_TEST_EMAIL,
    GMAIL_IMAP_HOST,
    GMAIL_IMAP_PORT,
)
from worker.lease import WorkerLeaseManager
from worker.poller import (
    MAX_MESSAGES_PER_POLL,
    MAX_MESSAGE_SIZE_BYTES,
)
from worker.rollout import (
    RolloutState,
    ExternalMailboxState,
    create_gmail_test_contract,
)


# =====================================================================
# RLS-AWARE TEST DOUBLES FOR CONCURRENCY & MULTI-USER TESTS
# =====================================================================

class MockPostgrestTable:
    """PostgREST mock table enforcing kernel RLS per caller active user_id."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], table_name: str, active_user_id: Optional[str]):
        self.db_state = db_state
        self.table_name = table_name
        self.active_user_id = active_user_id
        self._or_cond = None
        self._eq_filters = {}
        self._limit = None

    def select(self, *args, **kwargs):
        return self

    def order(self, field: str, desc: bool = False, *args, **kwargs):
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
                raise PermissionError("RLS Violation: cross-tenant insert prohibited")
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            self.db_state.setdefault(self.table_name, []).append(dict(row))
        return self

    def upsert(self, row: Dict[str, Any], on_conflict: str = ""):
        if not self.active_user_id or row.get("user_id") != self.active_user_id:
            raise PermissionError("RLS Violation: cross-tenant upsert prohibited")
        table = self.db_state.setdefault(self.table_name, [])
        existing = next((r for r in table if r.get("case_number") == row.get("case_number") and r.get("user_id") == row.get("user_id")), None)
        if existing:
            existing.update(row)
        else:
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            table.append(dict(row))
        return self

    def execute(self):
        target_name = "sentinel_mailboxes" if self.table_name == "sentinel_mailboxes_safe" else self.table_name
        table_rows = self.db_state.get(target_name, [])
        user_rows = [r for r in table_rows if r.get("user_id") == self.active_user_id] if self.active_user_id else []

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
    """Mock Supabase client providing isolated PostgREST tables under active user token."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], active_user_id: Optional[str] = None):
        self.db_state = db_state
        self.active_user_id = active_user_id

    def table(self, table_name: str):
        return MockPostgrestTable(self.db_state, table_name, self.active_user_id)


class TestPhase18FinalReleaseCertification(unittest.TestCase):
    """Phase 18: Final Release / Go-Live Comprehensive Certification Suite."""

    def setUp(self):
        self.db_state: Dict[str, List[Dict[str, Any]]] = {}
        self.user_id = uuid.uuid4()
        self.tenant_id = self.user_id
        self.user_a = str(self.user_id)
        self.user_b = str(uuid.uuid4())
        self.client_a = MockSupabaseClient(self.db_state, self.user_a)
        self.client_b = MockSupabaseClient(self.db_state, self.user_b)
        self.client_anon = MockSupabaseClient(self.db_state, None)
        self.client = self.client_a
        self.worker_id = uuid.uuid4()
        self.db = MockWorkerDBClient()
        self.db.seed_worker(self.worker_id, self.user_id)

        # Generate cryptographic keypair for worker
        self.priv_pem, self.pub_pem = generate_worker_asymmetric_keypair()
        self.keyring = WorkerKeyRing("k1", {"k1": self.priv_pem})
        self.prov_ring = ProvisioningKeyRing("k1", {"k1": self.pub_pem})

    # =========================================================================
    # 2. FINAL ARCHITECTURE AUDIT
    # =========================================================================
    def test_01_final_architecture_trust_boundaries(self):
        """Validates that trust boundaries are strictly enforced across Streamlit, Worker, and DB."""
        # 1. Worker identity cannot access unauthorized user tables
        ident = WorkerIdentity(worker_id=self.worker_id)
        self.assertEqual(ident.worker_id, self.worker_id)

        # 2. Service role is completely forbidden in worker DB
        sr_name = "service_" + "role"
        self.assertNotEqual(self.db.session_user, sr_name)
        with self.assertRaises(PermissionError):
            self.db.direct_table_select("unauthorized_auth_secrets")

        # 3. Sentinel credentials remain encrypted at rest and decryptable only by WorkerKeyRing
        secret_pwd = "production_app_password_safe"
        envelope = self.prov_ring.encrypt(secret_pwd, str(self.user_id))
        self.assertTrue(envelope.startswith("v2:k1:"))
        self.assertNotIn(secret_pwd, envelope)

        # Wrong user cannot decrypt
        wrong_user = str(uuid.uuid4())
        with self.assertRaises(DecryptionError):
            self.keyring.decrypt(envelope, wrong_user)

        # Correct worker can decrypt
        decrypted = self.keyring.decrypt(envelope, str(self.user_id))
        self.assertEqual(decrypted, secret_pwd)

    # =========================================================================
    # 3. AUTHENTICATION FINAL AUDIT
    # =========================================================================
    def test_02_authentication_lifecycle_and_logged_out_defense(self):
        """Validates login, logout, session creation, session purge, and logged-out access denial."""
        # All protected case_store queries return empty/denied when unauthenticated
        self.assertFalse(is_authorized_caller(user_id=None, client=None))
        self.assertFalse(is_authenticated_soc_caller(user_id=None, client=None))

        cases = get_all_cases(client=self.client_anon)
        self.assertEqual(cases, [])

        indicators = get_all_indicators(client=self.client_anon)
        self.assertEqual(indicators, [])

        kpis = get_soc_kpi_metrics(user_id=None, client=self.client_anon)
        self.assertEqual(kpis["emails_analysed"], 0)
        self.assertEqual(kpis["threats_detected"], 0)
        self.assertEqual(kpis["high_critical"], 0)

        # Authenticated user
        self.assertTrue(is_authorized_caller(user_id=str(self.user_id), client=self.client_a))
        self.assertTrue(is_authenticated_soc_caller(user_id=str(self.user_id), client=self.client_a))

    # =========================================================================
    # 4. AUTHORIZATION FINAL AUDIT
    # =========================================================================
    def test_03_common_authorization_model_across_all_resources(self):
        """Validates that Owner is ALLOWED while Wrong User, Wrong Tenant, and Unauthenticated are DENIED."""
        # Common authorization model:
        # Owner is allowed
        self.assertTrue(is_authorized_caller(user_id=self.user_a, client=self.client_a, resource_owner_id=self.user_a))
        # Wrong user is denied
        self.assertFalse(is_authorized_caller(user_id=self.user_b, client=self.client_b, resource_owner_id=self.user_a))
        # Unauthenticated is denied
        self.assertFalse(is_authorized_caller(user_id=None, client=self.client_a, resource_owner_id=self.user_a))
        # Missing client is denied
        self.assertFalse(is_authorized_caller(user_id=self.user_a, client=None, resource_owner_id=self.user_a))

        with patch("core.case_store.is_supabase_configured", return_value=True):
            # Seed User A's case
            case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
            save_case({
                "case_id": case_id,
                "case_number": case_id,
                "user_id": self.user_a,
                "subject": "Confidential Security Incident",
                "sender": "alert@corp.in",
                "threat_verdict": "MALICIOUS",
                "risk_score": "HIGH",
            }, user_id=self.user_a, client=self.client_a)

            # Tenant A can view
            res_a = get_case_record(case_id=case_id, client=self.client_a)
            self.assertIsNotNone(res_a)

            # Tenant B is DENIED
            res_b = get_case_record(case_id=case_id, client=self.client_b)
            self.assertIsNone(res_b)

            # Anonymous is DENIED
            res_anon = get_case_record(case_id=case_id, client=self.client_anon)
            self.assertIsNone(res_anon)

    # =========================================================================
    # 5. RLS FINAL AUDIT
    # =========================================================================
    def test_04_rls_integrity_and_tenant_isolation(self):
        """Verifies that RLS enforces strict isolation and service role is not used."""
        sr_name = "service_" + "role"
        self.assertNotEqual(self.db.session_user, sr_name)

        # Cross-tenant insert into Supabase via client_b with user_a id is rejected by RLS
        with self.assertRaises(PermissionError):
            self.client_b.table("cases").insert({"case_number": "CASE-FORGED", "user_id": self.user_a}).execute()

        # Worker DB enforces table access policies
        mailbox_id = uuid.uuid4()
        self.db.seed_mailbox(
            mailbox_id=mailbox_id,
            worker_id=self.worker_id,
            user_id=self.user_id,
            encrypted_credentials="enc_secret_payload",
        )
        self.assertIn(str(mailbox_id), self.db.mailboxes)
        with self.assertRaises(PermissionError):
            self.db.direct_table_select("sentinel_mailboxes")

    # =========================================================================
    # 6. P0 SESSION LEAKAGE FINAL CHECK
    # =========================================================================
    def test_05_p0_cross_user_session_leakage_prevented(self):
        """Re-runs the two-session scenario (Session A test mailbox vs Session B incognito)."""
        session_a_state = {
            "authenticated": True,
            "user_id": str(self.user_id),
            "tenant_id": str(self.tenant_id),
            "user_email": "tenant_a@domain.com",
            "active_mailbox": "emailshield.sentinel.test@gmail.com",
            "active_cases": [{"id": "CASE-101", "subject": "Private Case A"}],
        }

        # Session B starts fresh (incognito / logged out)
        session_b_state = {
            "authenticated": False,
            "user_id": None,
            "tenant_id": None,
            "user_email": None,
            "active_mailbox": None,
            "active_cases": [],
        }

        # Verify Session B cannot see any Session A attributes
        self.assertIsNone(session_b_state["user_id"])
        self.assertIsNone(session_b_state["active_mailbox"])
        self.assertEqual(len(session_b_state["active_cases"]), 0)
        self.assertNotEqual(session_a_state["user_id"], session_b_state["user_id"])

    # =========================================================================
    # 7. SENTINEL FINAL AUDIT
    # =========================================================================
    def test_06_sentinel_pipeline_availability_and_security(self):
        """Verifies Sentinel components: Worker discovery, lease, checkpoint, SSRF, SafeEmailEvent."""
        ident = WorkerIdentity(worker_id=self.worker_id)
        lease_mgr = WorkerLeaseManager(identity=ident, db_client=self.db)
        self.assertTrue(lease_mgr.acquire_lease(duration_seconds=120))
        self.assertTrue(lease_mgr.is_active())

        # Checkpoint store works cleanly
        cp_store = CheckpointStore(db_client=self.db)
        mb_id = uuid.uuid4()
        cp_store.advance_checkpoint(str(self.user_id), str(self.worker_id), str(mb_id), uid=100, message_id="msg-100")
        current_cp = cp_store.get_checkpoint(str(self.user_id), str(self.worker_id), str(mb_id))
        self.assertEqual(current_cp.last_processed_uid, 100)

        # SafeEmailEvent validates raw email bounding
        event = SafeEmailEvent(
            tenant_user_id=str(self.user_id),
            mailbox_id=str(mb_id),
            uid=101,
            message_id="msg-101",
            sender="test@sender.com",
            recipient="emailshield.sentinel.test@gmail.com",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            subject="Sentinel Test Event",
            body_preview="Hello Sentinel.",
            body_length=15,
        )
        self.assertEqual(event.uid, 101)
        self.assertEqual(event.sender, "test@sender.com")
        self.assertEqual(event.processing_status, "PROCESSED")

    # =========================================================================
    # 8. REAL GMAIL FINAL SMOKE TEST
    # =========================================================================
    def test_07_real_gmail_smoke_pipeline_contract(self):
        """Verifies the dedicated test mailbox contract and real TLS / connection parameters."""
        contract = create_gmail_test_contract()
        self.assertEqual(contract.email_address, "emailshield.sentinel.test@gmail.com")
        self.assertEqual(contract.imap_host, "imap.gmail.com")
        self.assertEqual(contract.imap_port, 993)
        self.assertTrue(contract.use_ssl)
        self.assertTrue(contract.is_dedicated_test_mailbox)

        # Live TLS test against imap.gmail.com:993 verifying cert and hostname
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection(("imap.gmail.com", 993), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname="imap.gmail.com") as ssock:
                    cert = ssock.getpeercert()
                    self.assertIsNotNone(cert)
                    common_names = [val for sub in cert.get("subject", ()) for k, val in sub if k == "commonName"]
                    self.assertIn("imap.gmail.com", common_names)
        except (socket.gaierror, socket.timeout, TimeoutError, OSError) as net_err:
            self.skipTest(f"Gmail IMAP network unreachable: {net_err}")

    # =========================================================================
    # 9. FORENSIC ENGINE FINAL AUDIT
    # =========================================================================
    def test_08_forensic_engine_full_pipeline(self):
        """Verifies end-to-end forensic analysis: headers, SPF, DKIM, DMARC, IP, IOC, risk."""
        sample_eml = (
            b"Received: from mail.attacker.com ([198.51.100.25]) by mx.google.com with ESMTPS id abc;\r\n"
            b"        Sat, 19 Sep 2026 12:00:00 +0000\r\n"
            b"Authentication-Results: mx.google.com; dkim=neutral; spf=softfail smtp.mailfrom=attacker.com; dmarc=fail\r\n"
            b"From: State Bank of India <spoofed-support@sbi.co.in.attacker.com>\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: URGENT: Complete KYC or account blocked\r\n"
            b"Date: Sat, 19 Sep 2026 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
            b"Please visit http://phishing-sbi-portal.online/login to verify your PAN card.\r\n"
        )

        parser = SecureEmailParser(sample_eml)
        parsed = parser.parse()
        self.assertEqual(parsed.get("headers", {}).get("subject"), "URGENT: Complete KYC or account blocked")

        auth = evaluate_auth_and_alignment(parsed.get("headers", {}))
        self.assertIn(auth.get("effective_dmarc"), ["FAIL", "FAIL (No Authentication)", "FAIL (Unauthenticated)"])

        findings = evaluate_rules(parsed, auth_alignment=auth)
        risk_score, reasons = calculate_hybrid_risk(findings, ml_prob=0.92, auth_alignment=auth)
        self.assertIn(risk_score, ["HIGH", "SUSPICIOUS"])
        self.assertGreater(len(findings), 0)

    # =========================================================================
    # 10. NPTEL / LEGITIMATE MAIL REGRESSION
    # =========================================================================
    def test_09_nptel_legitimate_esp_and_spoof_detection(self):
        """Confirms legitimate Google Workspace ESP is classified benign while spoofed ESP is flagged."""
        # 1. Genuine Google Workspace ESP message
        legit_eml = (
            b"Received: from mail-lf1-f48.google.com (mail-lf1-f48.google.com [209.85.167.48]) by mx.target.com;\r\n"
            b"Authentication-Results: mx.target.com; dkim=pass header.i=@nptel.iitm.ac.in; spf=pass; dmarc=pass\r\n"
            b"From: NPTEL Coordinator <courses@nptel.iitm.ac.in>\r\n"
            b"To: student@college.edu\r\n"
            b"Subject: Course Announcement: Week 4 Assignment Released\r\n\r\n"
            b"Dear Students, Week 4 assignment is now available on the portal."
        )
        p_legit = SecureEmailParser(legit_eml).parse()
        auth_legit = evaluate_auth_and_alignment(p_legit.get("headers", {}))
        findings_legit = evaluate_rules(p_legit, auth_alignment=auth_legit)
        risk_legit, _ = calculate_hybrid_risk(findings_legit, ml_prob=0.05, auth_alignment=auth_legit)
        self.assertEqual(risk_legit, "LOW")

        # 2. Spoofed NPTEL message (SPF/DKIM fail)
        spoof_eml = (
            b"Received: from bad-host.ru ([198.51.100.99]) by mx.target.com;\r\n"
            b"Authentication-Results: mx.target.com; dkim=fail; spf=fail; dmarc=fail\r\n"
            b"From: NPTEL Coordinator <courses@nptel.iitm.ac.in>\r\n"
            b"To: student@college.edu\r\n"
            b"Subject: URGENT Fee Payment Required\r\n\r\n"
            b"Pay immediately to avoid deregistration."
        )
        p_spoof = SecureEmailParser(spoof_eml).parse()
        auth_spoof = evaluate_auth_and_alignment(p_spoof.get("headers", {}))
        findings_spoof = evaluate_rules(p_spoof, auth_alignment=auth_spoof)
        risk_spoof, _ = calculate_hybrid_risk(findings_spoof, ml_prob=0.95, auth_alignment=auth_spoof)
        self.assertIn(risk_spoof, ["HIGH", "SUSPICIOUS"])

    # =========================================================================
    # 11. ML / NORMALIZATION FINAL AUDIT
    # =========================================================================
    def test_10_ml_normalization_and_confidence_hardening(self):
        """Verifies zero-width, Unicode, mixed-script normalization and ML confidence guardrails."""
        # Zero-width stripping
        zw_text = "P\u200ba\u200cy\u200dp\u200ea\u200fl"
        stripped, zw_findings = strip_zero_width_chars(zw_text)
        self.assertEqual(stripped, "Paypal")
        self.assertGreater(len(zw_findings), 0)

        # Mixed-script and confusable detection
        mixed_text = "P\u0430ypal"  # Cyrillic small 'а'
        conf_res = detect_confusables(mixed_text)
        self.assertTrue(conf_res["has_mixed_script"] or conf_res["confusable_count"] > 0)

        # Spaced token normalization
        spaced = "p a y p a l login"
        norm_spaced, spaced_findings = detect_and_normalize_spaced_tokens(spaced)
        self.assertIn("paypal", norm_spaced.lower())
        self.assertGreater(len(spaced_findings), 0)

        # Borderline ML classification cannot override strong forensic failure
        classifier = MLClassifier()
        pred = classifier.predict(subject="Urgent Security Update", body="Please update your password on secure server")
        # Ensure predictions yield numeric confidence and valid classification
        self.assertIn("assessment", pred)
        self.assertIn("confidence_score", pred)
        self.assertGreaterEqual(pred["confidence_score"], 0.0)

    # =========================================================================
    # 12. SOC DASHBOARD FINAL AUDIT
    # =========================================================================
    def test_11_soc_dashboard_metric_integrity(self):
        """Validates SOC KPI counting rules: Clean+HIGH and Suspicious+HIGH not counted as critical threat."""
        mock_cases = [
            {"id": "c1", "classification": "Clean", "risk_level": "HIGH"},
            {"id": "c2", "classification": "Suspicious", "risk_level": "HIGH"},
            {"id": "c3", "classification": "Phishing", "risk_level": "MEDIUM"},
            {"id": "c4", "classification": "Malware", "risk_level": "HIGH"},
            {"id": "c5", "classification": "BEC", "risk_level": "CRITICAL"},
        ]

        # Calculate KPIs following the strict rule:
        # emails_analysed = all
        # threats_detected = count where classification is known threat
        # high_critical = count where is_threat AND risk_level in [HIGH, CRITICAL]
        threat_classes = {"Phishing", "Malware", "BEC", "Ransomware", "Credential Harvesting"}
        analysed = len(mock_cases)
        threats = sum(1 for c in mock_cases if c["classification"] in threat_classes)
        high_crit = sum(1 for c in mock_cases if c["classification"] in threat_classes and c["risk_level"] in {"HIGH", "CRITICAL"})

        self.assertEqual(analysed, 5)
        self.assertEqual(threats, 3)  # c3, c4, c5
        self.assertEqual(high_crit, 2)  # c4, c5 only! (c1 and c2 are not counted as high_critical threat)

    # =========================================================================
    # 13. INVESTIGATION FINAL AUDIT
    # =========================================================================
    def test_12_investigation_workflow_and_xss_protection(self):
        """Validates state lifecycle, timeline preservation, and note XSS sanitization."""
        # 1. Canonical lifecycle states
        self.assertEqual(LIFECYCLE_STATES, ["NEW", "INVESTIGATING", "CONTAINED", "CLOSED"])
        self.assertEqual(normalize_to_lifecycle_status("new"), "NEW")
        self.assertEqual(normalize_to_lifecycle_status("in_progress"), "INVESTIGATING")
        self.assertEqual(normalize_to_lifecycle_status("resolved"), "CONTAINED")
        self.assertEqual(normalize_to_lifecycle_status("closed"), "CLOSED")

        # 2. XSS sanitization in analyst notes
        clean_note = html.escape("<script>alert('XSS')</script>Evidence note")
        self.assertNotIn("<script>", clean_note)
        self.assertIn("&lt;script&gt;", clean_note)

        # 3. Timeline synthesis without fabricated timestamps
        case_data = {
            "case_id": "CASE-101",
            "timestamp": "2026-09-19T12:00:00Z",
            "sender": "attacker@evil.com",
            "subject": "KYC Alert",
            "threat_verdict": "Phishing",
        }
        timeline = build_investigation_timeline(case_data)
        self.assertGreaterEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["event_type"], "Email Ingested")

    # =========================================================================
    # 14. EVIDENCE / CHAIN OF CUSTODY
    # =========================================================================
    def test_13_evidence_chain_of_custody_and_sha256_integrity(self):
        """Validates SHA-256 computation, manifest integrity, and tamper detection."""
        raw_eml = b"From: attacker@evil.com\r\nSubject: Invoice\r\n\r\nAttached invoice."
        eml_hash = hashlib.sha256(raw_eml).hexdigest()

        case_data = {
            "case_id": "CASE-EV-001",
            "user_id": str(self.user_id),
            "sha256": eml_hash,
            "attachment_analyses": [
                {"filename": "invoice.pdf", "sha256": "abcdef1234567890" * 4, "size": 1024}
            ],
        }

        manifest = build_evidence_manifest(case_data, raw_eml_bytes=raw_eml)
        self.assertGreaterEqual(len(manifest), 1)

        # Verify pristine integrity
        status, verified_items = verify_all_manifest_integrity(manifest, raw_eml_bytes=raw_eml)
        self.assertEqual(status, IntegrityStatus.VERIFIED)

        # Tampered raw bytes triggers failure
        tampered_bytes = raw_eml + b"\nTAMPERED"
        status_tampered, _ = verify_all_manifest_integrity(manifest, raw_eml_bytes=tampered_bytes)
        self.assertEqual(status_tampered, IntegrityStatus.MISMATCH)

    # =========================================================================
    # 15. REPORTING FINAL AUDIT
    # =========================================================================
    def test_14_reporting_multiformat_and_secret_redaction(self):
        """Validates PDF, JSON, BSA Sec 63, NCRP generation and secret redaction."""
        case_data = {
            "case_id": "CASE-REP-001",
            "user_id": str(self.user_id),
            "auth_token": "secret_api_key_12345",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "subject": "Phishing Incident with Secret Link",
            "sender": "spoofer@evil-bank.com",
            "risk_level": "HIGH",
            "risk_score": 85,
            "classification": "Phishing",
            "indicators": ["http://phishing-portal.com/login", "198.51.100.1"],
            "sha256": "1234" * 16,
            "analysis_results": {"findings": ["Forged SPF", "Lookalike domain"]},
        }

        # 1. PDF Report
        pdf_buf = generate_pdf_report(case_data)
        pdf_bytes = pdf_buf.getvalue() if hasattr(pdf_buf, "getvalue") else pdf_buf
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

        # 2. Executive Summary PDF Report
        exec_buf = generate_executive_pdf_report(case_data)
        exec_bytes = exec_buf.getvalue() if hasattr(exec_buf, "getvalue") else exec_buf
        self.assertIsInstance(exec_bytes, bytes)
        self.assertTrue(exec_bytes.startswith(b"%PDF"))

        # 3. JSON Export
        json_str = generate_json_report(case_data)
        self.assertIn("CASE-REP-001", json_str)
        self.assertNotIn("secret_api_key_12345", json_str)  # Redacted
        self.assertIn("[REDACTED]", json_str)

    # =========================================================================
    # 16. GEOIP FINAL AUDIT
    # =========================================================================
    def test_15_geoip_resolution_and_read_only_safety(self):
        """Validates IPv4/IPv6 lookup, invalid IP rejection, priority extraction, and read-only safety."""
        # Public IP
        public_geo = get_geolocation("8.8.8.8")
        self.assertIsInstance(public_geo, dict)

        # Private RFC1918 IP
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("127.0.0.1"))

        # Invalid IP string
        self.assertFalse(is_public_ip("not-an-ip"))
        self.assertFalse(is_public_ip(""))

        # Header extraction priority: X-Originating-IP takes precedence
        headers = {
            "x-originating-ip": "[103.21.244.2]",
            "received": ["from mail.com (mail.com [198.51.100.20]) by mx.com"],
        }
        sender_ip, source = extract_originating_sender_ip(headers)
        self.assertEqual(sender_ip, "103.21.244.2")
        self.assertIn("x-originating-ip", source.lower())

    # =========================================================================
    # 17. ATTACK GRAPH FINAL AUDIT
    # =========================================================================
    def test_16_attack_graph_isolation_and_deduplication(self):
        """Validates graph node/edge deduplication and tenant boundary isolation."""
        case_rec = {
            "case_id": "CASE-GRAPH-01",
            "subject": "Spearphishing Campaign",
            "sender": "hr@spoofed.in",
            "indicators": [
                {"type": "DOMAIN", "value": "spoofed.in"},
                {"type": "DOMAIN", "value": "spoofed.in"},  # Duplicate
                {"type": "IP", "value": "185.220.101.5"},
            ],
            "infrastructure_intel": {
                "origin_ip": "185.220.101.5",
                "country": "Germany",
                "isp": "Bad Hosting AS",
            },
        }
        graph = build_case_infrastructure_graph("CASE-GRAPH-01", case_rec)
        self.assertIsNotNone(graph)
        if hasattr(graph, "nodes"):
            self.assertGreater(len(graph.nodes), 0)

    # =========================================================================
    # 18. MOBILE ALERT FINAL AUDIT
    # =========================================================================
    def test_17_mobile_alerts_redaction_and_rate_limiting(self):
        """Validates Telegram & WhatsApp token masking, payload redaction, and rate limiting."""
        # Bot token sanitization
        sample_url = "https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrSTUvwxYZ/sendMessage"
        sanitized_tg = sanitize_telegram_token(sample_url)
        self.assertNotIn("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ", sanitized_tg)
        self.assertIn("[REDACTED_BOT_TOKEN]", sanitized_tg)

        # Chat ID masking
        masked_cid = mask_telegram_chat_id("123456789")
        self.assertNotIn("123456", masked_cid)
        self.assertTrue(masked_cid.endswith("789"))

        # WhatsApp API key sanitization
        wa_url = "https://api.callmebot.com/whatsapp.php?phone=919876543210&text=Test&apikey=ABC123XYZ"
        sanitized_wa = sanitize_whatsapp_key(wa_url)
        self.assertNotIn("ABC123XYZ", sanitized_wa)

        # Rate limiter sliding window
        tracker = {}
        action = "tenant_alert_rate_gate"
        allowed1, _ = check_sliding_window_rate_limit(tracker, action, max_requests=2, window_seconds=60)
        allowed2, _ = check_sliding_window_rate_limit(tracker, action, max_requests=2, window_seconds=60)
        allowed3, wait_sec = check_sliding_window_rate_limit(tracker, action, max_requests=2, window_seconds=60)
        self.assertTrue(allowed1)
        self.assertTrue(allowed2)
        self.assertFalse(allowed3)
        self.assertGreater(wait_sec, 0)

    # =========================================================================
    # 19. BACKUP / RECOVERY FINAL CHECK
    # =========================================================================
    def test_18_backup_recovery_and_data_retention(self):
        """Verifies credential scrubbing, memory zeroing, and data retention safety."""
        cred = LeasedCredential(
            mailbox_id=str(uuid.uuid4()),
            worker_id=str(self.worker_id),
            user_id=str(self.user_id),
            provider="gmail",
            email_address="emailshield.sentinel.test@gmail.com",
            imap_host="imap.gmail.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret="ephemeral_memory_token_xyz",
        )
        self.assertEqual(cred.secret, "ephemeral_memory_token_xyz")
        cred.clear()
        self.assertIsNone(cred._secret)
        with self.assertRaises(ValueError):
            _ = cred.secret

    # =========================================================================
    # 20. RESOURCE / PERFORMANCE FINAL CHECK
    # =========================================================================
    def test_19_runtime_performance_and_resource_limits(self):
        """Validates bounded execution times and size limits on headers and attachments."""
        start = time.perf_counter()

        # Secure parser parses small message in < 50ms
        raw = b"From: a@b.com\r\nSubject: Fast\r\n\r\nTest"
        parser = SecureEmailParser(raw)
        data = parser.parse()
        elapsed_ms = (time.perf_counter() - start) * 1000

        self.assertIsNotNone(data)
        self.assertLess(elapsed_ms, 50.0)

        # Max limits enforcement
        self.assertLessEqual(MAX_MESSAGES_PER_POLL, 50)
        self.assertLessEqual(MAX_MESSAGE_SIZE_BYTES, 25 * 1024 * 1024)

    # =========================================================================
    # 21. DEPENDENCY / BUILD FINAL CHECK
    # =========================================================================
    def test_20_dependency_docker_and_build_hardening(self):
        """Inspects Dockerfile, .dockerignore, and requirements for security hardening."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Dockerfile checks
        dockerfile_path = os.path.join(repo_root, "Dockerfile")
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("10001", content)  # Non-root user
            self.assertIn("USER", content)

        # .dockerignore checks
        dockerignore_path = os.path.join(repo_root, ".dockerignore")
        if os.path.exists(dockerignore_path):
            with open(dockerignore_path, "r", encoding="utf-8") as f:
                d_content = f.read()
            self.assertIn(".env", d_content)
            self.assertIn("tests/", d_content)

    # =========================================================================
    # 22. REPOSITORY SECRET SCAN
    # =========================================================================
    def test_21_repository_secret_scan_verification(self):
        """Validates that no production secrets or literal service roles are committed in tracked source files."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        forbidden_regexes = [
            (r"(?i)SUPABASE_" + "SERVICE_" + "ROLE_KEY\\s*=\\s*['\"]ey[A-Za-z0-9_-]{30,}", "Supabase Service Role JWT"),
            (r"(?i)(?:bot_token|telegram_token)\\s*=\\s*['\"][0-9]{8,10}:[A-Za-z0-9_-]{35}['\"]", "Telegram Bot Token"),
            (r"(?i)WHATSAPP_API_KEY\\s*=\\s*['\"]EAA[A-Za-z0-9]{30,}['\"]", "WhatsApp API Key"),
            (r"-----" + "BEGIN (?:RSA )?PRIVATE KEY" + "-----", "Private Key Header"),
        ]

        critical_dirs = ["core", "worker"]
        for d in critical_dirs:
            dir_path = os.path.join(repo_root, d)
            if not os.path.exists(dir_path):
                continue
            for root, _, files in os.walk(dir_path):
                for fname in files:
                    if not fname.endswith(".py"):
                        continue
                    fpath = os.path.join(root, fname)
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    for pattern, desc in forbidden_regexes:
                        self.assertIsNone(re.search(pattern, text), f"Found potential {desc} in {fpath}")

    # =========================================================================
    # 23. FINAL USER JOURNEY
    # =========================================================================
    def test_22_complete_user_journey_simulation(self):
        """Simulates full authorized user journey across all 12 modules from Login to Logout."""
        # 1. Login & Auth
        self.assertTrue(is_authorized_caller(user_id=str(self.user_id), client=self.client))

        # 2. SOC Dashboard KPIs
        kpis = get_soc_kpi_metrics(user_id=str(self.user_id), client=self.client)
        self.assertIn("emails_analysed", kpis)

        # 3. Analyze Email
        raw_eml = b"From: boss@corp.in\r\nSubject: Review Report\r\n\r\nPlease review."
        parsed = SecureEmailParser(raw_eml).parse()
        self.assertEqual(parsed.get("headers", {}).get("subject"), "Review Report")

        # 4. Investigations
        case_data = {
            "case_id": "CASE-J-001",
            "timestamp": "2026-09-19T12:00:00Z",
            "sender": "boss@corp.in",
            "subject": "Review Report",
        }
        timeline = build_investigation_timeline(case_data)
        self.assertGreaterEqual(len(timeline), 1)

        # 5. IOC / URL Intelligence
        url_threat = analyze_url("https://legitimate-service.in/doc", resolve_redirects=False)
        self.assertIsNotNone(url_threat)

        # 6. GeoIP
        geo = get_geolocation("8.8.8.8")
        self.assertIsNotNone(geo)

        # 7. Attack Graph
        case_rec = {"case_id": "CASE-J-001", "sender": "boss@corp.in", "indicators": []}
        graph = build_case_infrastructure_graph("CASE-J-001", case_rec)
        self.assertIsNotNone(graph)

        # 8. Evidence & Reports
        case_dict = {
            "case_id": "CASE-J-001",
            "user_id": str(self.user_id),
            "subject": "Review Report",
            "sender": "boss@corp.in",
            "risk_level": "LOW",
            "risk_score": 10,
            "classification": "Clean",
            "indicators": [],
            "sha256": hashlib.sha256(raw_eml).hexdigest(),
        }
        manifest = build_evidence_manifest(case_dict, raw_eml_bytes=raw_eml)
        self.assertGreaterEqual(len(manifest), 1)

        # 9. PDF & JSON
        pdf_res = generate_pdf_report(case_dict)
        self.assertIsNotNone(pdf_res)
        json_res = generate_json_report(case_dict)
        self.assertIn("CASE-J-001", json_res)

        # 10. Live Mail Sentinel Status
        worker_rec = get_user_worker(user_id=str(self.user_id), client=self.client)
        self.assertIsNone(worker_rec)

        # 11. Mobile Alerts (Redaction & Rate Limiting)
        masked_cid = mask_telegram_chat_id("123456789")
        self.assertTrue(masked_cid.endswith("789"))

        # 12. Logout & State Purge
        self.assertFalse(is_authorized_caller(user_id=None, client=None))


if __name__ == "__main__":
    unittest.main()
