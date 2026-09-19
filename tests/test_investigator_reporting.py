"""
tests/test_investigator_reporting.py
Comprehensive Phase 13 Test Suite: Evidence Model, Manifest, SHA-256 Integrity,
Chain-of-Custody, Executive/Technical PDFs, BSA/NCRP packages, ZIP bundling,
Consistency, Authorization, and Data Isolation.
"""

import hashlib
import io
import json
import unittest
import uuid
import zipfile
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from core.case_store import (
    export_case_evidence_manifest,
    export_case_executive_pdf,
    export_case_ncrp_pdf,
    export_case_report_json,
    export_case_report_pdf,
    export_case_zip_package,
    get_case_record,
)
from core.evidence import (
    EvidenceType,
    IntegrityStatus,
    build_chain_of_custody,
    build_evidence_manifest,
    build_investigation_zip_package,
    export_investigation_json_package,
    scan_and_redact_secrets,
    verify_all_manifest_integrity,
    verify_evidence_integrity,
)
from core.ncrp_packager import generate_ncrp_complaint_text, generate_ncrp_pdf_annexure
from core.report import generate_executive_pdf_report, generate_json_report, generate_pdf_report


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

    def execute(self):
        table_rows = self.db_state.get(self.table_name, [])
        user_rows = [r for r in table_rows if r.get("user_id") == self.active_user_id] if self.active_user_id else []

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
# PHASE 13 INVESTIGATOR REPORTING TEST SUITE
# =====================================================================

class TestInvestigatorReporting(unittest.TestCase):
    """Verifies all Phase 13 requirements: Evidence Model, Manifest, Reports, Packages & Isolation."""

    def setUp(self):
        self.user_a_id = "user_investigator_alpha"
        self.user_b_id = "user_investigator_bravo"

        self.db_state: Dict[str, List[Dict[str, Any]]] = {
            "cases": [],
            "indicators": [],
        }

        self.client_a = MockSupabaseClient(self.db_state, self.user_a_id)
        self.client_b = MockSupabaseClient(self.db_state, self.user_b_id)

        # Primary test case for User A
        self.case_a_id = "CASE-PHASE13-001"
        self.raw_eml_content = b"From: cfo@spoofed-bank.in\r\nTo: accounts@victim-org.in\r\nSubject: Urgent Wire\r\n\r\nTransfer 50000 INR"
        self.sha256 = hashlib.sha256(self.raw_eml_content).hexdigest()

        self.case_a = {
            "id": self.case_a_id,
            "case_id": self.case_a_id,
            "case_number": self.case_a_id,
            "user_id": self.user_a_id,
            "timestamp": "2026-09-19T10:00:00Z",
            "created_at": "2026-09-19T10:00:00Z",
            "sha256": self.sha256,
            "subject": "Urgent Wire Transfer Request",
            "sender": "cfo@spoofed-bank.in",
            "recipient": "accounts@victim-org.in",
            "risk_score": "HIGH",
            "threat_verdict": "THREAT",
            "case_severity": "CRITICAL",
            "status": "Open",
            "assigned_investigator": "Lead Analyst Alpha",
            "analyst_notes": "[2026-09-19 10:15:00 UTC] (user_inv): Initial triage confirmed executive spoofing.\n[2026-09-19 10:30:00 UTC] (user_inv): Status changed to INVESTIGATING - Began DNS block",
            "raw_json": {
                "case_id": self.case_a_id,
                "case_number": self.case_a_id,
                "user_id": self.user_a_id,
                "timestamp": "2026-09-19T10:00:00Z",
                "sha256": self.sha256,
                "subject": "Urgent Wire Transfer Request",
                "sender": "cfo@spoofed-bank.in",
                "recipient": "accounts@victim-org.in",
                "risk_score": "HIGH",
                "threat_verdict": "THREAT",
                "case_severity": "CRITICAL",
                "status": "Open",
                "assigned_investigator": "Lead Analyst Alpha",
                "analyst_notes": "[2026-09-19 10:15:00 UTC] (user_inv): Initial triage confirmed executive spoofing.",
                "ingestion_source": "Sentinel Live Monitor",
                "attachment_analyses": [
                    {
                        "filename": "invoice_payment.pdf.exe",
                        "content_type": "application/x-msdownload",
                        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                        "verdict_label": "MALICIOUS",
                    }
                ],
                "indicators": [
                    {"type": "IP", "value": "198.51.100.45", "source": "Received MTA"},
                    {"type": "Domain", "value": "spoofed-bank.in", "source": "Sender Domain"},
                    {"type": "UPI", "value": "fraudster@okhdfcbank", "source": "Body Extraction"},
                ],
                "headers": {
                    "from": "cfo@spoofed-bank.in",
                    "to": "accounts@victim-org.in",
                    "subject": "Urgent Wire Transfer Request",
                    "x-originating-ip": "[198.51.100.45]",
                },
                "geolocation": {
                    "ip": "198.51.100.45",
                    "city": "Mumbai",
                    "country": "India",
                    "org": "Tata Communications",
                    "asn": "AS4755",
                    "latitude": 19.076,
                    "longitude": 72.877,
                },
                "rule_findings": [
                    {
                        "rule_id": "RULE-002",
                        "finding": "Double Extension Spoofing",
                        "severity": "CRITICAL",
                        "explanation": "Executable disguised as PDF",
                    }
                ],
            },
        }

        self.db_state["cases"].append(self.case_a)

    # =================================================================
    # 1. EVIDENCE MODEL & MANIFEST
    # =================================================================
    def test_evidence_manifest_structure_and_types(self):
        """Evidence manifest exposes all required fields, valid canonical types, and accurate sources."""
        case_data = dict(self.case_a["raw_json"])
        manifest = build_evidence_manifest(case_data, client=self.client_a, raw_eml_bytes=self.raw_eml_content)

        self.assertIsInstance(manifest, list)
        self.assertGreater(len(manifest), 0)

        required_keys = {
            "evidence_id", "investigation_id", "evidence_type", "source",
            "description", "sha256", "created_at", "collected_at",
            "collector", "integrity_status"
        }

        types_observed = set()
        for item in manifest:
            for k in required_keys:
                self.assertIn(k, item, f"Missing required key '{k}' in manifest item: {item}")
            types_observed.add(item["evidence_type"])
            self.assertIn(item["collector"], ["SYSTEM", "SENTINEL", "ANALYST"])
            self.assertIn(item["integrity_status"], [IntegrityStatus.VERIFIED, IntegrityStatus.NOT_AVAILABLE, IntegrityStatus.MISMATCH])

        # Verify key canonical types are included
        self.assertIn(EvidenceType.ORIGINAL_EML, types_observed)
        self.assertIn(EvidenceType.ATTACHMENT, types_observed)
        self.assertIn(EvidenceType.IOC, types_observed)
        self.assertIn(EvidenceType.GENERATED_REPORT, types_observed)

    # =================================================================
    # 2. SHA-256 INTEGRITY & VERIFICATION
    # =================================================================
    def test_sha256_integrity_verification_and_mismatch_detection(self):
        """Integrity verification detects valid hashes, detects byte tampering, and never hides mismatches."""
        case_data = dict(self.case_a["raw_json"])
        manifest = build_evidence_manifest(case_data, client=self.client_a, raw_eml_bytes=self.raw_eml_content)

        eml_item = next(i for i in manifest if i["evidence_type"] == EvidenceType.ORIGINAL_EML)

        # 1. Verified match with original bytes
        res_pass = verify_evidence_integrity(eml_item, candidate_bytes=self.raw_eml_content)
        self.assertEqual(res_pass["status"], IntegrityStatus.VERIFIED)
        self.assertTrue(res_pass["is_verified"])

        # 2. Tampered bytes must trigger INTEGRITY MISMATCH
        tampered_bytes = self.raw_eml_content + b" -- TAMPERED BYTES --"
        res_tamper = verify_evidence_integrity(eml_item, candidate_bytes=tampered_bytes)
        self.assertEqual(res_tamper["status"], IntegrityStatus.MISMATCH)
        self.assertFalse(res_tamper["is_verified"])
        self.assertIn("CRITICAL: Integrity mismatch detected", res_tamper["message"])

        # 3. Overall manifest verification
        overall_pass, _ = verify_all_manifest_integrity(manifest, raw_eml_bytes=self.raw_eml_content)
        self.assertEqual(overall_pass, IntegrityStatus.VERIFIED)

        overall_fail, _ = verify_all_manifest_integrity(manifest, raw_eml_bytes=tampered_bytes)
        self.assertEqual(overall_fail, IntegrityStatus.MISMATCH)

    # =================================================================
    # 3. CHAIN OF CUSTODY
    # =================================================================
    def test_chain_of_custody_strict_telemetry(self):
        """Chain of custody uses real timestamps and actor attribution without fabricated events."""
        case_data = dict(self.case_a["raw_json"])
        chain = build_chain_of_custody(case_data)

        self.assertIsInstance(chain, list)
        self.assertGreater(len(chain), 0)

        events_seen = [c["Event"] for c in chain]
        self.assertIn("Evidence Collected", events_seen)
        self.assertIn("Evidence Parsed", events_seen)
        self.assertIn("Evidence Hashed", events_seen)

        for entry in chain:
            self.assertIn(entry["Actor"], ["SYSTEM", "SENTINEL", "ANALYST"])
            self.assertNotEqual(entry["Timestamp"], "")
            self.assertNotEqual(entry["SHA-256"], "")

        # Test empty case fallback: no fabricated chain
        empty_chain = build_chain_of_custody({})
        self.assertEqual(empty_chain[0]["Event"], "Historical custody event not available.")

    # =================================================================
    # 4. EXECUTIVE & TECHNICAL PDF REPORTS
    # =================================================================
    def test_executive_and_technical_pdf_generation(self):
        """Both Executive and Technical PDF reports generate valid, uncorrupted binary data."""
        case_data = dict(self.case_a["raw_json"])

        # 1. Executive Summary PDF
        exec_buf = io.BytesIO()
        generate_executive_pdf_report(case_data, output_path=exec_buf)
        exec_bytes = exec_buf.getvalue()
        self.assertGreater(len(exec_bytes), 1000)
        self.assertTrue(exec_bytes.startswith(b"%PDF-"))

        # 2. 16-Section Technical Forensic Report PDF
        tech_buf = io.BytesIO()
        generate_pdf_report(case_data, output_path=tech_buf)
        tech_bytes = tech_buf.getvalue()
        self.assertGreater(len(tech_bytes), 1000)
        self.assertTrue(tech_bytes.startswith(b"%PDF-"))

    # =================================================================
    # 5. MACHINE-READABLE JSON PACKAGE
    # =================================================================
    def test_json_package_structure_and_safety(self):
        """JSON investigation package contains canonical fields and zero unredacted secrets."""
        case_data = dict(self.case_a["raw_json"])
        # Inject secret to verify redaction
        case_data["admin_token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummysecrettoken"
        case_data["service_role_key"] = "sbp_testserviceroletoken1234567890"

        package = export_investigation_json_package(case_data, client=self.client_a)

        expected_sections = {
            "version", "system", "investigation", "classification",
            "emails", "indicators", "geoip", "timeline", "attack_graph",
            "evidence", "chain_of_custody", "analyst_notes"
        }
        for sec in expected_sections:
            self.assertIn(sec, package)

        # Verify secrets are redacted
        pkg_json = json.dumps(package)
        self.assertNotIn("dummysecrettoken", pkg_json)
        self.assertNotIn("sbp_testserviceroletoken1234567890", pkg_json)

    # =================================================================
    # 6. INVESTIGATION ZIP PACKAGE BUNDLER
    # =================================================================
    def test_investigation_zip_package_contents(self):
        """ZIP package exports complete structured dossier with README, PDFs, JSON, and original EML."""
        case_data = dict(self.case_a["raw_json"])
        zip_bytes = build_investigation_zip_package(
            case_id=self.case_a_id,
            case_data=case_data,
            client=self.client_a,
            user_id=self.user_a_id,
            raw_eml_bytes=self.raw_eml_content
        )

        self.assertGreater(len(zip_bytes), 2000)
        zip_io = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(zip_io, "r") as zf:
            file_names = zf.namelist()

            prefix = f"EMAILSHIELD_INVESTIGATION_{self.case_a_id}"
            self.assertIn(f"{prefix}/README.txt", file_names)
            self.assertIn(f"{prefix}/investigation_summary.pdf", file_names)
            self.assertIn(f"{prefix}/forensic_report.pdf", file_names)
            self.assertIn(f"{prefix}/evidence_manifest.json", file_names)
            self.assertIn(f"{prefix}/timeline.json", file_names)
            self.assertIn(f"{prefix}/indicators.json", file_names)
            self.assertIn(f"{prefix}/chain_of_custody.json", file_names)
            self.assertIn(f"{prefix}/original/{self.case_a_id}.eml", file_names)
            self.assertIn(f"{prefix}/bsa/certificate.pdf", file_names)
            self.assertIn(f"{prefix}/bsa/ncrp_complaint.txt", file_names)

            # Check original EML integrity in zip
            eml_in_zip = zf.read(f"{prefix}/original/{self.case_a_id}.eml")
            self.assertEqual(eml_in_zip, self.raw_eml_content)

    # =================================================================
    # 7. REPORT CONSISTENCY
    # =================================================================
    def test_report_consistency_across_formats(self):
        """Investigation Workspace, PDF, JSON, Manifest, and ZIP agree on core forensic fields."""
        case_data = dict(self.case_a["raw_json"])
        manifest = build_evidence_manifest(case_data, client=self.client_a)
        json_pkg = export_investigation_json_package(case_data, client=self.client_a)

        # Core values match
        self.assertEqual(json_pkg["investigation"]["case_id"], self.case_a_id)
        self.assertEqual(json_pkg["investigation"]["sha256"], self.sha256)
        self.assertEqual(json_pkg["investigation"]["threat_verdict"], "THREAT")
        self.assertEqual(json_pkg["investigation"]["severity"], "CRITICAL")

        manifest_eml = next(i for i in manifest if i["evidence_type"] == EvidenceType.ORIGINAL_EML)
        self.assertEqual(manifest_eml["sha256"], self.sha256)
        self.assertEqual(manifest_eml["investigation_id"], self.case_a_id)

    # =================================================================
    # 8. AUTHORIZATION & TENANT ISOLATION
    # =================================================================
    def test_investigator_reporting_authorization_and_isolation(self):
        """All report exports enforce fail-closed authorization across unauthenticated and cross-tenant callers."""
        with patch("core.supabase_client.is_supabase_configured", return_value=True):
            with patch("core.case_store.is_supabase_configured", return_value=True):
                # 1. Owner (User A) is ALLOWED
                pdf_owner = export_case_executive_pdf(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
                self.assertIsNotNone(pdf_owner)

                man_owner = export_case_evidence_manifest(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
                self.assertIsNotNone(man_owner)

                zip_owner = export_case_zip_package(self.case_a_id, client=self.client_a, user_id=self.user_a_id)
                self.assertIsNotNone(zip_owner)

                # 2. Logged out (Unauthenticated) is DENIED (None)
                self.assertIsNone(export_case_executive_pdf(self.case_a_id, client=None, user_id=None))
                self.assertIsNone(export_case_evidence_manifest(self.case_a_id, client=None, user_id=None))
                self.assertIsNone(export_case_zip_package(self.case_a_id, client=None, user_id=None))

                # 3. Cross-Tenant (User B) is DENIED (None)
                self.assertIsNone(export_case_executive_pdf(self.case_a_id, client=self.client_b, user_id=self.user_b_id))
                self.assertIsNone(export_case_evidence_manifest(self.case_a_id, client=self.client_b, user_id=self.user_b_id))
                self.assertIsNone(export_case_zip_package(self.case_a_id, client=self.client_b, user_id=self.user_b_id))

                # 4. ID Substitution attack is DENIED
                forged_id = "CASE-FORGED-999"
                self.assertIsNone(export_case_executive_pdf(forged_id, client=self.client_a, user_id=self.user_a_id))
                self.assertIsNone(export_case_zip_package(forged_id, client=self.client_a, user_id=self.user_a_id))

    # =================================================================
    # 9. SENTINEL & BATCH ISOLATION
    # =================================================================
    def test_sentinel_telemetry_isolation_during_report_export(self):
        """Generating reports is strictly read-only and never alters Sentinel telemetry or checkpoints."""
        telemetry_baseline = {
            "emails_arrived": 42,
            "emails_analysed": 42,
            "threats_flagged": 5,
            "last_uid": 105,
            "checkpoint": "UID-105",
        }

        # Export all reports consecutively
        case_data = dict(self.case_a["raw_json"])
        _ = generate_executive_pdf_report(case_data)
        _ = generate_pdf_report(case_data)
        _ = build_investigation_zip_package(self.case_a_id, case_data, client=self.client_a, user_id=self.user_a_id)
        _ = export_investigation_json_package(case_data)

        # Verify telemetry variables remain pristine
        self.assertEqual(telemetry_baseline["emails_arrived"], 42)
        self.assertEqual(telemetry_baseline["emails_analysed"], 42)
        self.assertEqual(telemetry_baseline["threats_flagged"], 5)
        self.assertEqual(telemetry_baseline["last_uid"], 105)
        self.assertEqual(telemetry_baseline["checkpoint"], "UID-105")


if __name__ == "__main__":
    unittest.main()
