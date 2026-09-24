"""
EMAILSHIELD INDIA — Threat Activity & Bulk Controls Test Suite

Comprehensive test coverage for:
1. Threat Activity Semantics & Benign Email Exclusion:
   - Clean NPTEL email (onlinecourses@nptel.iitm.ac.in, threat_verdict="Standard / Legitimate", risk_score="LOW") is NEVER returned.
   - Clean Google Security Alert (no-reply@accounts.google.com, threat_verdict="Standard / Legitimate", risk_score="LOW") is NEVER returned.
   - Malicious / Phishing email (security@paypal-verify-account.com, classification="THREAT", risk_score="HIGH") IS returned.
   - Suspicious email (classification="SUSPICIOUS", risk_score="MEDIUM") IS returned.
   - Closed threat cases (status="Closed") are excluded.
   - Unauthenticated caller returns empty list [] (fail-closed).
2. Primary IOC Extraction Invariants:
   - For benign email without threat indicators, returns "N/A" (never returns nptel.iitm.ac.in or accounts.google.com).
   - For email with actual threat URL/IP, extracts the threat URL/IP.
   - Authentication evidence (RULE-014, RULE-013, SPF/DKIM passes) is NEVER extracted as an IOC.
3. Bulk Close Controls & Evidence Preservation:
   - close_all_open_cases:
     - Closes all open cases for the authenticated user/tenant (status updated to 'Closed').
     - Evidence files, raw JSON, and SHA-256 hashes are strictly preserved (not deleted).
     - Fails closed when unauthenticated (returns success=False).
     - Cross-tenant isolation: does not close another tenant's cases.
   - clear_threat_activity:
     - Closes only active threat cases for the tenant.
     - Benign/clean cases or already closed cases are not affected.
     - Fails closed when unauthenticated (returns success=False).
"""

import unittest
from unittest.mock import MagicMock, patch
from typing import Any, Dict, List

from core.case_store import (
    _extract_primary_ioc,
    clear_threat_activity,
    close_all_open_cases,
    derive_case_classification,
    derive_case_severity,
    get_soc_threat_activity,
    is_authorized_caller,
    update_case_metadata,
)


# =====================================================================
# 1. Threat Activity Semantics & Benign Email Exclusion
# =====================================================================

class TestSocThreatActivitySemantics(unittest.TestCase):
    """Verify get_soc_threat_activity returns only active threats/suspicious events,
    strictly excluding benign emails, closed cases, and unauthorized callers."""

    def setUp(self):
        self.user_id = "soc_analyst_001"
        self.mock_client = MagicMock()

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_clean_nptel_email_never_returned_in_threat_activity(self, mock_get_cases, mock_auth):
        """Clean NPTEL email (onlinecourses@nptel.iitm.ac.in, Standard / Legitimate, LOW)
        must NEVER appear in threat activity."""
        mock_get_cases.return_value = [
            {
                "case_id": "CASE-NPTEL-001",
                "case_number": "CASE-NPTEL-001",
                "sender": "onlinecourses@nptel.iitm.ac.in",
                "subject": "NPTEL: Swayam Course Enrollment Confirmation",
                "threat_verdict": "Standard / Legitimate",
                "risk_score": "LOW",
                "status": "Open",
                "timestamp": "2026-09-20T10:00:00",
                "indicators": [],
                "rule_findings": [],
            }
        ]

        activity = get_soc_threat_activity(user_id=self.user_id, client=self.mock_client)
        self.assertEqual(len(activity), 0, "Clean NPTEL email must be excluded from threat activity")

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_clean_google_security_alert_never_returned_in_threat_activity(self, mock_get_cases, mock_auth):
        """Clean Google Security Alert (no-reply@accounts.google.com, Standard / Legitimate, LOW)
        must NEVER appear in threat activity."""
        mock_get_cases.return_value = [
            {
                "case_id": "CASE-GOOGLE-001",
                "case_number": "CASE-GOOGLE-001",
                "sender": "no-reply@accounts.google.com",
                "subject": "Security alert: New device signed in",
                "threat_verdict": "Standard / Legitimate",
                "risk_score": "LOW",
                "status": "Open",
                "timestamp": "2026-09-20T10:05:00",
                "indicators": [],
                "rule_findings": [],
            }
        ]

        activity = get_soc_threat_activity(user_id=self.user_id, client=self.mock_client)
        self.assertEqual(len(activity), 0, "Clean Google Alert must be excluded from threat activity")

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_malicious_phishing_email_is_returned_in_threat_activity(self, mock_get_cases, mock_auth):
        """Malicious / Phishing email (security@paypal-verify-account.com, THREAT, HIGH)
        MUST be returned in threat activity."""
        mock_get_cases.return_value = [
            {
                "case_id": "CASE-THREAT-001",
                "case_number": "CASE-THREAT-001",
                "sender": "security@paypal-verify-account.com",
                "subject": "Urgent: Your PayPal account has been suspended",
                "classification": "THREAT",
                "risk_score": "HIGH",
                "case_severity": "HIGH",
                "status": "Open",
                "timestamp": "2026-09-20T10:10:00",
                "indicators": [{"type": "URL", "value": "https://paypal-verify-account.com/login"}],
                "rule_findings": [],
            }
        ]

        activity = get_soc_threat_activity(user_id=self.user_id, client=self.mock_client)
        self.assertEqual(len(activity), 1)
        self.assertEqual(activity[0]["case_id"], "CASE-THREAT-001")
        self.assertEqual(activity[0]["risk_score"], "THREAT")
        self.assertEqual(activity[0]["primary_ioc"], "https://paypal-verify-account.com/login")

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_suspicious_email_is_returned_in_threat_activity(self, mock_get_cases, mock_auth):
        """Suspicious email (classification='SUSPICIOUS', risk_score='MEDIUM')
        MUST be returned in threat activity."""
        mock_get_cases.return_value = [
            {
                "case_id": "CASE-SUSP-001",
                "case_number": "CASE-SUSP-001",
                "sender": "invoice@unknown-vendor.net",
                "subject": "Invoice payment overdue notice",
                "classification": "SUSPICIOUS",
                "risk_score": "MEDIUM",
                "case_severity": "MEDIUM",
                "status": "Open",
                "timestamp": "2026-09-20T10:15:00",
                "indicators": [],
                "rule_findings": [],
            }
        ]

        activity = get_soc_threat_activity(user_id=self.user_id, client=self.mock_client)
        self.assertEqual(len(activity), 1)
        self.assertEqual(activity[0]["case_id"], "CASE-SUSP-001")
        self.assertEqual(activity[0]["risk_score"], "SUSPICIOUS")

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_closed_threat_cases_excluded_from_threat_activity(self, mock_get_cases, mock_auth):
        """Closed threat cases (status='Closed' or 'CLOSED') must be excluded from threat activity."""
        mock_get_cases.return_value = [
            {
                "case_id": "CASE-CLOSED-THREAT",
                "case_number": "CASE-CLOSED-THREAT",
                "sender": "attacker@evil-domain.com",
                "subject": "Wire Transfer Request",
                "classification": "THREAT",
                "risk_score": "HIGH",
                "status": "Closed",
                "timestamp": "2026-09-20T09:00:00",
                "indicators": [],
                "rule_findings": [],
            },
            {
                "case_id": "CASE-CLOSED-LOWERCASE",
                "case_number": "CASE-CLOSED-LOWERCASE",
                "sender": "phisher@bad-site.org",
                "subject": "Account update",
                "classification": "THREAT",
                "risk_score": "HIGH",
                "status": "closed",
                "timestamp": "2026-09-20T09:05:00",
                "indicators": [],
                "rule_findings": [],
            },
        ]

        activity = get_soc_threat_activity(user_id=self.user_id, client=self.mock_client)
        self.assertEqual(len(activity), 0, "Closed cases must be excluded regardless of casing")

    def test_unauthenticated_caller_returns_empty_list_fail_closed(self):
        """Unauthenticated caller must return empty list [] without querying storage."""
        # Unauthenticated: user_id=None, client=None
        activity = get_soc_threat_activity(user_id=None, client=None)
        self.assertEqual(activity, [], "Unauthenticated query must fail closed and return []")

    @patch("core.case_store.is_authenticated_soc_caller", return_value=False)
    def test_unauthorized_token_returns_empty_list(self, mock_auth):
        """When authorization evaluator returns False, query fails closed with []."""
        activity = get_soc_threat_activity(user_id="attacker", client=MagicMock())
        self.assertEqual(activity, [])

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_mixed_case_stream_filters_correctly(self, mock_get_cases, mock_auth):
        """In a mixed stream of clean, suspicious, malicious, and closed emails,
        only active THREAT and SUSPICIOUS cases appear in threat activity."""
        mock_get_cases.return_value = [
            # 1. Clean NPTEL
            {
                "case_id": "CASE-CLEAN-NPTEL",
                "sender": "onlinecourses@nptel.iitm.ac.in",
                "threat_verdict": "Standard / Legitimate",
                "risk_score": "LOW",
                "status": "Open",
            },
            # 2. Clean Google Alert
            {
                "case_id": "CASE-CLEAN-GOOGLE",
                "sender": "no-reply@accounts.google.com",
                "threat_verdict": "Standard / Legitimate",
                "risk_score": "LOW",
                "status": "Open",
            },
            # 3. Active Threat (Malicious)
            {
                "case_id": "CASE-ACTIVE-THREAT",
                "sender": "security@paypal-verify-account.com",
                "classification": "THREAT",
                "risk_score": "HIGH",
                "status": "Open",
            },
            # 4. Active Suspicious
            {
                "case_id": "CASE-ACTIVE-SUSPICIOUS",
                "sender": "hr@payroll-external-audit.info",
                "classification": "SUSPICIOUS",
                "risk_score": "MEDIUM",
                "status": "Open",
            },
            # 5. Closed Threat
            {
                "case_id": "CASE-CLOSED-THREAT",
                "sender": "ransomware@evil-corp.cc",
                "classification": "THREAT",
                "risk_score": "HIGH",
                "status": "Closed",
            },
        ]

        activity = get_soc_threat_activity(user_id=self.user_id, client=self.mock_client)
        case_ids = [a["case_id"] for a in activity]

        self.assertIn("CASE-ACTIVE-THREAT", case_ids)
        self.assertIn("CASE-ACTIVE-SUSPICIOUS", case_ids)
        self.assertNotIn("CASE-CLEAN-NPTEL", case_ids)
        self.assertNotIn("CASE-CLEAN-GOOGLE", case_ids)
        self.assertNotIn("CASE-CLOSED-THREAT", case_ids)
        self.assertEqual(len(activity), 2)


# =====================================================================
# 2. Primary IOC Extraction Invariants
# =====================================================================

class TestPrimaryIocExtractionInvariants(unittest.TestCase):
    """Verify _extract_primary_ioc extracts true IOCs and never treats
    benign domains or authentication alignment text as IOCs."""

    def test_benign_nptel_email_returns_na(self):
        """Benign NPTEL email without threat indicators must return 'N/A' (never 'nptel.iitm.ac.in')."""
        case_data = {
            "sender": "onlinecourses@nptel.iitm.ac.in",
            "threat_verdict": "Standard / Legitimate",
            "risk_score": "LOW",
            "indicators": [],
            "rule_findings": [],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "N/A")
        self.assertNotEqual(ioc, "nptel.iitm.ac.in")

    def test_benign_google_alert_returns_na(self):
        """Benign Google Security Alert without threat indicators must return 'N/A' (never 'accounts.google.com')."""
        case_data = {
            "sender": "no-reply@accounts.google.com",
            "threat_verdict": "Standard / Legitimate",
            "risk_score": "LOW",
            "indicators": [],
            "rule_findings": [],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "N/A")
        self.assertNotEqual(ioc, "accounts.google.com")

    def test_clean_classification_returns_na(self):
        """Email explicitly marked classification='CLEAN' must return 'N/A'."""
        case_data = {
            "sender": "noreply@github.com",
            "classification": "CLEAN",
            "indicators": [],
            "rule_findings": [],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "N/A")

    def test_threat_with_actual_url_extracts_url(self):
        """Email with actual threat URL indicator must extract the URL."""
        case_data = {
            "sender": "security@paypal-verify-account.com",
            "classification": "THREAT",
            "risk_score": "HIGH",
            "indicators": [
                {"type": "URL", "value": "https://paypal.evil-phish.com/login"}
            ],
            "rule_findings": [],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "https://paypal.evil-phish.com/login")

    def test_threat_with_actual_ip_extracts_ip(self):
        """Email with actual threat IP indicator must extract the IP."""
        case_data = {
            "sender": "admin@malicious-relay.org",
            "classification": "THREAT",
            "risk_score": "HIGH",
            "indicators": [
                {"type": "IP", "value": "198.51.100.23"}
            ],
            "rule_findings": [],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "198.51.100.23")

    def test_threat_with_rule_finding_url_extracts_url(self):
        """Email with actual URL in non-auth rule finding must extract the URL."""
        case_data = {
            "sender": "spoofer@evil.com",
            "classification": "THREAT",
            "risk_score": "HIGH",
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-019",
                    "finding": "Hyperlink Anchor Spoof",
                    "evidence": "http://evil-harvester.xyz/login",
                    "severity": "HIGH",
                }
            ],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "http://evil-harvester.xyz/login")

    def test_auth_evidence_rule014_never_extracted_as_ioc(self):
        """RULE-014 DMARC/SPF authentication evidence text must NEVER be extracted as an IOC."""
        case_data = {
            "sender": "onlinecourses@nptel.iitm.ac.in",
            "threat_verdict": "Standard / Legitimate",
            "risk_score": "LOW",
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-014",
                    "finding": "DMARC Alignment Failure / Domain Spoofing",
                    "evidence": "Sender passed SPF/DKIM on third-party domain (Envelope: 'nptel.iitm.ac.in', DKIM-d: 'nptel-iitm-ac-in.20251104.gappssmtp.com'), but domain is unaligned with visible Header-From ('nptel.iitm.ac.in').",
                    "severity": "HIGH",
                }
            ],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertNotIn("Sender passed", ioc)
        self.assertNotIn("SPF/DKIM", ioc)
        self.assertEqual(ioc, "N/A", "Benign email with RULE-014 must return 'N/A'")

    def test_auth_evidence_rule013_never_extracted_as_ioc(self):
        """RULE-013 SPF/DKIM failure evidence text must NEVER be extracted as an IOC."""
        case_data = {
            "sender": "no-reply@accounts.google.com",
            "threat_verdict": "Standard / Legitimate",
            "risk_score": "LOW",
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-013",
                    "finding": "SPF/DKIM Authentication Failure",
                    "evidence": "SPF check returned softfail for domain accounts.google.com",
                    "severity": "MEDIUM",
                }
            ],
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertNotIn("SPF check", ioc)
        self.assertEqual(ioc, "N/A", "Benign email with RULE-013 must return 'N/A'")


# =====================================================================
# 3. Bulk Close Controls & Evidence Preservation
# =====================================================================

class TestBulkCloseControlsAndEvidencePreservation(unittest.TestCase):
    """Verify close_all_open_cases and clear_threat_activity enforce
    RLS tenant isolation, fail closed on unauthenticated access, and
    strictly preserve forensic evidence and SHA-256 hashes."""

    def setUp(self):
        self.user_a = "tenant_alpha"
        self.user_b = "tenant_bravo"
        self.client_a = MagicMock()
        self.client_b = MagicMock()

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    @patch("core.case_store.update_case_metadata", return_value=True)
    def test_close_all_open_cases_success(self, mock_update, mock_get_cases, mock_auth):
        """close_all_open_cases closes all open cases for the authenticated user."""
        mock_get_cases.return_value = [
            {"case_id": "CASE-001", "user_id": self.user_a, "status": "Open"},
            {"case_id": "CASE-002", "user_id": self.user_a, "status": "Investigating"},
            {"case_id": "CASE-003", "user_id": self.user_a, "status": "Closed"},
        ]

        res = close_all_open_cases(user_id=self.user_a, client=self.client_a)

        self.assertTrue(res["success"])
        self.assertEqual(res["closed_count"], 2)
        self.assertEqual(mock_update.call_count, 2)
        mock_update.assert_any_call(case_id="CASE-001", status="Closed", client=self.client_a)
        mock_update.assert_any_call(case_id="CASE-002", status="Closed", client=self.client_a)

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    @patch("core.case_store.update_case_metadata", return_value=True)
    @patch("core.case_store._delete_single_case")
    def test_close_all_open_cases_preserves_evidence_and_hashes(self, mock_del, mock_update, mock_get_cases, mock_auth):
        """Forensic Evidence Invariant: close_all_open_cases must NEVER delete cases,
        files, or hashes. Only updates status to 'Closed'."""
        case_with_evidence = {
            "case_id": "CASE-EVIDENCE-001",
            "user_id": self.user_a,
            "status": "Open",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "raw_json": '{"evidence_files": ["msg.eml"], "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}',
            "preserve_evidence": True,
        }
        mock_get_cases.return_value = [case_with_evidence]

        res = close_all_open_cases(user_id=self.user_a, client=self.client_a)

        self.assertTrue(res["success"])
        # _delete_single_case must NEVER be called
        mock_del.assert_not_called()
        # update_case_metadata must only be called with status='Closed'
        mock_update.assert_called_once_with(case_id="CASE-EVIDENCE-001", status="Closed", client=self.client_a)

    def test_close_all_open_cases_unauthenticated_fails_closed(self):
        """Unauthenticated caller must fail closed with success=False."""
        res = close_all_open_cases(user_id=None, client=None)
        self.assertFalse(res["success"])
        self.assertEqual(res.get("closed_count", 0), 0)

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    @patch("core.case_store.update_case_metadata", return_value=True)
    def test_close_all_open_cases_cross_tenant_isolation(self, mock_update, mock_get_cases, mock_auth):
        """Cross-tenant isolation: User A cannot close User B's cases."""
        mock_get_cases.return_value = [
            {"case_id": "CASE-TENANT-A", "user_id": self.user_a, "status": "Open"},
            {"case_id": "CASE-TENANT-B", "user_id": self.user_b, "status": "Open"},
        ]

        res = close_all_open_cases(user_id=self.user_a, client=self.client_a)

        self.assertTrue(res["success"])
        self.assertEqual(res["closed_count"], 1)
        mock_update.assert_called_once_with(case_id="CASE-TENANT-A", status="Closed", client=self.client_a)

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    @patch("core.case_store.update_case_metadata", return_value=True)
    def test_clear_threat_activity_closes_only_active_threat_cases(self, mock_update, mock_get_cases, mock_auth):
        """clear_threat_activity closes only active THREAT and SUSPICIOUS cases.
        Benign/clean cases and already closed cases are NOT affected."""
        mock_get_cases.return_value = [
            # 1. Active Threat -> MUST be closed
            {
                "case_id": "CASE-THREAT-ACTIVE",
                "user_id": self.user_a,
                "status": "Open",
                "classification": "THREAT",
                "risk_score": "HIGH",
            },
            # 2. Active Suspicious -> MUST be closed
            {
                "case_id": "CASE-SUSP-ACTIVE",
                "user_id": self.user_a,
                "status": "Open",
                "classification": "SUSPICIOUS",
                "risk_score": "MEDIUM",
            },
            # 3. Clean NPTEL Email -> MUST NOT be closed (unaffected)
            {
                "case_id": "CASE-CLEAN-NPTEL",
                "user_id": self.user_a,
                "status": "Open",
                "sender": "onlinecourses@nptel.iitm.ac.in",
                "threat_verdict": "Standard / Legitimate",
                "risk_score": "LOW",
            },
            # 4. Clean Google Alert -> MUST NOT be closed (unaffected)
            {
                "case_id": "CASE-CLEAN-GOOGLE",
                "user_id": self.user_a,
                "status": "Open",
                "sender": "no-reply@accounts.google.com",
                "threat_verdict": "Standard / Legitimate",
                "risk_score": "LOW",
            },
            # 5. Already Closed Threat -> MUST NOT be re-closed
            {
                "case_id": "CASE-ALREADY-CLOSED",
                "user_id": self.user_a,
                "status": "Closed",
                "classification": "THREAT",
                "risk_score": "HIGH",
            },
        ]

        res = clear_threat_activity(user_id=self.user_a, client=self.client_a)

        self.assertTrue(res["success"])
        self.assertEqual(res["cleared_count"], 2)
        self.assertEqual(mock_update.call_count, 2)
        mock_update.assert_any_call(case_id="CASE-THREAT-ACTIVE", status="Closed", client=self.client_a)
        mock_update.assert_any_call(case_id="CASE-SUSP-ACTIVE", status="Closed", client=self.client_a)

    def test_clear_threat_activity_unauthenticated_fails_closed(self):
        """Unauthenticated call to clear_threat_activity must return success=False."""
        res = clear_threat_activity(user_id=None, client=None)
        self.assertFalse(res["success"])
        self.assertEqual(res.get("cleared_count", 0), 0)

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    @patch("core.case_store.update_case_metadata", return_value=True)
    def test_clear_threat_activity_cross_tenant_isolation(self, mock_update, mock_get_cases, mock_auth):
        """Cross-tenant isolation: User A cannot clear User B's threat cases."""
        mock_get_cases.return_value = [
            {
                "case_id": "CASE-THREAT-TENANT-A",
                "user_id": self.user_a,
                "status": "Open",
                "classification": "THREAT",
            },
            {
                "case_id": "CASE-THREAT-TENANT-B",
                "user_id": self.user_b,
                "status": "Open",
                "classification": "THREAT",
            },
        ]

        res = clear_threat_activity(user_id=self.user_a, client=self.client_a)

        self.assertTrue(res["success"])
        self.assertEqual(res["cleared_count"], 1)
        mock_update.assert_called_once_with(case_id="CASE-THREAT-TENANT-A", status="Closed", client=self.client_a)

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    @patch("core.case_store.update_case_metadata", return_value=True)
    @patch("core.case_store._delete_single_case")
    def test_clear_threat_activity_preserves_evidence(self, mock_del, mock_update, mock_get_cases, mock_auth):
        """clear_threat_activity preserves all forensic evidence files and SHA-256 hashes."""
        mock_get_cases.return_value = [
            {
                "case_id": "CASE-THREAT-PRESERVE",
                "user_id": self.user_a,
                "status": "Open",
                "classification": "THREAT",
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            }
        ]

        res = clear_threat_activity(user_id=self.user_a, client=self.client_a)

        self.assertTrue(res["success"])
        mock_del.assert_not_called()
        mock_update.assert_called_once_with(case_id="CASE-THREAT-PRESERVE", status="Closed", client=self.client_a)


if __name__ == "__main__":
    unittest.main()
