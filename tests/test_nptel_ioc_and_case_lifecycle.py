"""
EMAILSHIELD INDIA — NPTEL IOC Bug + Case Lifecycle Regression Tests

Tests covering:
1. _extract_primary_ioc does NOT return authentication alignment text as IOC
2. RULE-014 evidence is never displayed as primary IOC
3. Legitimate NPTEL email classification
4. close_case authorization enforcement
5. Closed case filtering from active views
6. Evidence preservation after close
"""
import unittest
from unittest.mock import patch, MagicMock
from core.case_store import (
    _extract_primary_ioc,
    close_case,
    close_all_open_cases,
    clear_threat_activity,
    get_soc_investigation_queue,
    get_soc_threat_activity,
    derive_case_classification,
    derive_case_severity,
    update_case_metadata,
    is_authorized_caller,
    get_case_record,
)
from core.auth_claims import evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk


# =====================================================================
# 1. _extract_primary_ioc — Authentication Evidence Must NOT Be IOC
# =====================================================================

class TestExtractPrimaryIocAuthEvidence(unittest.TestCase):
    """Verify authentication alignment text is NEVER returned as an IOC and clean emails do not return benign domains."""

    def test_rule014_dmarc_reason_not_treated_as_ioc(self):
        """RULE-014 evidence containing 'Sender passed SPF/DKIM on third-party domain' must be skipped, returning N/A for clean."""
        case_data = {
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-014",
                    "finding": "DMARC Alignment Failure / Domain Spoofing",
                    "evidence": "Sender passed SPF/DKIM on third-party domain (Envelope: 'nptel.iitm.ac.in', DKIM-d: 'nptel-iitm-ac-in.20251104.gappssmtp.com'), but domain is unaligned with visible Header-From ('nptel.iitm.ac.in').",
                    "severity": "HIGH",
                },
            ],
            "sender": "onlinecourses@nptel.iitm.ac.in"
        }
        ioc = _extract_primary_ioc(case_data)
        # Must NOT contain the auth evidence text
        self.assertNotIn("Sender passed", ioc)
        self.assertNotIn("SPF/DKIM", ioc)
        # Benign clean emails must NOT return sender domain as IOC
        self.assertEqual(ioc, "N/A")

    def test_rule013_auth_evidence_skipped(self):
        """RULE-013 authentication evidence must also be skipped, returning N/A for clean."""
        case_data = {
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-013",
                    "finding": "SPF/DKIM Authentication Failure",
                    "evidence": "SPF failed for domain example.com",
                    "severity": "MEDIUM",
                },
            ],
            "sender": "test@example.com"
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertNotIn("SPF failed", ioc)
        self.assertEqual(ioc, "N/A")

    def test_real_url_ioc_still_extracted(self):
        """Actual URL IOCs in non-auth rule findings must still be extracted."""
        case_data = {
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-019",
                    "finding": "Hyperlink Anchor Spoof",
                    "evidence": "URL: https://evil-phish.example.com/login | Visible: PayPal",
                    "severity": "HIGH",
                },
            ],
            "sender": "test@example.com"
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertIn("https://evil-phish", ioc)

    def test_indicator_url_takes_priority(self):
        """Actual IOC indicators take priority over rule findings."""
        case_data = {
            "indicators": [
                {"type": "URL", "value": "https://malicious.example.com/phish"}
            ],
            "rule_findings": [
                {
                    "rule_id": "RULE-014",
                    "finding": "DMARC Alignment Failure",
                    "evidence": "Sender passed SPF/DKIM on third-party domain...",
                    "severity": "HIGH",
                },
            ],
            "sender": "test@example.com"
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertIn("malicious.example.com", ioc)

    def test_no_fallback_to_sender_domain_for_clean_email(self):
        """When no indicators or URL findings exist, clean emails return N/A instead of sender domain."""
        case_data = {
            "indicators": [],
            "rule_findings": [],
            "sender": "admin@trusted.gov.in"
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "N/A")

    def test_no_false_positive_on_dot_in_domain_in_evidence(self):
        """Old bug: '.in' substring in evidence text matched domain TLDs. Must not happen."""
        case_data = {
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-014",
                    "finding": "DMARC Alignment Failure",
                    "evidence": "Sender passed SPF/DKIM on third-party domain (Envelope: 'bounce@example.co.in', DKIM-d: 'proxy.gappssmtp.com')",
                    "severity": "HIGH",
                },
            ],
            "sender": "noreply@example.co.in"
        }
        ioc = _extract_primary_ioc(case_data)
        # Must NOT return the auth evidence text or benign domain
        self.assertNotIn("Sender passed", ioc)
        self.assertEqual(ioc, "N/A")

    def test_spoofed_lookalike_threat_returns_sender_domain(self):
        """When email is THREAT or SUSPICIOUS and has lookalike finding, return sender domain."""
        case_data = {
            "indicators": [],
            "classification": "THREAT",
            "rule_findings": [
                {
                    "rule_id": "RULE-002",
                    "finding": "Lookalike Domain / Typosquatting",
                    "evidence": "paypa1.com mimics paypal.com",
                    "severity": "HIGH",
                }
            ],
            "sender": "security@paypa1.com"
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "paypa1.com")

    def test_clean_email_benign_domain_indicator_ignored(self):
        """Domain indicator matching clean email sender domain must not be returned as IOC."""
        case_data = {
            "classification": "CLEAN",
            "indicators": [
                {"type": "domain", "value": "nptel.iitm.ac.in"}
            ],
            "rule_findings": [],
            "sender": "onlinecourses@nptel.iitm.ac.in"
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "N/A")


# =====================================================================
# 2. NPTEL Classification — Auth PASS Must NOT Produce False Suspicious
# =====================================================================

class TestNptelClassification(unittest.TestCase):
    """Verify legitimate NPTEL emails are classified correctly."""

    def _make_nptel_headers(self, include_dmarc_pass=True):
        """Build NPTEL email headers with optional dmarc=pass."""
        auth_results = "mx.google.com; dkim=pass header.d=nptel-iitm-ac-in.20251104.gappssmtp.com; spf=pass"
        if include_dmarc_pass:
            auth_results += "; dmarc=pass header.from=nptel.iitm.ac.in"
        return {
            "from": "onlinecourses@nptel.iitm.ac.in",
            "subject": "Introduction to Internet of Things - Assignment Solutions for Week 9",
            "return-path": "<noc26-cs161-announce+bncBCZ5RXNBUUOBBPWIT7KQMGQES36WPII@nptel.iitm.ac.in>",
            "dkim-signature": "v=1; a=rsa-sha256; d=nptel-iitm-ac-in.20251104.gappssmtp.com; s=20251104;",
            "authentication-results": auth_results,
            "list-unsubscribe": "<https://groups.google.com/a/nptel.iitm.ac.in/group/noc26-cs161-announce/subscribe>"
        }

    def test_nptel_with_dmarc_pass_no_rule014(self):
        """NPTEL with dmarc=pass in auth-results must NOT trigger RULE-014."""
        headers = self._make_nptel_headers(include_dmarc_pass=True)
        auth = evaluate_auth_and_alignment(headers)
        self.assertIn("PASS", auth["effective_dmarc"])
        self.assertFalse(auth["threat_detected"])

        findings = evaluate_rules({"headers": headers, "body": "Week 9 content"}, auth_alignment=auth)
        rule014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertEqual(len(rule014), 0, "RULE-014 must not fire for authenticated NPTEL")

    def test_nptel_without_dmarc_pass_google_workspace_aligned(self):
        """NPTEL without explicit dmarc=pass but with Google Workspace DKIM alignment should still pass."""
        headers = self._make_nptel_headers(include_dmarc_pass=False)
        auth = evaluate_auth_and_alignment(headers)
        # The Google Workspace convention decoding should align the DKIM
        # Even if effective_dmarc is PASS via SPF+DKIM alignment
        self.assertFalse(
            auth.get("threat_detected", False),
            f"Legitimate NPTEL must not be threat_detected. Got effective_dmarc={auth['effective_dmarc']}"
        )

    def test_nptel_auth_evidence_not_in_primary_ioc(self):
        """Even if RULE-014 fires, primary_ioc must not show auth text."""
        case_data = {
            "indicators": [],
            "rule_findings": [
                {
                    "rule_id": "RULE-014",
                    "finding": "DMARC Alignment Failure",
                    "evidence": "Sender passed SPF/DKIM on third-party domain (Envelope: 'nptel.iitm.ac.in')",
                    "severity": "HIGH",
                },
            ],
            "sender": "onlinecourses@nptel.iitm.ac.in"
        }
        ioc = _extract_primary_ioc(case_data)
        self.assertEqual(ioc, "N/A")
        self.assertNotIn("Sender passed", ioc)


# =====================================================================
# 3. Close Case — Authorization & Lifecycle
# =====================================================================

class TestCloseCaseAuthorization(unittest.TestCase):
    """Verify close_case enforces authentication and RLS."""

    @patch("core.case_store.is_authorized_caller", return_value=False)
    def test_close_case_unauthenticated_denied(self, mock_auth):
        """Anonymous/unauthenticated close must be denied."""
        success, err = close_case(case_id="CASE-TEST-001", user_id=None, client=None)
        self.assertFalse(success)
        self.assertIn("denied", err.lower())

    @patch("core.case_store.is_authorized_caller", return_value=False)
    def test_close_case_wrong_user_denied(self, mock_auth):
        """User trying to close another user's case must be denied."""
        success, err = close_case(case_id="CASE-OTHER-USER", user_id="user_b", client=MagicMock())
        self.assertFalse(success)
        self.assertIn("denied", err.lower())

    def test_close_case_invalid_id(self):
        """Invalid case ID must be rejected."""
        success, err = close_case(case_id="", user_id="test_user")
        self.assertFalse(success)
        self.assertIn("invalid", err.lower())

    def test_close_case_none_id(self):
        """None case ID must be rejected."""
        success, err = close_case(case_id=None, user_id="test_user")
        self.assertFalse(success)

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_case_record", return_value=None)
    def test_close_case_nonexistent_case(self, mock_rec, mock_auth):
        """Closing a nonexistent case must fail gracefully."""
        success, err = close_case(case_id="CASE-NONEXISTENT", user_id="test_user")
        self.assertFalse(success)
        self.assertIn("not found", err.lower())

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_case_record", return_value={"status": "Closed"})
    def test_close_case_already_closed(self, mock_rec, mock_auth):
        """Closing an already-closed case is idempotent."""
        success, err = close_case(case_id="CASE-CLOSED", user_id="test_user")
        self.assertTrue(success)
        self.assertIn("already", err.lower())

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_case_record", return_value={"status": "Open", "case_id": "CASE-OPEN-001"})
    @patch("core.case_store.update_case_metadata", return_value=True)
    def test_close_case_success(self, mock_update, mock_rec, mock_auth):
        """Authorized close of an open case must succeed."""
        success, err = close_case(case_id="CASE-OPEN-001", user_id="test_user")
        self.assertTrue(success)
        self.assertEqual(err, "")
        mock_update.assert_called_once_with(case_id="CASE-OPEN-001", status="Closed", client=None)


# =====================================================================
# 4. Closed Cases Filtered from Active Views
# =====================================================================

class TestClosedCaseFiltering(unittest.TestCase):
    """Verify closed cases don't appear in active dashboard views."""

    def _make_case(self, case_id, status="Open", severity="MEDIUM", risk_score="SUSPICIOUS"):
        return {
            "case_id": case_id,
            "timestamp": "2026-09-20T12:00:00",
            "sender": "test@example.com",
            "subject": "Test Subject",
            "status": status,
            "case_severity": severity,
            "risk_score": risk_score,
            "rule_findings": [],
            "indicators": [],
        }

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_closed_case_excluded_from_investigation_queue(self, mock_cases, mock_auth):
        """Closed cases must NOT appear in the Active Incident Triage Queue."""
        mock_cases.return_value = [
            self._make_case("CASE-OPEN", status="Open"),
            self._make_case("CASE-CLOSED", status="Closed"),
            self._make_case("CASE-ACTIVE", status="Active"),
        ]
        queue = get_soc_investigation_queue(user_id="test", client=MagicMock())
        case_ids = [q["case_id"] for q in queue]
        self.assertIn("CASE-OPEN", case_ids)
        self.assertIn("CASE-ACTIVE", case_ids)
        self.assertNotIn("CASE-CLOSED", case_ids)

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_closed_case_excluded_from_threat_activity(self, mock_cases, mock_auth):
        """Closed cases must NOT appear in Recent Threat Activity."""
        mock_cases.return_value = [
            self._make_case("CASE-OPEN", status="Open"),
            self._make_case("CASE-CLOSED", status="Closed"),
        ]
        activity = get_soc_threat_activity(user_id="test", client=MagicMock())
        case_ids = [a["case_id"] for a in activity]
        self.assertIn("CASE-OPEN", case_ids)
        self.assertNotIn("CASE-CLOSED", case_ids)

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_closed_case_case_insensitive(self, mock_cases, mock_auth):
        """Closed status check must be case-insensitive."""
        mock_cases.return_value = [
            self._make_case("CASE-1", status="closed"),
            self._make_case("CASE-2", status="CLOSED"),
            self._make_case("CASE-3", status=" Closed "),
        ]
        queue = get_soc_investigation_queue(user_id="test", client=MagicMock())
        case_ids = [q["case_id"] for q in queue]
        self.assertEqual(len(case_ids), 0, "All closed cases should be filtered out")


# =====================================================================
# 5. Evidence Preservation After Close
# =====================================================================

class TestEvidencePreservation(unittest.TestCase):
    """Verify close_case preserves forensic evidence."""

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_case_record")
    @patch("core.case_store.update_case_metadata", return_value=True)
    def test_close_only_updates_status(self, mock_update, mock_rec, mock_auth):
        """close_case must ONLY update status field — nothing else."""
        mock_rec.return_value = {
            "case_id": "CASE-PRESERVE",
            "status": "Open",
            "rule_findings": [{"rule_id": "RULE-001", "severity": "MEDIUM"}],
            "indicators": [{"type": "URL", "value": "https://example.com"}],
        }
        success, _ = close_case(case_id="CASE-PRESERVE", user_id="test_user")
        self.assertTrue(success)
        # Verify only status was updated
        mock_update.assert_called_once_with(
            case_id="CASE-PRESERVE",
            status="Closed",
            client=None
        )
        # update_case_metadata was NOT called with any other fields
        call_kwargs = mock_update.call_args[1]
        self.assertNotIn("rule_findings", call_kwargs)
        self.assertNotIn("indicators", call_kwargs)
        self.assertNotIn("analyst_notes", call_kwargs)


# =====================================================================
# 6. Spoofed/Malicious NPTEL Variant Must Still Detect
# =====================================================================

class TestMaliciousNptelVariant(unittest.TestCase):
    """Ensure genuine threats from NPTEL-like domains are still detected."""

    def test_nptel_lookalike_with_phishing_url(self):
        """An NPTEL lookalike domain with phishing URL must still produce HIGH."""
        headers = {
            "from": "onlinecourses@nptel-iitm.fake.com",
            "subject": "Urgent: Your NPTEL Account Will Be Suspended",
            "return-path": "<bounce@nptel-iitm.fake.com>",
            "authentication-results": "mx.google.com; dkim=fail; spf=fail; dmarc=fail"
        }
        auth = evaluate_auth_and_alignment(headers)
        self.assertEqual(auth["effective_dmarc"], "FAIL")
        self.assertTrue(auth["threat_detected"])

    def test_genuine_auth_failure_contributes_to_risk(self):
        """SPF/DKIM/DMARC failure is auth evidence that can contribute to risk."""
        headers = {
            "from": "admin@important-bank.com",
            "return-path": "<bounce@completely-different.ru>",
            "authentication-results": "mx.google.com; dkim=fail; spf=fail; dmarc=fail"
        }
        auth = evaluate_auth_and_alignment(headers)
        self.assertTrue(auth["threat_detected"])
        self.assertIn("FAIL", auth["effective_dmarc"])


# =====================================================================
# 7. Bulk Case Operations: close_all_open_cases & clear_threat_activity
# =====================================================================

class TestCloseAllOpenCases(unittest.TestCase):
    """Verify close_all_open_cases behavior, authorization, and multi-store support."""

    @patch("core.case_store.is_authorized_caller", return_value=False)
    def test_unauthenticated_fails_closed(self, mock_auth):
        """Unauthenticated caller must receive error and closed_count 0."""
        res = close_all_open_cases(user_id=None, client=None)
        self.assertFalse(res["success"])
        self.assertEqual(res["closed_count"], 0)
        self.assertIn("Access denied", res["error"])

    @patch("core.case_store.is_authorized_caller", return_value=True)
    def test_supabase_client_bulk_close(self, mock_auth):
        """When client is provided, executes bulk update on Supabase cases table."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_update = MagicMock()
        mock_eq = MagicMock()
        mock_exec = MagicMock()

        mock_client.table.return_value = mock_table
        mock_table.update.return_value = mock_update
        mock_update.eq.return_value = mock_eq
        mock_eq.execute.return_value = MagicMock(data=[{"id": "1"}, {"id": "2"}])

        with patch("os.path.exists", return_value=False):
            res = close_all_open_cases(user_id="user_123", client=mock_client)

        self.assertTrue(res["success"])
        self.assertEqual(res["closed_count"], 2)
        mock_client.table.assert_called_with("cases")
        mock_table.update.assert_called_with({"status": "Closed"})
        mock_update.eq.assert_called_with("status", "Open")


class TestClearThreatActivity(unittest.TestCase):
    """Verify clear_threat_activity bulk-closes open threats while preserving clean cases."""

    @patch("core.case_store.is_authorized_caller", return_value=False)
    def test_unauthenticated_fails_closed(self, mock_auth):
        """Unauthenticated caller must receive error and cleared_count 0."""
        res = clear_threat_activity(user_id=None, client=None)
        self.assertFalse(res["success"])
        self.assertEqual(res["cleared_count"], 0)
        self.assertIn("Access denied", res["error"])

    @patch("core.case_store.is_authorized_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    @patch("core.case_store.close_case", return_value=(True, ""))
    def test_closes_only_threat_and_suspicious_cases(self, mock_close, mock_get_cases, mock_auth):
        """Only THREAT/SUSPICIOUS or CRITICAL/HIGH/MEDIUM cases are closed; clean cases are skipped."""
        mock_get_cases.return_value = [
            {"case_id": "CASE-THREAT-1", "classification": "THREAT", "case_severity": "HIGH", "status": "Open"},
            {"case_id": "CASE-SUSP-2", "classification": "SUSPICIOUS", "case_severity": "MEDIUM", "status": "Open"},
            {"case_id": "CASE-CLEAN-3", "classification": "CLEAN", "case_severity": "LOW", "status": "Open"},
            {"case_id": "CASE-ALREADY-CLOSED", "classification": "THREAT", "case_severity": "CRITICAL", "status": "Closed"},
        ]
        res = clear_threat_activity(user_id="user_123", client=MagicMock())
        self.assertTrue(res["success"])
        self.assertEqual(res["cleared_count"], 2)
        # Verify close_case was called for the 2 open threats, and NOT for the clean or already closed cases
        closed_ids = [call.kwargs.get("case_id") or call.args[0] for call in mock_close.call_args_list]
        self.assertIn("CASE-THREAT-1", closed_ids)
        self.assertIn("CASE-SUSP-2", closed_ids)
        self.assertNotIn("CASE-CLEAN-3", closed_ids)
        self.assertNotIn("CASE-ALREADY-CLOSED", closed_ids)


class TestGetSocThreatActivityFiltering(unittest.TestCase):
    """Verify get_soc_threat_activity filters out clean cases and masks sensitive data."""

    @patch("core.case_store.is_authenticated_soc_caller", return_value=True)
    @patch("core.case_store.get_all_cases")
    def test_clean_cases_excluded_from_threat_activity(self, mock_get_cases, mock_auth):
        """Clean cases must NOT appear in recent threat activity."""
        mock_get_cases.return_value = [
            {"case_id": "CASE-CLEAN", "classification": "CLEAN", "case_severity": "LOW", "status": "Open", "subject": "Clean newsletter"},
            {"case_id": "CASE-THREAT", "classification": "THREAT", "case_severity": "HIGH", "status": "Open", "subject": "Your OTP 123456 is ready"},
        ]
        activity = get_soc_threat_activity(user_id="test_user", client=MagicMock(), limit=10)
        self.assertEqual(len(activity), 1)
        self.assertEqual(activity[0]["case_id"], "CASE-THREAT")
        # Verify OTP is masked
        self.assertNotIn("123456", activity[0]["subject"])
        self.assertIn("••••••", activity[0]["subject"])


if __name__ == "__main__":
    unittest.main()
