"""
tests/test_soc_dashboard_audit.py
Verification suite for SOC Operations Dashboard security controls and metric aggregation:
- Bug 1: Unauthenticated callers fail closed (zero metrics, empty lists).
- Bug 2: High / Critical strictly requires (final classification == THREAT and severity in ('HIGH', 'CRITICAL')).
  CLEAN + HIGH -> NO
  SUSPICIOUS + HIGH -> NO
  THREAT + MEDIUM -> NO
  THREAT + HIGH -> YES
  THREAT + CRITICAL -> YES
- Lifecycle: Open investigations count only active cases (OPEN, IN_PROGRESS, ACTIVE, NEW).
"""
import unittest
from unittest.mock import MagicMock, patch
import os

from core.case_store import (
    is_authenticated_soc_caller,
    derive_case_classification,
    derive_case_severity,
    get_soc_kpi_metrics,
    get_soc_threat_distribution,
    get_soc_threat_activity,
    get_soc_investigation_queue,
    get_all_cases,
    get_case_record,
    get_all_indicators,
    export_case_iocs_csv,
    export_case_iocs_json,
)


class TestSOCDashboardAudit(unittest.TestCase):
    """Rigorous audit test cases for Bug 1 and Bug 2."""

    def _create_mock_client(self, cases):
        mock_client = MagicMock()
        data_rows = [
            {
                "case_number": c.get("case_id", "CASE-01"),
                "status": c.get("status", "Open"),
                "case_severity": c.get("case_severity", "MEDIUM"),
                "assigned_investigator": c.get("assigned_investigator", "Unassigned"),
                "analyst_notes": c.get("analyst_notes", ""),
                "raw_json": c
            }
            for c in cases
        ]
        mock_table = MagicMock()
        mock_table.select.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(data=data_rows)
        mock_table.select.return_value.order.return_value.execute.return_value = MagicMock(data=data_rows)
        mock_client.table.return_value = mock_table
        return mock_client

    # =========================================================================
    # BUG 1 TESTS: UNAUTHENTICATED ACCESS MUST FAIL CLOSED
    # =========================================================================

    def test_bug1_unauthenticated_kpi_returns_zeros(self):
        """Unauthenticated requests must receive all zero metrics (fail closed)."""
        metrics = get_soc_kpi_metrics(None, None)
        self.assertEqual(metrics["emails_analysed"], 0)
        self.assertEqual(metrics["threats_detected"], 0)
        self.assertEqual(metrics["high_critical"], 0)
        self.assertEqual(metrics["open_investigations"], 0)

    def test_bug1_unauthenticated_distribution_returns_zeros(self):
        """Unauthenticated requests must receive zero distribution (fail closed)."""
        dist = get_soc_threat_distribution(None, None)
        self.assertEqual(dist["Clean"], 0)
        self.assertEqual(dist["Suspicious"], 0)
        self.assertEqual(dist["High"], 0)
        self.assertEqual(dist["Critical"], 0)

    def test_bug1_unauthenticated_activity_returns_empty(self):
        """Unauthenticated requests must receive empty recent activity list."""
        activity = get_soc_threat_activity(None, None)
        self.assertEqual(activity, [])

    def test_bug1_unauthenticated_queue_returns_empty(self):
        """Unauthenticated requests must receive empty triage queue list."""
        queue = get_soc_investigation_queue(None, None)
        self.assertEqual(queue, [])

    def test_bug1_supabase_configured_without_client_fails_closed(self):
        """When Supabase is configured, providing a user_id without client must fail closed."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            self.assertFalse(is_authenticated_soc_caller(user_id="arbitrary_user", client=None))
            metrics = get_soc_kpi_metrics(user_id="arbitrary_user", client=None)
            self.assertEqual(metrics["emails_analysed"], 0)
            self.assertEqual(metrics["threats_detected"], 0)
            self.assertEqual(metrics["high_critical"], 0)

    # =========================================================================
    # BUG 2 TESTS: AUTHORITATIVE CLASSIFICATION & HIGH/CRITICAL TRUTH TABLE
    # =========================================================================

    def test_bug2_derive_case_classification_clean(self):
        """Legitimate / Benign emails must always classify as CLEAN."""
        clean_cases = [
            {"threat_verdict": "Standard / Legitimate"},
            {"threat_verdict": "Standard / Legitimate (Newsletter / Subscription)"},
            {"threat_verdict": "Standard / Legitimate (Transactional / Billing)"},
            {"threat_verdict": "Verified Clean"},
            {"threat_verdict": "Security Alert / Notification (Authenticated)"},
            {"classification": "CLEAN"},
            {"classification": "BENIGN"},
        ]
        for c in clean_cases:
            self.assertEqual(derive_case_classification(c), "CLEAN", f"Failed for {c}")

    def test_bug2_derive_case_classification_threats(self):
        """Confirmed threat types must classify as THREAT."""
        threat_cases = [
            {"threat_verdict": "Malicious Delivery"},
            {"threat_verdict": "Phishing Lure"},
            {"threat_verdict": "Business Email Compromise (BEC / Wire Fraud)"},
            {"threat_verdict": "Executive Impersonation"},
            {"threat_verdict": "Credential Harvesting"},
            {"threat_verdict": "UPI / Financial Fraud"},
            {"threat_verdict": "Extortion / Blackmail"},
            {"classification": "THREAT"},
            {"threat_detected": True},
        ]
        for c in threat_cases:
            self.assertEqual(derive_case_classification(c), "THREAT", f"Failed for {c}")

    def test_bug2_derive_case_classification_suspicious(self):
        """Suspicious solicitations without confirmed payloads must classify as SUSPICIOUS."""
        susp_cases = [
            {"threat_verdict": "Suspicious Financial / Authority Solicitation"},
            {"threat_verdict": "Suspicious / Unverified Infrastructure"},
            {"classification": "SUSPICIOUS"},
        ]
        for c in susp_cases:
            self.assertEqual(derive_case_classification(c), "SUSPICIOUS", f"Failed for {c}")

    def test_bug2_truth_table_high_critical_rigorous(self):
        """
        Verify the exact truth table specified by the user:
        - CLEAN + HIGH -> NO (high_critical == 0, threats_detected == 0)
        - SUSPICIOUS + HIGH -> NO (high_critical == 0, threats_detected == 0)
        - THREAT + MEDIUM -> NO (high_critical == 0, threats_detected == 1)
        - THREAT + HIGH -> YES (high_critical == 1, threats_detected == 1)
        - THREAT + CRITICAL -> YES (high_critical == 1, threats_detected == 1)
        """
        truth_table = [
            ({"threat_verdict": "Standard / Legitimate", "case_severity": "HIGH", "status": "Open"}, 0, 0, "CLEAN + HIGH"),
            ({"threat_verdict": "Suspicious Financial / Authority Solicitation", "case_severity": "HIGH", "status": "Open"}, 0, 0, "SUSPICIOUS + HIGH"),
            ({"threat_verdict": "Credential Harvesting", "case_severity": "MEDIUM", "status": "Open"}, 1, 0, "THREAT + MEDIUM"),
            ({"threat_verdict": "Phishing Lure", "case_severity": "HIGH", "status": "Open"}, 1, 1, "THREAT + HIGH"),
            ({"threat_verdict": "Malware Delivery", "case_severity": "CRITICAL", "status": "Open"}, 1, 1, "THREAT + CRITICAL"),
        ]

        for case_data, exp_threats, exp_high_crit, label in truth_table:
            client = self._create_mock_client([case_data])
            metrics = get_soc_kpi_metrics(user_id="investigator_1", client=client)
            self.assertEqual(
                metrics["threats_detected"], exp_threats,
                f"[{label}] Expected threats_detected={exp_threats}, got {metrics['threats_detected']}"
            )
            self.assertEqual(
                metrics["high_critical"], exp_high_crit,
                f"[{label}] Expected high_critical={exp_high_crit}, got {metrics['high_critical']}"
            )

    def test_bug2_open_investigations_lifecycle(self):
        """
        Active lifecycle (OPEN, IN_PROGRESS, ACTIVE, NEW) counts toward open_investigations.
        Resolved and closed cases must NOT be counted.
        """
        cases = [
            {"case_id": "C1", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "Open"},
            {"case_id": "C2", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "In Progress"},
            {"case_id": "C3", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "Active"},
            {"case_id": "C4", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "New"},
            {"case_id": "C5", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "Closed"},
            {"case_id": "C6", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "Resolved"},
            {"case_id": "C7", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "Archived"},
        ]
        client = self._create_mock_client(cases)
        metrics = get_soc_kpi_metrics(user_id="investigator_1", client=client)
        self.assertEqual(metrics["emails_analysed"], 7)
        self.assertEqual(metrics["threats_detected"], 7)
        self.assertEqual(metrics["high_critical"], 7)
        self.assertEqual(metrics["open_investigations"], 4)  # Only C1, C2, C3, C4

    def test_bug2_distribution_buckets_integrity(self):
        """
        Threat distribution never misclassifies Clean or Suspicious cases into High/Critical.
        """
        cases = [
            {"threat_verdict": "Standard / Legitimate", "case_severity": "HIGH"},
            {"threat_verdict": "Suspicious Financial", "case_severity": "HIGH"},
            {"threat_verdict": "Phishing Lure", "case_severity": "HIGH"},
            {"threat_verdict": "Malware Delivery", "case_severity": "CRITICAL"},
        ]
        client = self._create_mock_client(cases)
        dist = get_soc_threat_distribution(user_id="investigator_1", client=client)
        self.assertEqual(dist["Clean"], 1)
        self.assertEqual(dist["Suspicious"], 1)
        self.assertEqual(dist["High"], 1)
        self.assertEqual(dist["Critical"], 1)

    # =========================================================================
    # VIEW & EXPORT AUTHORIZATION GAP CLOSURE TESTS
    # =========================================================================

    def test_unauthenticated_exports_fail_closed(self):
        """Unauthenticated callers cannot export IOCs as CSV or JSON when Supabase is configured."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            csv_data = export_case_iocs_csv(client=None)
            self.assertIn("Indicator_Type", csv_data)
            # Must only have the header line, no indicator data rows
            lines = [line.strip() for line in csv_data.strip().splitlines() if line.strip()]
            self.assertEqual(len(lines), 1)

            json_str = export_case_iocs_json(client=None)
            import json
            parsed = json.loads(json_str)
            self.assertEqual(parsed["ioc_count"], 0)
            self.assertEqual(parsed["indicators"], [])

    def test_unauthenticated_case_retrieval_fails_closed(self):
        """Unauthenticated callers cannot retrieve cases or single records when Supabase is configured."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            cases = get_all_cases(client=None)
            self.assertEqual(cases, [])

            rec = get_case_record("CASE-ANY-01", client=None)
            self.assertIsNone(rec)

            inds = get_all_indicators(client=None)
            self.assertEqual(inds, [])

    def test_authenticated_user_accesses_data_successfully(self):
        """Authenticated users with valid client receive their authorized cases and IOCs."""
        sample_cases = [
            {"case_id": "AUTH-01", "threat_verdict": "Phishing", "case_severity": "HIGH", "status": "Open"}
        ]
        client = self._create_mock_client(sample_cases)
        cases = get_all_cases(client=client)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["case_id"], "AUTH-01")


if __name__ == "__main__":
    unittest.main()
