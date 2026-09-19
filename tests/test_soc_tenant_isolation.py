"""
tests/test_soc_tenant_isolation.py
Unit tests for multi-tenant isolation across all SOC Operations Dashboard queries.

Verifies:
1. User A sees only User A's KPI metrics; User B sees only User B's KPI metrics.
2. Threat distribution is isolated per-tenant.
3. Recent threat activity is isolated per-tenant and masks OTP/passcode tokens.
4. Active investigation queue is isolated per-tenant and prioritises by severity.
5. In public multi-user mode, unauthenticated queries fail closed (zero counts / empty lists).
"""

import os
import unittest
from unittest.mock import MagicMock, patch
from core.case_store import (
    get_soc_kpi_metrics,
    get_soc_threat_distribution,
    get_soc_threat_activity,
    get_soc_investigation_queue,
)


class TestSOCTenantIsolation(unittest.TestCase):

    def _create_mock_client(self, user_cases):
        """Build a mock Supabase client returning specific cases for the user."""
        mock_client = MagicMock()
        mock_query = MagicMock()
        mock_query.select.return_value = mock_query
        mock_query.order.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.execute.return_value = MagicMock(data=[
            {
                "case_number": c["case_id"],
                "status": c.get("status", "Open"),
                "assigned_investigator": c.get("assigned_investigator", "Unassigned"),
                "analyst_notes": c.get("analyst_notes", ""),
                "case_severity": c.get("case_severity", "MEDIUM"),
                "raw_json": c
            }
            for c in user_cases
        ])
        mock_client.table.return_value = mock_query
        return mock_client

    def test_01_soc_kpi_metrics_tenant_isolated(self):
        """User A and User B receive strictly isolated KPI metrics."""
        cases_a = [
            {"case_id": "CASE-A-01", "threat_verdict": "Phishing", "risk_score": "HIGH", "case_severity": "HIGH", "status": "Open"},
            {"case_id": "CASE-A-02", "threat_verdict": "Standard / Legitimate", "risk_score": "LOW", "case_severity": "LOW", "status": "Closed"},
        ]
        cases_b = [
            {"case_id": "CASE-B-01", "threat_verdict": "Malware Delivery", "risk_score": "CRITICAL", "case_severity": "CRITICAL", "status": "Open"},
            {"case_id": "CASE-B-02", "threat_verdict": "Credential Harvesting", "risk_score": "HIGH", "case_severity": "HIGH", "status": "Open"},
            {"case_id": "CASE-B-03", "threat_verdict": "Phishing Lure", "risk_score": "SUSPICIOUS", "case_severity": "MEDIUM", "status": "Open"},
        ]

        client_a = self._create_mock_client(cases_a)
        client_b = self._create_mock_client(cases_b)

        metrics_a = get_soc_kpi_metrics(user_id="user_a", client=client_a)
        metrics_b = get_soc_kpi_metrics(user_id="user_b", client=client_b)

        self.assertEqual(metrics_a["emails_analysed"], 2)
        self.assertEqual(metrics_a["threats_detected"], 1)
        self.assertEqual(metrics_a["high_critical"], 1)
        self.assertEqual(metrics_a["open_investigations"], 1)

        self.assertEqual(metrics_b["emails_analysed"], 3)
        self.assertEqual(metrics_b["threats_detected"], 3)
        self.assertEqual(metrics_b["high_critical"], 2)
        self.assertEqual(metrics_b["open_investigations"], 3)

    def test_02_soc_threat_distribution_tenant_isolated(self):
        """Threat distribution reflects only the authenticated tenant's data."""
        cases_a = [
            {"case_id": "CASE-A-01", "threat_verdict": "Standard / Legitimate", "risk_score": "LOW", "case_severity": "LOW"},
            {"case_id": "CASE-A-02", "threat_verdict": "Standard / Legitimate", "risk_score": "LOW", "case_severity": "LOW"},
        ]
        cases_b = [
            {"case_id": "CASE-B-01", "threat_verdict": "Malware Delivery", "risk_score": "CRITICAL", "case_severity": "CRITICAL"},
            {"case_id": "CASE-B-02", "threat_verdict": "Credential Harvesting", "risk_score": "HIGH", "case_severity": "HIGH"},
        ]

        client_a = self._create_mock_client(cases_a)
        client_b = self._create_mock_client(cases_b)

        dist_a = get_soc_threat_distribution(user_id="user_a", client=client_a)
        dist_b = get_soc_threat_distribution(user_id="user_b", client=client_b)

        self.assertEqual(dist_a["Clean"], 2)
        self.assertEqual(dist_a["Critical"], 0)

        self.assertEqual(dist_b["Clean"], 0)
        self.assertEqual(dist_b["Critical"], 1)
        self.assertEqual(dist_b["High"], 1)

    def test_03_soc_threat_activity_masks_sensitive_tokens(self):
        """Recent threat activity masks OTPs, PINs, and sensitive passcodes."""
        cases = [
            {
                "case_id": "CASE-SENSITIVE-01",
                "subject": "Your OTP code is 482910 for bank transaction",
                "sender": "alerts@bank-fraud.com",
                "risk_score": "HIGH",
                "case_severity": "HIGH",
                "status": "Open",
                "indicators": [{"type": "domain", "value": "bank-fraud.com"}]
            }
        ]
        client = self._create_mock_client(cases)
        activity = get_soc_threat_activity(user_id="user_a", client=client)

        self.assertEqual(len(activity), 1)
        # 482910 must be masked
        self.assertNotIn("482910", activity[0]["subject"])
        self.assertIn("••••••", activity[0]["subject"])

    def test_04_soc_investigation_queue_severity_prioritisation(self):
        """Investigation queue orders by CRITICAL > HIGH > MEDIUM > LOW."""
        cases = [
            {"case_id": "CASE-LOW", "case_severity": "LOW", "status": "Open", "subject": "Low risk"},
            {"case_id": "CASE-CRIT", "case_severity": "CRITICAL", "status": "Open", "subject": "Critical breach"},
            {"case_id": "CASE-HIGH", "case_severity": "HIGH", "status": "Open", "subject": "Phish lure"},
        ]
        client = self._create_mock_client(cases)
        queue = get_soc_investigation_queue(user_id="user_a", client=client)

        self.assertEqual(len(queue), 3)
        self.assertEqual(queue[0]["case_id"], "CASE-CRIT")
        self.assertEqual(queue[1]["case_id"], "CASE-HIGH")
        self.assertEqual(queue[2]["case_id"], "CASE-LOW")

    def test_05_public_multiuser_unauthenticated_fails_closed(self):
        """In public multi-user mode, unauthenticated queries fail closed with zero/empty results."""
        with patch.dict(os.environ, {"EMAILSHIELD_MODE": "public_multiuser"}):
            metrics = get_soc_kpi_metrics(None, None)
            self.assertEqual(metrics["emails_analysed"], 0)
            self.assertEqual(metrics["threats_detected"], 0)

            dist = get_soc_threat_distribution(None, None)
            self.assertEqual(sum(dist.values()), 0)

            activity = get_soc_threat_activity(None, None)
            self.assertEqual(activity, [])

            queue = get_soc_investigation_queue(None, None)
            self.assertEqual(queue, [])


if __name__ == "__main__":
    unittest.main()
