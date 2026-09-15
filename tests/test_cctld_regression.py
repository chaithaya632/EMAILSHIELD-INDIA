"""
tests/test_cctld_regression.py
Regression tests for multi-level ccTLD registrable domain parsing,
academic/institutional alignment (NPTEL), and genuine phishing detection (DHL).
"""

import unittest
from core.indicators import get_registrable_domain
from core.auth_claims import get_org_domain, evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk


class TestCctldRegression(unittest.TestCase):

    def test_registrable_domain_multilevel_cctlds(self):
        """Verify multi-level ccTLD parsing handles academic, governmental, and commercial domains."""
        cases = [
            ("nptel.iitm.ac.in", "iitm.ac.in"),
            ("onlinecourses.nptel.iitm.ac.in", "iitm.ac.in"),
            ("example.gov.in", "example.gov.in"),
            ("example.edu.in", "example.edu.in"),
            ("example.co.in", "example.co.in"),
            ("example.ac.in", "example.ac.in"),
            ("example.co.uk", "example.co.uk"),
            ("example.com", "example.com"),
            ("sub.example.com", "example.com"),
        ]
        for input_dom, expected in cases:
            with self.subTest(input_dom=input_dom):
                self.assertEqual(get_registrable_domain(input_dom), expected)

    def test_auth_claims_get_org_domain(self):
        """Verify get_org_domain in core/auth_claims uses multi-level ccTLD resolution."""
        self.assertEqual(get_org_domain("nptel.iitm.ac.in"), "iitm.ac.in")
        self.assertEqual(get_org_domain("iitm.ac.in"), "iitm.ac.in")
        self.assertEqual(get_org_domain("sub.example.com"), "example.com")
        self.assertEqual(get_org_domain("example.co.in"), "example.co.in")
        self.assertEqual(get_org_domain("scores.gov.in"), "scores.gov.in")

    def test_nptel_dmarc_dkim_alignment_no_bypass(self):
        """Verify NPTEL email with institutional DKIM signature passes relaxed alignment without RULE-014."""
        headers = {
            "from": "onlinecourses@nptel.iitm.ac.in",
            "return-path": "<bounce@nptel.iitm.ac.in>",
            "dkim-signature": "v=1; a=rsa-sha256; d=iitm.ac.in; s=mail;",
            "authentication-results": "mx.google.com; dkim=pass header.i=onlinecourses@nptel.iitm.ac.in header.d=iitm.ac.in"
        }
        auth_res = evaluate_auth_and_alignment(headers)
        self.assertEqual(auth_res["effective_dmarc"], "PASS")
        self.assertFalse(auth_res["threat_detected"])
        self.assertTrue(auth_res["dkim_aligned"])

        parsed_data = {
            "headers": headers,
            "body": "Welcome to week 9. Visit https://swayam.gov.in/courses for details."
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type="Education / Academic")
        rule_014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertEqual(len(rule_014), 0, "RULE-014 must not fire on aligned institutional signatures")

    def test_nptel_full_evaluation_clean(self):
        """Verify NPTEL course dispatch produces LOW risk and zero HIGH findings."""
        headers = {
            "from": "onlinecourses@nptel.iitm.ac.in",
            "subject": "Introduction to Internet of Things - Week 9 content is live now!!",
            "return-path": "<bounce@nptel.iitm.ac.in>",
            "dkim-signature": "v=1; a=rsa-sha256; d=iitm.ac.in; s=2023;",
            "authentication-results": "mx.google.com; dkim=pass header.d=iitm.ac.in; spf=pass"
        }
        auth_res = evaluate_auth_and_alignment(headers)
        body = (
            'Dear Candidate,<br><br>'
            'Week 9 content for Introduction to Internet of Things is now live.<br>'
            'Please access your course portal at: '
            '<a href="https://onlinecourses.nptel.ac.in/noc26_cs01/unit?unit=9">nptel.ac.in</a><br>'
            'Assignment 9 is available for submission.<br><br>'
            'Happy Learning,<br>NPTEL Team'
        )
        parsed_data = {
            "headers": headers,
            "body": body
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type="Education / Academic")
        high_findings = [f for f in findings if f.get("severity") == "HIGH"]
        self.assertEqual(len(high_findings), 0, f"NPTEL produced unexpected HIGH findings: {high_findings}")

        risk_score, reasons = calculate_hybrid_risk(findings, ml_prob=0.05, auth_alignment=auth_res, content_type="Education / Academic")
        self.assertEqual(risk_score, "LOW")

    def test_dhl_spoofing_remains_high(self):
        """Verify genuine DHL anchor spoofing continues to fire RULE-019 HIGH."""
        body = (
            'Track your DHL package: '
            '<a href="http://www.bgsexpress.com/sp1">https://international.dhl.com/en/express/tracking.html</a>'
        )
        parsed_data = {
            "headers": {
                "from": "support@dhl-tracking-express.com",
                "subject": "Shipment Update"
            },
            "body": body
        }
        findings = evaluate_rules(parsed_data)
        dhl_rule19 = [f for f in findings if f.get("rule_id") == "RULE-019" and f.get("severity") == "HIGH"]
        self.assertTrue(len(dhl_rule19) > 0, "DHL anchor spoofing must trigger RULE-019 HIGH")

        risk_score, _ = calculate_hybrid_risk(findings, ml_prob=0.90)
        self.assertEqual(risk_score, "HIGH")


if __name__ == "__main__":
    unittest.main()
