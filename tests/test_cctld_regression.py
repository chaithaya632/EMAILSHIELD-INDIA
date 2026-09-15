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


    def test_nptel_real_payload_with_sendgrid_and_login(self):
        """Verify real NPTEL email 7437 with SendGrid links and benign 'login' keyword yields LOW / Clean."""
        headers = {
            "from": "onlinecourses@nptel.iitm.ac.in",
            "subject": "Introduction to Internet of Things - Week 9 content is live now!!",
            "return-path": "<noc26-cs161-announce+bncBCZ5RXNBUUOBBPWIT7KQMGQES36WPII@nptel.iitm.ac.in>",
            "dkim-signature": "v=1; a=rsa-sha256; d=nptel-iitm-ac-in.20251104.gappssmtp.com; s=20251104;",
            "authentication-results": "mx.google.com; dkim=pass header.d=nptel-iitm-ac-in.20251104.gappssmtp.com; spf=pass; dmarc=pass header.from=nptel.iitm.ac.in",
            "list-unsubscribe": "<https://groups.google.com/a/nptel.iitm.ac.in/group/noc26-cs161-announce/subscribe>"
        }
        auth_res = evaluate_auth_and_alignment(headers)
        body = (
            "Dear Students,\n"
            "The lecture videos for Week 9 have been uploaded.\n"
            "Please remember to login into the website to view contents (if you aren't logged in already).\n"
            "Course link: <a href=\"https://u3447072.ct.sendgrid.net/ls/click?upn=123\">https://onlinecourses.nptel.ac.in/noc26_cs161/unit?unit=92&amp;lesson=93</a>\n"
            "Assignment link: <a href=\"https://u3447072.ct.sendgrid.net/ls/click?upn=456\">https://onlinecourses.nptel.ac.in/noc26_cs161/unit?unit=92&amp;assessment=387</a>\n"
            "Thanks and Regards, --NPTEL Team"
        )
        parsed_data = {"headers": headers, "body": body}
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type="Education / Academic")

        # Verify RULE-006 is present at LOW severity
        r6 = [f for f in findings if f.get("rule_id") == "RULE-006"]
        self.assertEqual(len(r6), 1)
        self.assertEqual(r6[0]["severity"], "LOW")

        # Verify RULE-019 is present at LOW severity (not HIGH)
        r19_high = [f for f in findings if f.get("rule_id") == "RULE-019" and f.get("severity") == "HIGH"]
        self.assertEqual(len(r19_high), 0, "Authenticated SendGrid ESP link with benign 'login' must not trigger RULE-019 HIGH")

        high_findings = [f for f in findings if f.get("severity") == "HIGH"]
        self.assertEqual(len(high_findings), 0)

        risk_score, _ = calculate_hybrid_risk(findings, ml_prob=0.4755, auth_alignment=auth_res, content_type="Education / Academic")
        self.assertEqual(risk_score, "LOW")

    def test_unauthenticated_phishing_with_esp_destination_remains_high(self):
        """Verify unauthenticated email routing through an ESP triggers RULE-019 HIGH via Branch B."""
        headers = {
            "from": "alerts@unverified-phish.xyz",
            "subject": "Security Alert: Verify Now"
        }
        # No auth headers -> auth_ok is False
        auth_res = evaluate_auth_and_alignment(headers)
        body = 'Click here: <a href="https://click.sendgrid.net/ls/click?upn=abc">https://accounts.portal-verify.com/login</a>'
        parsed_data = {"headers": headers, "body": body}
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res)

        r19_high = [f for f in findings if f.get("rule_id") == "RULE-019" and f.get("severity") == "HIGH"]
        self.assertTrue(len(r19_high) > 0, "Unauthenticated anchor spoofing via ESP must trigger RULE-019 HIGH")

        risk_score, _ = calculate_hybrid_risk(findings, ml_prob=0.85, auth_alignment=auth_res)
        self.assertEqual(risk_score, "HIGH")

    def test_sensitive_brand_spoof_via_esp_remains_high(self):
        """Verify sensitive brand anchor spoofing (PayPal) routing through ESP triggers Branch A HIGH."""
        headers = {
            "from": "billing@promotions-mailer.com",
            "subject": "Invoice Paid",
            "list-unsubscribe": "<mailto:unsub@promotions-mailer.com>"
        }
        # Even if auth passed for the sender domain
        auth_res = {"effective_dmarc": "PASS", "threat_detected": False}
        body = 'Receipt: <a href="https://click.sendgrid.net/track/123">paypal.com</a>'
        parsed_data = {"headers": headers, "body": body}
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type="Newsletter / Subscription")

        r19_high = [f for f in findings if f.get("rule_id") == "RULE-019" and f.get("severity") == "HIGH"]
        self.assertTrue(len(r19_high) > 0, "Sensitive brand masking via ESP must trigger Branch A HIGH")

        risk_score, _ = calculate_hybrid_risk(findings, ml_prob=0.60, auth_alignment=auth_res)
        self.assertEqual(risk_score, "HIGH")


if __name__ == "__main__":
    unittest.main()
