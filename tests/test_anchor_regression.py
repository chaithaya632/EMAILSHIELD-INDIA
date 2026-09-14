import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.indicators import extract_anchor_spoofs, get_registrable_domain
from core.parser import SecureEmailParser
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.auth_claims import evaluate_auth_and_alignment

class TestAnchorSpoofRegression(unittest.TestCase):

    def test_a_multipart_cctld(self):
        root_nse_cctld = get_registrable_domain("nse.co.in")
        self.assertEqual(root_nse_cctld, "nse.co.in", "Root domain of nse.co.in must be nse.co.in, not co.in")

        root_sub_cctld = get_registrable_domain("alerts.nse.co.in")
        self.assertEqual(root_sub_cctld, "nse.co.in", "Root domain of alerts.nse.co.in must be nse.co.in")

        root_gov_cctld = get_registrable_domain("scores.gov.in")
        self.assertEqual(root_gov_cctld, "scores.gov.in", "Root domain of scores.gov.in must be scores.gov.in")

        root_uk_cctld = get_registrable_domain("news.bbc.co.uk")
        self.assertEqual(root_uk_cctld, "bbc.co.uk", "Root domain of news.bbc.co.uk must be bbc.co.uk")

        # HTML with nse.co.in linking to official nseindia.com (intra-org pair)
        html_content = '<a href="https://www.nseindia.com/invest">nse.co.in</a>'
        spoofs = extract_anchor_spoofs(html_content)
        self.assertEqual(len(spoofs), 0, "Intra-org pairing nse.co.in / nseindia.com must not be flagged as a spoof")

    def test_b_email_address_is_not_hostname(self):
        html_input1 = '<a href="https://www.nseindia.com/contact">ignse@nse.co.in</a>'
        html_input2 = '<a href="mailto:ignse@nse.co.in">ignse@nse.co.in</a>'
        html_input3 = 'Please contact <a href="https://support.example.com">helpdesk@example.com</a> for queries.'

        self.assertEqual(len(extract_anchor_spoofs(html_input1)), 0)
        self.assertEqual(len(extract_anchor_spoofs(html_input2)), 0)
        self.assertEqual(len(extract_anchor_spoofs(html_input3)), 0)

    def test_c_legitimate_esp_newsletter(self):
        raw_eml = b"""From: "Industry Training Network" <updates@training-network.org>
To: subscriber@recipient.com
Subject: Weekly Technical Briefing & Industry Trends
List-Unsubscribe: <https://training-network.org/unsubscribe>
Authentication-Results: mx.google.com; dkim=pass header.i=@training-network.org; spf=pass smtp.mailfrom=training-network.org; dmarc=pass
Content-Type: text/html; charset=utf-8

<html>
<body>
  <h2>This Week in Engineering</h2>
  <p>Here are the latest insights and course modules.</p>
  <p>Follow our community discussions: <a href="https://click.example-esp.com/track/u1234?dest=https%3A%2F%2Flinkedin.com">linkedin.com</a></p>
  <p><a href="https://click.example-esp.com/track/unsub">Unsubscribe from this newsletter</a></p>
</body>
</html>"""
        parsed = SecureEmailParser(raw_eml).parse()
        auth_res = evaluate_auth_and_alignment(parsed["headers"])
        rules = evaluate_rules(parsed, auth_alignment=auth_res, content_type="Newsletter / Subscription")
        risk, reasons = calculate_hybrid_risk(rules, 0.15, auth_alignment=auth_res, content_type="Newsletter / Subscription")

        self.assertNotEqual(risk, "HIGH", f"Authenticated ESP newsletter must not become HIGH! Reasons: {reasons}")
        self.assertEqual(risk, "LOW", f"Expected LOW risk, got {risk}")
        r19 = [r for r in rules if r.get("rule_id") == "RULE-019"]
        for r in r19:
            self.assertEqual(r.get("severity"), "LOW")

    def test_d_legitimate_institutional_mail(self):
        raw_eml = b"""From: "Exchange Notifications" <alerts@nse.co.in>
To: investor@domain.in
Subject: Retention of Funds and Securities - Margin Statement
Authentication-Results: mx.google.com; dkim=pass header.i=@nse.co.in; spf=pass smtp.mailfrom=nse.co.in; dmarc=pass
Content-Type: text/html; charset=utf-8

<html>
<body>
  <h3>Securities Retention Statement</h3>
  <p>Please find your weekly ledger statement summary as prescribed by regulatory circulars.</p>
  <p>Official exchange web portal: <a href="https://www.nseindia.com">nse.co.in</a></p>
  <p>Investor Grievance: <a href="https://www.nseindia.com/invest/grievance">ignse@nse.co.in</a></p>
  <p>Securities Market Grievance: <a href="https://scores.gov.in">scores.gov.in</a></p>
  <p>Dispute Resolution: <a href="https://smartodr.in">smartodr.in</a></p>
</body>
</html>"""
        parsed = SecureEmailParser(raw_eml).parse()
        auth_res = evaluate_auth_and_alignment(parsed["headers"])
        rules = evaluate_rules(parsed, auth_alignment=auth_res, content_type="Personal / Direct Mail")
        risk, reasons = calculate_hybrid_risk(rules, 0.10, auth_alignment=auth_res, content_type="Personal / Direct Mail")

        self.assertEqual(risk, "LOW", f"Institutional exchange alert must be LOW risk, got {risk} (Reasons: {reasons})")
        r19_high = [r for r in rules if r.get("rule_id") == "RULE-019" and r.get("severity") == "HIGH"]
        self.assertEqual(len(r19_high), 0, "No HIGH severity RULE-019 should fire on legitimate institutional disclosures")

    def test_e_genuine_phishing_newsletter(self):
        raw_eml = b"""From: "Enterprise IT Weekly Brief" <newsletter@spoofed-bulletin.org>
To: victim@enterprise.com
Subject: Weekly Bulletin: Critical IT Update - Verify Your Work Account
List-Unsubscribe: <https://spoofed-bulletin.org/unsub>
Authentication-Results: mx.google.com; dkim=fail; spf=fail smtp.mailfrom=spoofed-bulletin.org; dmarc=fail
Content-Type: text/html; charset=utf-8

<html>
<body>
  <h2>IT Security & Technology Weekly</h2>
  <p>Dear Staff, please review the latest security policy changes below.</p>
  <p>Action Required: Verify and update your corporate password immediately to avoid account suspension.</p>
  <p><a href="http://credential-stealer-phish.xyz/login/m365">login.microsoftonline.com</a></p>
  <p>Thank you, Corporate IT Desk</p>
</body>
</html>"""
        parsed = SecureEmailParser(raw_eml).parse()
        auth_res = evaluate_auth_and_alignment(parsed["headers"])
        rules = evaluate_rules(parsed, auth_alignment=auth_res, content_type="Newsletter / Subscription")
        risk, reasons = calculate_hybrid_risk(rules, 0.92, auth_alignment=auth_res, content_type="Newsletter / Subscription")

        self.assertEqual(risk, "HIGH", f"Phishing disguised as newsletter MUST remain HIGH! Got {risk}")
        r19_high = [r for r in rules if r.get("rule_id") == "RULE-019" and r.get("severity") == "HIGH"]
        self.assertGreaterEqual(len(r19_high), 1, "RULE-019 must flag sensitive target spoofing with HIGH severity")

    def test_f_legitimate_social_link_tracking(self):
        raw_eml = b"""From: "Cloud Community" <digest@cloudcommunity.io>
To: engineer@work.com
Subject: Monthly Cloud Architecture Digest
List-Unsubscribe: <https://cloudcommunity.io/unsubscribe>
Authentication-Results: mx.google.com; dkim=pass header.i=@cloudcommunity.io; spf=pass smtp.mailfrom=cloudcommunity.io; dmarc=pass
Content-Type: text/html; charset=utf-8

<html>
<body>
  <h2>Cloud Architecture Monthly</h2>
  <p>Check out our featured speaker profiles and connect with the speakers:</p>
  <p>Speaker Profile: <a href="https://click.example.com/tracking/speaker-connect?ref=abc">linkedin.com</a></p>
  <p>X Updates: <a href="https://click.example.com/tracking/speaker-x?ref=xyz">twitter.com</a></p>
</body>
</html>"""
        parsed = SecureEmailParser(raw_eml).parse()
        auth_res = evaluate_auth_and_alignment(parsed["headers"])
        rules = evaluate_rules(parsed, auth_alignment=auth_res, content_type="Newsletter / Subscription")
        risk, reasons = calculate_hybrid_risk(rules, 0.12, auth_alignment=auth_res, content_type="Newsletter / Subscription")

        self.assertEqual(risk, "LOW", f"Legitimate social tracking in newsletter must be LOW risk, got {risk}")
        r19_high = [r for r in rules if r.get("rule_id") == "RULE-019" and r.get("severity") == "HIGH"]
        self.assertEqual(len(r19_high), 0, "RULE-019 must not be HIGH for social link tracking in authenticated newsletter")

if __name__ == "__main__":
    unittest.main()
