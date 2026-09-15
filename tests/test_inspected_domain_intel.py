"""
tests/test_inspected_domain_intel.py
Unit tests for the Inspected Domain Intelligence MVI.
Mocks all network-dependent behavior (DNS, WHOIS/RDAP, HTTP).
"""

import unittest
from unittest.mock import patch, MagicMock
import socket

from core.schemas import DomainRole, DomainVerdict, InspectedDomain
from core.domain_intel import (
    normalize_domain,
    extract_all_domains_with_roles,
    inspect_domain,
    evaluate_email_domains
)


class TestInspectedDomainIntel(unittest.TestCase):

    def setUp(self):
        # Default mock for DNS returning legitimate IP
        self.dns_patch = patch("socket.gethostbyname_ex", return_value=("mock.com", [], ["93.184.216.34"]))
        self.whois_patch = patch("core.domain_intel.resolve_whois_and_rdap", return_value=("Mock Registrar", "2015-05-20", 3500))
        self.mock_dns = self.dns_patch.start()
        self.mock_whois = self.whois_patch.start()

    def tearDown(self):
        self.dns_patch.stop()
        self.whois_patch.stop()

    def test_case_1_legitimate_corporate_domain(self):
        """Case 1: Legitimate established corporate domain -> LIKELY LEGITIMATE."""
        parsed_email = {
            "headers": {
                "from": "Google Accounts <no-reply@accounts.google.com>",
                "subject": "Security notification"
            },
            "body": "Your account details can be viewed at https://google.com/dashboard"
        }
        auth_alignment = {"effective_dmarc": "PASS"}
        results = evaluate_email_domains(parsed_email, auth_alignment=auth_alignment, skip_network=True)
        
        # Check google.com
        google_dom = next((d for d in results if d.domain == "google.com"), None)
        self.assertIsNotNone(google_dom)
        self.assertEqual(google_dom.verdict, DomainVerdict.LIKELY_LEGITIMATE)
        self.assertTrue(google_dom.is_claimed_brand_aligned or google_dom.is_sender_aligned)

    def test_case_2_lookalike_domain(self):
        """Case 2: Lookalike domain (micr0soft.com) -> LOOKALIKE / IMPERSONATION."""
        parsed_email = {
            "headers": {"from": "support@micr0soft.com"},
            "body": "Verify account at https://micr0soft.com/login"
        }
        results = evaluate_email_domains(parsed_email, skip_network=True)
        micr0soft = next((d for d in results if "micr0soft" in d.domain), None)
        self.assertIsNotNone(micr0soft)
        self.assertTrue(micr0soft.is_lookalike)
        self.assertEqual(micr0soft.impersonated_brand, "microsoft")
        self.assertEqual(micr0soft.verdict, DomainVerdict.LOOKALIKE_IMPERSONATION)

    def test_case_3_newly_registered_suspicious_domain(self):
        """Case 3: Newly registered domain (< 30 days) -> NRD supporting signal, SUSPICIOUS (not HIGH on age alone)."""
        self.mock_whois.return_value = ("NameCheap Inc", "2026-09-05", 10)  # 10 days old
        
        parsed_email = {
            "headers": {"from": "info@brand-new-portal.xyz"},
            "body": "Check out our portal at https://brand-new-portal.xyz/welcome"
        }
        results = evaluate_email_domains(parsed_email, skip_network=False)
        target = next((d for d in results if d.domain == "brand-new-portal.xyz"), None)
        self.assertIsNotNone(target)
        self.assertTrue(target.is_nrd)
        self.assertEqual(target.domain_age_days, 10)
        # NRD alone must produce SUSPICIOUS, NOT HIGH_RISK
        self.assertEqual(target.verdict, DomainVerdict.SUSPICIOUS)
        self.assertNotEqual(target.verdict, DomainVerdict.HIGH_RISK)

    def test_case_4_known_authenticated_esp(self):
        """Case 4: Known authenticated ESP -> THIRD-PARTY INFRASTRUCTURE."""
        parsed_email = {
            "headers": {
                "from": "Acme Newsletter <newsletter@acme.com>",
                "dkim-signature": "v=1; a=rsa-sha256; d=sendgrid.net; s=smtp;"
            },
            "body": "Read this newsletter at https://click.sendgrid.net/track/123"
        }
        auth_alignment = {
            "effective_dmarc": "PASS (Delegated ESP)",
            "dkim_signing_domain": "sendgrid.net"
        }
        results = evaluate_email_domains(parsed_email, auth_alignment=auth_alignment, content_type="Newsletter / Subscription", skip_network=True)
        sg_dom = next((d for d in results if d.domain == "click.sendgrid.net"), None)
        self.assertIsNotNone(sg_dom)
        self.assertIn(DomainRole.THIRD_PARTY_INFRASTRUCTURE, sg_dom.roles)
        self.assertEqual(sg_dom.verdict, DomainVerdict.THIRD_PARTY_INFRASTRUCTURE)

    def test_case_5_visible_anchor_mismatch(self):
        """Case 5: Visible anchor mismatch targeting sensitive brand -> HIGH RISK."""
        parsed_email = {
            "headers": {"from": "security@free-mail.com"},
            "body": 'Please verify: <a href="https://unrelated-phishing-host.com/login">paypal.com</a>'
        }
        results = evaluate_email_domains(parsed_email, skip_network=True)
        phish_dom = next((d for d in results if d.domain == "unrelated-phishing-host.com"), None)
        self.assertIsNotNone(phish_dom)
        self.assertEqual(phish_dom.verdict, DomainVerdict.HIGH_RISK)
        self.assertTrue(any("paypal" in ref.lower() for ref in phish_dom.evidence_references))

    def test_case_6_qr_destination(self):
        """Case 6: QR destination extracted; private IP does NOT produce HIGH RISK."""
        parsed_email = {
            "headers": {"from": "admin@local.test"},
            "body": "Scan the attached QR code to continue",
            "quishing_findings": [
                {
                    "decoded_url": "http://192.168.1.50/setup",
                    "filename": "qr_code.png"
                }
            ]
        }
        results = evaluate_email_domains(parsed_email, skip_network=True)
        qr_dom = next((d for d in results if d.domain == "192.168.1.50"), None)
        self.assertIsNotNone(qr_dom)
        self.assertIn(DomainRole.QR_DESTINATION, qr_dom.roles)
        # Private IP must NOT produce HIGH RISK
        self.assertNotEqual(qr_dom.verdict, DomainVerdict.HIGH_RISK)
        self.assertIn(qr_dom.verdict, [DomainVerdict.SUSPICIOUS, DomainVerdict.UNKNOWN])
        self.assertTrue(any("private" in s.lower() for s in qr_dom.risk_signals))

    def test_case_7_fifty_urls_one_domain(self):
        """Case 7: 50 URLs sharing one domain -> occurrence_count == 50, inspection runs once."""
        urls = [f"https://medium.com/topic/post-{i}" for i in range(50)]
        body_text = " ".join(urls)
        parsed_email = {
            "headers": {"from": "digest@medium.com"},
            "body": body_text
        }
        results = evaluate_email_domains(parsed_email, skip_network=True)
        medium_dom = next((d for d in results if d.domain == "medium.com"), None)
        self.assertIsNotNone(medium_dom)
        self.assertEqual(medium_dom.occurrence_count, 51)  # 50 in body + 1 in from

    def test_case_8_punycode_homograph(self):
        """Case 8: Punycode IDN homograph attack -> LOOKALIKE / IMPERSONATION."""
        # xn--pple-43d.com decodes to аpple.com (Cyrillic а)
        parsed_email = {
            "headers": {"from": "security@xn--pple-43d.com"},
            "body": "Login to your account at https://xn--pple-43d.com/signin"
        }
        results = evaluate_email_domains(parsed_email, skip_network=True)
        puny_dom = next((d for d in results if "xn--pple-43d" in d.domain), None)
        self.assertIsNotNone(puny_dom)
        self.assertTrue(puny_dom.is_lookalike)
        self.assertEqual(puny_dom.verdict, DomainVerdict.LOOKALIKE_IMPERSONATION)

    def test_case_9_missing_dns(self):
        """Case 9: Domain with missing DNS -> graceful handling without crash, dns_resolved == False."""
        self.mock_dns.side_effect = socket.gaierror("Name or service not known")
        
        parsed_email = {
            "headers": {"from": "contact@nonexistent-dns-domain-12345.com"},
            "body": "Visit https://nonexistent-dns-domain-12345.com/page"
        }
        results = evaluate_email_domains(parsed_email, skip_network=False)
        target = next((d for d in results if "nonexistent-dns-domain" in d.domain), None)
        self.assertIsNotNone(target)
        self.assertFalse(target.dns_resolved)
        self.assertEqual(target.resolved_ips, [])
        self.assertTrue(any("DNS A query unresolvable" in s for s in target.risk_signals))

    def test_case_10_rdap_whois_timeout(self):
        """Case 10: RDAP/WHOIS timeout -> graceful fallback without unhandled exception."""
        self.mock_whois.side_effect = socket.timeout("Socket timed out")
        
        parsed_email = {
            "headers": {"from": "service@rdap-timeout-domain.org"},
            "body": "Link at https://rdap-timeout-domain.org/help"
        }
        results = evaluate_email_domains(parsed_email, skip_network=False)
        target = next((d for d in results if "rdap-timeout" in d.domain), None)
        self.assertIsNotNone(target)
        self.assertFalse(target.rdap_available)
        self.assertIsNone(target.domain_age_days)
        self.assertIn(target.verdict, [DomainVerdict.UNKNOWN, DomainVerdict.SUSPICIOUS, DomainVerdict.LIKELY_LEGITIMATE])

    def test_case_11_private_reserved_ip_address(self):
        """Case 11: Private/reserved IP (10.0.0.1) -> contextual evidence, NOT automatic HIGH."""
        parsed_email = {
            "headers": {"from": "router@internal.corp"},
            "body": "Access gateway at http://10.0.0.1:8080/admin"
        }
        results = evaluate_email_domains(parsed_email, skip_network=True)
        target = next((d for d in results if d.domain == "10.0.0.1"), None)
        self.assertIsNotNone(target)
        self.assertNotEqual(target.verdict, DomainVerdict.HIGH_RISK)
        self.assertTrue(any("private" in s.lower() for s in target.risk_signals))

    def test_case_12_legitimate_newsletter_with_esp_tracker(self):
        """Case 12: Legitimate newsletter with authenticated ESP tracker -> THIRD-PARTY INFRASTRUCTURE."""
        parsed_email = {
            "headers": {
                "from": "Groww Digest <noreply@digest.groww.in>",
                "subject": "Market Wrap",
                "list-unsubscribe": "<https://click.convertkit-mail.com/unsubscribe>"
            },
            "body": 'Check article: <a href="https://click.convertkit-mail.com/track/456">Read story</a>'
        }
        auth_alignment = {
            "effective_dmarc": "PASS",
            "dkim_signing_domain": "convertkit-mail.com"
        }
        results = evaluate_email_domains(
            parsed_email,
            auth_alignment=auth_alignment,
            content_type="Newsletter / Subscription",
            skip_network=True
        )
        esp_dom = next((d for d in results if "convertkit-mail.com" in d.domain), None)
        self.assertIsNotNone(esp_dom)
        self.assertEqual(esp_dom.verdict, DomainVerdict.THIRD_PARTY_INFRASTRUCTURE)
        self.assertIn(DomainRole.THIRD_PARTY_INFRASTRUCTURE, esp_dom.roles)


if __name__ == "__main__":
    unittest.main()
