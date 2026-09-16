"""
tests/test_security.py
Comprehensive security regression tests verifying OWASP-10 SSRF hardening
in core/url_forensics.py:
- Loopback (IPv4 & IPv6)
- RFC1918 Private networks
- Link-local & Cloud Metadata (169.254.169.254, 100.100.100.200, fd00:ec2::254)
- Redirect hops to blocked destinations
- DNS rebinding prevention at socket connection layer
- Prohibited URL schemes and malformed URLs
- DNS resolution failure handling
- End-to-end URLAnalysisResult forensic reporting
"""

import socket
import unittest
from unittest.mock import patch, MagicMock
from core.url_forensics import (
    is_safe_ip,
    validate_url_target,
    safe_unshorten_url,
    analyze_url,
    SSRFBlockedError,
    SSRFResolutionError,
    _safe_create_connection,
)


class TestSSRFHardening(unittest.TestCase):

    def test_01_localhost_blocked(self):
        """Verify localhost and local hostnames are blocked from outbound probes."""
        for url in ["http://localhost", "http://localhost:8080/probe", "https://localhost/admin"]:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(url)

    def test_02_ipv4_loopback_blocked(self):
        """Verify all IPv4 loopback (127.0.0.0/8) destinations are blocked."""
        for ip in ["127.0.0.1", "127.0.0.2", "127.1.2.3", "127.255.255.255"]:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(f"http://{ip}:8000/secret")

    def test_03_ipv4_private_rfc1918_blocked(self):
        """Verify RFC 1918 private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are blocked."""
        private_ips = [
            "10.0.0.1",
            "10.254.254.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.254",
            "0.0.0.0"
        ]
        for ip in private_ips:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(f"http://{ip}/status")

    def test_04_cloud_metadata_blocked(self):
        """Verify cloud metadata endpoints (AWS, GCP, Azure, Alibaba, etc.) are strictly blocked."""
        metadata_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://169.254.1.1/internal",
        ]
        for url in metadata_targets:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(url)

    def test_05_ipv6_loopback_blocked(self):
        """Verify IPv6 loopback (::1) and IPv4-mapped loopback addresses are blocked."""
        ipv6_loopbacks = [
            "http://[::1]:8080/",
            "http://[::]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:127.0.0.2]:8000/",
        ]
        for url in ipv6_loopbacks:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(url)

    def test_06_ipv6_private_and_link_local_blocked(self):
        """Verify IPv6 link-local (fe80::/10), unique local (fc00::/7), and cloud IPv6 metadata are blocked."""
        ipv6_private = [
            "http://[fe80::1]/",
            "http://[fe80::200:5aee:feaa:20a2]/",
            "http://[fc00::1]/",
            "http://[fd00::1]/",
            "http://[fd00:ec2::254]/",  # AWS IPv6 IMDS
            "http://[::ffff:10.0.0.1]/",
            "http://[::ffff:192.168.1.1]/",
            "http://[::ffff:169.254.169.254]/",
        ]
        for url in ipv6_private:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(url)

    def test_07_normal_public_url_allowed(self):
        """Verify legitimate, globally routable public URLs pass validation safely."""
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
            host, ips = validate_url_target("https://example.com/login")
            self.assertEqual(host, "example.com")
            self.assertIn("93.184.216.34", ips)

    def test_08_redirect_from_public_to_blocked_destination(self):
        """Verify that a public URL redirecting to a private or metadata IP is blocked at the redirect hop."""
        with patch("core.url_forensics.validate_url_target") as mock_val:
            def side_effect(u):
                if "public-shortener.com" in u:
                    return "public-shortener.com", ["93.184.216.34"]
                raise SSRFBlockedError("SSRF blocked: target is cloud metadata", destination_url=u, redirect_count=1)
            mock_val.side_effect = side_effect

            with patch("requests.Session.head") as mock_head:
                mock_resp = MagicMock()
                mock_resp.status_code = 301
                mock_resp.is_redirect = True
                mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
                mock_head.return_value = mock_resp

                with self.assertRaises(SSRFBlockedError) as cm:
                    safe_unshorten_url("http://public-shortener.com/redir")

                self.assertEqual(cm.exception.redirect_count, 1)
                self.assertEqual(cm.exception.destination_url, "http://169.254.169.254/latest/meta-data/")

    def test_09_malformed_and_prohibited_schemes(self):
        """Verify non-HTTP schemes, missing hostnames, and numeric integer IP tricks are blocked."""
        prohibited = [
            "file:///etc/passwd",
            "file:///C:/Windows/win.ini",
            "ftp://internal-ftp.corp/data",
            "gopher://127.0.0.1:70/",
            "dict://127.0.0.1:11211/",
            "http://",
            "http://:80",
            "not_a_valid_url",
            "http://2130706433/",  # Integer representation of 127.0.0.1
        ]
        for u in prohibited:
            with self.assertRaises(SSRFBlockedError):
                validate_url_target(u)

    def test_10_dns_resolution_failure(self):
        """Verify DNS resolution failures raise SSRFResolutionError and do not trigger network connections."""
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.side_effect = socket.gaierror(11001, "getaddrinfo failed")
            with self.assertRaises(SSRFResolutionError):
                validate_url_target("https://unresolvable-domain-xyz-test.org")

    def test_11_dns_rebinding_defense_at_socket_level(self):
        """Verify that if DNS rebinds to an unsafe IP at socket connection time, connection is aborted."""
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
            ]
            with self.assertRaises(SSRFBlockedError):
                _safe_create_connection(("rebind-attacker.com", 80))

    def test_12_analyze_url_ssrf_integration(self):
        """Verify end-to-end analyze_url flags SSRF blocked targets as HIGH risk without making outbound requests."""
        res_local = analyze_url("http://localhost:8080/internal-api")
        self.assertEqual(res_local.risk_level, "HIGH")
        self.assertIn("Restricted/Internal Network Destination (SSRF Blocked)", res_local.suspicious_indicators)
        self.assertEqual(res_local.threat_category, "Restricted / Internal Network Destination (SSRF Blocked)")

        res_meta = analyze_url("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(res_meta.risk_level, "HIGH")
        self.assertIn("Restricted/Internal Network Destination (SSRF Blocked)", res_meta.suspicious_indicators)
        self.assertEqual(res_meta.threat_category, "Restricted / Internal Network Destination (SSRF Blocked)")

    def test_13_no_credentials_in_probe_headers(self):
        """Verify safe unshortening probe does not attach credentials or sensitive auth headers."""
        with patch("core.url_forensics.validate_url_target") as mock_val:
            mock_val.return_value = ("example.com", ["93.184.216.34"])
            with patch("requests.Session.head") as mock_head:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.is_redirect = False
                mock_head.return_value = mock_resp

                safe_unshorten_url("http://example.com/test")
                call_kwargs = mock_head.call_args[1]
                headers = call_kwargs.get("headers", {})

                self.assertNotIn("Authorization", headers)
                self.assertNotIn("Cookie", headers)
                self.assertNotIn("Proxy-Authorization", headers)


if __name__ == "__main__":
    unittest.main()
