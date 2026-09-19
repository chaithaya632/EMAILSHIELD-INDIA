"""
tests/test_real_imap_adapter.py
Unit and integration tests for Real IMAP Adapter:
- Protocol interface conformance
- Host validation and SSRF defenses
- Port validation
- Authentication mechanism validation
- TLS context verification
- Mocked IMAP4_SSL session operations
- Context-manager cleanup guarantees
"""

import email
import os
import ssl
import unittest
from unittest.mock import MagicMock, patch

from worker.imap_client import (
    RealIMAPConnection,
    IMAPConnectionProtocol,
    IMAPClientError,
    RealNetworkDeniedError,
    SSRFSecurityError,
    TLSVerificationError,
    UnsupportedAuthMechanismError,
    IMAPAuthenticationError,
    IMAPConnectionTimeoutError,
    validate_imap_host,
    validate_imap_port,
    validate_auth_mechanism,
    GUARD_ENV_VAR,
)
from worker.synthetic_imap import SyntheticIMAPConnection, SyntheticIMAPServer


class TestRealIMAPAdapter(unittest.TestCase):
    """Verifies RealIMAPConnection functionality, validation, and protocol compliance."""

    def setUp(self):
        # Enable guard for adapter tests with mocked sockets
        self._orig_guard = os.environ.get(GUARD_ENV_VAR)
        os.environ[GUARD_ENV_VAR] = "1"

    def tearDown(self):
        if self._orig_guard is not None:
            os.environ[GUARD_ENV_VAR] = self._orig_guard
        else:
            os.environ.pop(GUARD_ENV_VAR, None)

    # =========================================================================
    # 1. PROTOCOL CONFORMANCE
    # =========================================================================

    def test_01_protocol_conformance(self):
        """Both SyntheticIMAPConnection and RealIMAPConnection conform to IMAPConnectionProtocol."""
        server = SyntheticIMAPServer()
        syn_conn = SyntheticIMAPConnection(server=server)
        self.assertIsInstance(syn_conn, IMAPConnectionProtocol)

        mock_imap = MagicMock()
        real_conn = RealIMAPConnection(
            host="imap.example.com",
            port=993,
            _imap_factory=lambda *a, **kw: mock_imap
        )
        self.assertIsInstance(real_conn, IMAPConnectionProtocol)

    # =========================================================================
    # 2. HOST VALIDATION & SSRF HARDENING
    # =========================================================================

    def test_02_valid_hosts_accepted(self):
        """Valid DNS hostnames and permitted public IPs pass validation."""
        valid_hosts = [
            "imap.gmail.com",
            "outlook.office365.com",
            "mail.example.com",
            "imap.mail.yahoo.co.uk",
            "sub-domain.host-server1.net",
            "93.184.216.34",  # example.com public IP
        ]
        for host in valid_hosts:
            clean = validate_imap_host(host)
            self.assertEqual(clean, host)

    def test_03_empty_or_whitespace_host_rejected(self):
        """Empty or whitespace-only hostnames are rejected."""
        for invalid in ["", "   ", None]:
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host(invalid)

    def test_04_url_and_schemes_rejected(self):
        """URLs, schemes, paths, and userinfo are strictly rejected."""
        invalid_hosts = [
            "http://imap.example.com",
            "https://mail.example.com",
            "imap://mail.example.com",
            "imaps://mail.example.com",
            "mail.example.com/inbox",
            "mail.example.com\\path",
            "user:pass@mail.example.com",
            "mail.example.com:993",
            "mail.example.com?folder=inbox",
            "mail.example.com#section",
        ]
        for host in invalid_hosts:
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host(host)

    def test_05_cloud_metadata_ip_rejected(self):
        """Cloud metadata endpoint 169.254.169.254 is strictly prohibited."""
        with self.assertRaises(SSRFSecurityError) as ctx:
            validate_imap_host("169.254.169.254")
        self.assertIn("169.254.169.254", str(ctx.exception))

    def test_06_link_local_and_reserved_ips_rejected(self):
        """Link-local, multicast, and reserved IP ranges are rejected."""
        invalid_ips = [
            "169.254.1.1",     # link-local IPv4
            "224.0.0.1",       # multicast IPv4
            "240.0.0.1",       # reserved IPv4
            "0.0.0.0",         # unspecified IPv4
        ]
        for ip in invalid_ips:
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host(ip)

    def test_07_private_and_loopback_ips_rejected_by_default(self):
        """Private RFC1918 and loopback IPs are rejected by default."""
        forbidden_ips = [
            "127.0.0.1",       # loopback
            "10.0.0.1",        # RFC1918 class A
            "172.16.0.1",      # RFC1918 class B
            "192.168.1.1",     # RFC1918 class C
        ]
        for ip in forbidden_ips:
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host(ip, allow_private=False)

        # But accepted when explicitly allowed for local testing
        for ip in forbidden_ips:
            self.assertEqual(validate_imap_host(ip, allow_private=True), ip)

    def test_08_internal_domain_names_rejected(self):
        """Internal domains and cloud metadata hostnames are rejected."""
        internal_hosts = [
            "localhost",
            "metadata.google.internal",
            "instance-data",
            "mail.internal",
            "imap.local",
            "server.localhost",
            "router.lan",
            "dc.corp",
            "home.home",
        ]
        for host in internal_hosts:
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host(host)

    # =========================================================================
    # 3. PORT VALIDATION
    # =========================================================================

    def test_09_port_validation(self):
        """Valid ports return int; invalid ports raise ValueError."""
        self.assertEqual(validate_imap_port(993), 993)
        self.assertEqual(validate_imap_port("143"), 143)
        self.assertEqual(validate_imap_port(1), 1)
        self.assertEqual(validate_imap_port(65535), 65535)

        invalid_ports = [0, -1, 65536, 70000, "abc", None, ""]
        for p in invalid_ports:
            with self.assertRaises(ValueError):
                validate_imap_port(p)

    # =========================================================================
    # 4. AUTH MECHANISM VALIDATION
    # =========================================================================

    def test_10_auth_mechanism_validation(self):
        """PLAIN and LOGIN are accepted; unsupported mechanisms fail closed."""
        self.assertEqual(validate_auth_mechanism("PLAIN"), "PLAIN")
        self.assertEqual(validate_auth_mechanism("plain"), "PLAIN")
        self.assertEqual(validate_auth_mechanism("LOGIN"), "LOGIN")
        self.assertEqual(validate_auth_mechanism("login"), "LOGIN")

        unsupported = ["OAUTHBEARER", "XOAUTH2", "CRAM-MD5", "GSSAPI", "NTLM", "ANONYMOUS", ""]
        for mech in unsupported:
            with self.assertRaises(UnsupportedAuthMechanismError):
                validate_auth_mechanism(mech)

    # =========================================================================
    # 5. TLS CONFIGURATION
    # =========================================================================

    def test_11_tls_context_enforced(self):
        """SSLContext enforces check_hostname=True and verify_mode=CERT_REQUIRED."""
        mock_imap = MagicMock()
        conn = RealIMAPConnection(
            host="imap.example.com",
            port=993,
            use_ssl=True,
            _imap_factory=lambda *a, **kw: mock_imap
        )
        self.assertIsNotNone(conn._ssl_context)
        self.assertTrue(conn._ssl_context.check_hostname)
        self.assertEqual(conn._ssl_context.verify_mode, ssl.CERT_REQUIRED)

    # =========================================================================
    # 6. MOCKED IMAP SESSION OPERATIONS
    # =========================================================================

    def test_12_login_success_and_failures(self):
        """Login success sets state; IMAP errors wrap in IMAPAuthenticationError."""
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"LOGIN completed"])

        conn = RealIMAPConnection(
            host="imap.example.com",
            port=993,
            _imap_factory=lambda *a, **kw: mock_imap
        )
        self.assertTrue(conn.login("testuser@example.com", "secret_pass"))
        self.assertEqual(conn._logged_in_user, "testuser@example.com")

        # Empty credentials rejected
        with self.assertRaises(IMAPAuthenticationError):
            conn.login("", "secret")
        with self.assertRaises(IMAPAuthenticationError):
            conn.login("user", "")

        # Server rejection
        mock_imap.login.return_value = ("NO", [b"Authentication failed"])
        with self.assertRaises(IMAPAuthenticationError):
            conn.login("user@example.com", "bad_pass")

    def test_13_select_folder(self):
        """Folder selection parses message count and stores selected folder."""
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"LOGIN completed"])
        mock_imap.select.return_value = ("OK", [b"42"])

        conn = RealIMAPConnection(
            host="imap.example.com",
            _imap_factory=lambda *a, **kw: mock_imap
        )
        conn.login("user@example.com", "pass")
        status, count = conn.select("INBOX")
        self.assertEqual(status, "OK")
        self.assertEqual(count, 42)
        self.assertEqual(conn._selected_folder, "INBOX")

        # Select failure
        mock_imap.select.return_value = ("NO", [b"Folder does not exist"])
        status, count = conn.select("NONEXISTENT")
        self.assertEqual(status, "NO")
        self.assertEqual(count, 0)

    def test_14_search_uids(self):
        """Search parses ascending UIDs strictly greater than since_uid."""
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"LOGIN completed"])
        mock_imap.select.return_value = ("OK", [b"5"])
        # Server returns space-separated UIDs
        mock_imap.uid.return_value = ("OK", [b"101 102 105 108 110"])

        conn = RealIMAPConnection(
            host="imap.example.com",
            _imap_factory=lambda *a, **kw: mock_imap
        )
        conn.login("user@example.com", "pass")
        conn.select("INBOX")

        # Search without since_uid -> all
        uids = conn.search(since_uid=None)
        self.assertEqual(uids, [101, 102, 105, 108, 110])
        mock_imap.uid.assert_called_with("SEARCH", None, "ALL")

        # Search with since_uid=105 -> strictly > 105
        uids_since = conn.search(since_uid=105)
        self.assertEqual(uids_since, [108, 110])
        mock_imap.uid.assert_called_with("SEARCH", None, "UID 106:*")

    def test_15_fetch_rfc822_message(self):
        """Fetch retrieves RFC822 bytes and extracts Message-ID header safely."""
        raw_email = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: Test Subject\r\n"
            b"Message-ID: <unique-msg-123@example.com>\r\n"
            b"\r\n"
            b"Test Body Message"
        )
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"LOGIN completed"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.uid.return_value = ("OK", [(b"1 (BODY.PEEK[] {120}", raw_email)])

        conn = RealIMAPConnection(
            host="imap.example.com",
            _imap_factory=lambda *a, **kw: mock_imap
        )
        conn.login("user@example.com", "pass")
        conn.select("INBOX")

        result = conn.fetch(101)
        self.assertEqual(result["uid"], 101)
        self.assertEqual(result["rfc822"], raw_email)
        self.assertEqual(result["size"], len(raw_email))
        self.assertEqual(result["message_id"], "<unique-msg-123@example.com>")

    def test_16_context_manager_cleanup(self):
        """Context manager guarantees logout and socket teardown on normal exit and exceptions."""
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"LOGIN completed"])

        with RealIMAPConnection(
            host="imap.example.com",
            _imap_factory=lambda *a, **kw: mock_imap
        ) as conn:
            self.assertTrue(conn._is_connected)

        mock_imap.logout.assert_called_once()
        self.assertFalse(conn._is_connected)

        # Test exception path
        mock_imap.reset_mock()
        try:
            with RealIMAPConnection(
                host="imap.example.com",
                _imap_factory=lambda *a, **kw: mock_imap
            ) as conn:
                raise RuntimeError("Unexpected failure inside context block")
        except RuntimeError:
            pass

        mock_imap.logout.assert_called_once()
        self.assertFalse(conn._is_connected)
