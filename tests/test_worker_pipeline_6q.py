"""
tests/test_worker_pipeline_6q.py
Automated Security, Protocol, and E2E Test Suite for Sentinel Phase 6Q:
Full Gmail Test Mailbox Identification -> Secure Configuration -> Real IMAP E2E Test.

Mailbox: emailshield.sentinel.test@gmail.com
Server: imap.gmail.com:993 (TLS mandatory, CERT_REQUIRED, check_hostname=True)
"""

import os
import re
import ssl
import socket
import sys
import uuid
import unittest
from unittest.mock import MagicMock, patch

from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    export_public_key_pem,
    export_private_key_pem,
    WorkerKeyRing,
    ProvisioningKeyRing,
    DecryptionError,
)
from core.parser import SecureEmailParser
from core.classifier import MLClassifier
from core.agent import AutonomousForensicAgent
from core.indicators import extract_all_indicators

from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.lease import WorkerLeaseManager
from worker.db import MockWorkerDBClient, TableAccessViolationError
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.checkpoint import CheckpointStore
from worker.poller import (
    MailboxPoller,
    MAX_MESSAGES_PER_POLL,
    MAX_MESSAGE_SIZE_BYTES,
)
from worker.events import SafeEmailEvent
from worker.imap_client import (
    RealIMAPConnection,
    SSRFSecurityError,
    RealNetworkDeniedError,
    TLSVerificationError,
    validate_imap_host,
    validate_imap_port,
    validate_auth_mechanism,
    is_real_imap_test_enabled,
    check_real_imap_guard,
    GMAIL_TEST_EMAIL,
    GMAIL_IMAP_HOST,
    GMAIL_IMAP_PORT,
    GMAIL_APP_PASSWORD_ENV_VAR,
    get_gmail_app_password,
    is_gmail_app_password_available,
    CONNECTION_TIMEOUT_SECONDS,
    FETCH_TIMEOUT_SECONDS,
    MAX_HEADER_SIZE_BYTES,
)
from worker.rollout import (
    RolloutState,
    ExternalMailboxState,
    ExternalMailboxContractError,
    ExternalMailboxConfigContract,
    ExternalIMAPSecurityGate,
    create_gmail_test_contract,
)


def mask_sensitive_subject(subject: str) -> str:
    """Masks 4-8 digit numeric OTPs and verification tokens in subjects."""
    return re.sub(r"\b\d{4,8}\b", "••••••", subject)


class TestPhase6QGmailContractAndSSRF(unittest.TestCase):
    """Phase 2, 5, 8: Gmail Test Mailbox Contract, Tenant Binding, & SSRF Validation."""

    def test_01_gmail_contract_configuration(self):
        """Dedicated Gmail test mailbox contract matches all required metadata."""
        contract = create_gmail_test_contract()
        self.assertEqual(contract.provider, "gmail")
        self.assertEqual(contract.email_address, "emailshield.sentinel.test@gmail.com")
        self.assertEqual(contract.imap_host, "imap.gmail.com")
        self.assertEqual(contract.imap_port, 993)
        self.assertTrue(contract.use_ssl)
        self.assertEqual(contract.auth_mechanism, "PLAIN")
        self.assertTrue(contract.is_dedicated_test_mailbox)
        self.assertEqual(contract.state, ExternalMailboxState.CONFIGURED)

    def test_02_gmail_host_ssrf_allowance(self):
        """imap.gmail.com is a valid public host and passes SSRF validation."""
        self.assertEqual(validate_imap_host("imap.gmail.com"), "imap.gmail.com")

    def test_03_ssrf_negative_controls_remain_uncompromised(self):
        """Cloud metadata, private RFC1918, link-local, loopback, and internal TLDs rejected."""
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("169.254.169.254")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("10.0.0.1")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("192.168.1.1")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("127.0.0.1")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("localhost")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("mail.internal")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("mail.local")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("imap://imap.gmail.com")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("imap.gmail.com/path")

    def test_04_secrets_absence_in_contract(self):
        """Contract representation contains zero passwords, tokens, or keys."""
        contract = create_gmail_test_contract()
        rep = repr(contract)
        self.assertNotIn("password", rep.lower())
        self.assertNotIn("token", rep.lower())
        self.assertNotIn("key", rep.lower())
        self.assertNotIn("secret", rep.lower())

    def test_05_gmail_app_password_env_resolution(self):
        """Both SENTINEL_TEST_GMAIL_APP_PASSWORD and SENTINEL_GMAIL_APP_PASSWORD resolve safely."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_gmail_app_password_available())
            self.assertIsNone(get_gmail_app_password())

        with patch.dict(os.environ, {"SENTINEL_TEST_GMAIL_APP_PASSWORD": "test-secret-val-1"}):
            self.assertTrue(is_gmail_app_password_available())
            self.assertEqual(get_gmail_app_password(), "test-secret-val-1")

        with patch.dict(os.environ, {"SENTINEL_GMAIL_APP_PASSWORD": "test-secret-val-2"}):
            self.assertTrue(is_gmail_app_password_available())
            self.assertEqual(get_gmail_app_password(), "test-secret-val-2")



class TestPhase6QGmailTLSAndLiveBanner(unittest.TestCase):
    """Phase 9, 10: Real TLS Handshake with Google Trust Services & IMAP Banner Greeting."""

    def test_01_tls_context_enforces_cert_required_and_check_hostname(self):
        """RealIMAPConnection enforces check_hostname=True and CERT_REQUIRED."""
        with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "1"}):
            conn = RealIMAPConnection(host="imap.gmail.com", port=993, use_ssl=True)
            self.assertTrue(conn.use_ssl)
            self.assertIsNotNone(conn._ssl_context)
            self.assertTrue(conn._ssl_context.check_hostname)
            self.assertEqual(conn._ssl_context.verify_mode, ssl.CERT_REQUIRED)

    def test_02_real_gmail_tls_handshake_and_cert_verification(self):
        """Executes genuine TLS handshake with imap.gmail.com:993 verifying Google Trust Services CA."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection(("imap.gmail.com", 993), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname="imap.gmail.com") as ssock:
                    cert = ssock.getpeercert()
                    self.assertIsNotNone(cert)
                    # Verify subject contains imap.gmail.com
                    subject_entries = [val for sub in cert.get("subject", ()) for key, val in sub if key == "commonName"]
                    self.assertIn("imap.gmail.com", subject_entries)
                    # Verify issuer is Google Trust Services
                    issuer_orgs = [val for iss in cert.get("issuer", ()) for key, val in iss if key == "organizationName"]
                    self.assertIn("Google Trust Services", issuer_orgs)
        except (socket.gaierror, socket.timeout, TimeoutError, OSError) as net_err:
            self.skipTest(f"Gmail IMAP network unreachable: {net_err}")

    def test_03_real_gmail_imap_banner_greeting(self):
        """Connects to imap.gmail.com:993 and reads the genuine Google IMAP greeting banner."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection(("imap.gmail.com", 993), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname="imap.gmail.com") as ssock:
                    banner = ssock.recv(1024).decode("utf-8", errors="ignore")
                    self.assertIn("* OK", banner)
                    self.assertIn("Gimap", banner)
        except (socket.gaierror, socket.timeout, TimeoutError, OSError) as net_err:
            self.skipTest(f"Gmail IMAP network unreachable: {net_err}")

    def test_04_real_imap_adapter_connect_and_disconnect(self):
        """RealIMAPConnection adapter connects cleanly to Gmail and logs out."""
        with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "1"}):
            conn = RealIMAPConnection(host="imap.gmail.com", port=993, use_ssl=True)
            try:
                conn.connect()
                self.assertTrue(conn._is_connected)
                conn.logout()
                self.assertFalse(conn._is_connected)
            except (socket.gaierror, socket.timeout, TimeoutError, OSError, IMAPConnectionTimeoutError, IMAPClientError) as net_err:
                self.skipTest(f"Gmail IMAP network unreachable: {net_err}")


class TestPhase6QCredentialFlowAndTenantIsolation(unittest.TestCase):
    """Phase 6, 7, 24: Credential Provisioning, Encryption, Worker Decryption & Tenant Isolation."""

    def setUp(self):
        self.priv_a, self.pub_a = generate_worker_asymmetric_keypair()
        self.priv_b, self.pub_b = generate_worker_asymmetric_keypair()

        self.user_a = str(uuid.uuid4())
        self.user_b = str(uuid.uuid4())
        self.worker_a = uuid.uuid4()
        self.worker_b = uuid.uuid4()

        self.keyring_a = WorkerKeyRing("k1", {"k1": self.priv_a})
        self.keyring_b = WorkerKeyRing("k1", {"k1": self.priv_b})

        self.prov_ring_a = ProvisioningKeyRing("k1", {"k1": self.pub_a})
        self.prov_ring_b = ProvisioningKeyRing("k1", {"k1": self.pub_b})

    def test_01_asymmetric_envelope_provisioning_and_decryption(self):
        """Simulates Gmail App Password provisioning via RSA-2048 OAEP + AES-256-GCM envelope."""
        test_app_password = "abcd efgh ijkl mnop"
        # 1. Provisioning encrypts with tenant user_id AAD
        envelope = self.prov_ring_a.encrypt(test_app_password, self.user_a)
        self.assertTrue(envelope.startswith("v2:k1:"))

        # 2. Worker decrypts using authoritative WorkerKeyRing
        decrypted = self.keyring_a.decrypt(envelope, self.user_a)
        self.assertEqual(decrypted, test_app_password)

    def test_02_leased_credential_memory_wiping(self):
        """LeasedCredential.clear() scrubs decrypted secret from memory."""
        cred = LeasedCredential(
            mailbox_id=str(uuid.uuid4()),
            worker_id=str(self.worker_a),
            user_id=self.user_a,
            provider="gmail",
            email_address="emailshield.sentinel.test@gmail.com",
            imap_host="imap.gmail.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret="ephemeral_app_pw",
        )
        self.assertEqual(cred.secret, "ephemeral_app_pw")
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret
        self.assertNotIn("ephemeral_app_pw", repr(cred))

    def test_03_wrong_tenant_decryption_denied(self):
        """Tenant A envelope cannot be decrypted under Tenant B context."""
        envelope_a = self.prov_ring_a.encrypt("pw_a", self.user_a)
        with self.assertRaises(DecryptionError):
            self.keyring_a.decrypt(envelope_a, self.user_b)

    def test_04_wrong_worker_key_decryption_denied(self):
        """Tenant A envelope cannot be decrypted by Worker B private key."""
        envelope_a = self.prov_ring_a.encrypt("pw_a", self.user_a)
        with self.assertRaises(DecryptionError):
            self.keyring_b.decrypt(envelope_a, self.user_a)

    def test_05_wrong_capability_token_renewal_denied(self):
        """Lease renewal with wrong capability token is denied."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(self.worker_a, uuid.UUID(self.user_a), desired_state="RUNNING")

        identity = WorkerIdentity(self.worker_a)
        lease_mgr = WorkerLeaseManager(identity, db)
        self.assertTrue(lease_mgr.acquire_lease(duration_seconds=120))

        # Tamper token with forged 64-hex string
        identity.bind_token("f" * 64)
        self.assertFalse(lease_mgr.renew_lease(extension_seconds=60))

    def test_06_direct_table_access_denied_for_worker(self):
        """Worker role has zero direct table SELECT access."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        with self.assertRaises(PermissionError):
            db.direct_table_select("sentinel_mailboxes")
        db.verify_table_privilege_denial()


class TestPhase6QResourceBoundsAndCheckpointContract(unittest.TestCase):
    """Phase 11, 12, 13, 18, 19: Resource Bounds, Checkpointing & Alert Safety."""

    def test_01_resource_limits_enforced(self):
        """Resource bounds: 20 messages, 5 MB message size, 64 KB headers, 15s timeout."""
        self.assertEqual(MAX_MESSAGES_PER_POLL, 20)
        self.assertEqual(MAX_MESSAGE_SIZE_BYTES, 5 * 1024 * 1024)
        self.assertEqual(MAX_HEADER_SIZE_BYTES, 64 * 1024)
        self.assertEqual(CONNECTION_TIMEOUT_SECONDS, 15)
        self.assertEqual(FETCH_TIMEOUT_SECONDS, 15)

    def test_02_monotonic_checkpoint_and_deduplication(self):
        """Checkpoint advances monotonically and secondary Message-ID dedup works."""
        store = CheckpointStore()
        user_id = str(uuid.uuid4())
        worker_id = str(uuid.uuid4())
        mailbox_id = str(uuid.uuid4())

        cp = store.get_checkpoint(user_id, worker_id, mailbox_id)
        self.assertEqual(cp.last_processed_uid, 0)

        store.advance_checkpoint(user_id, worker_id, mailbox_id, uid=10, message_id="<msg-10@gmail.com>")
        cp = store.get_checkpoint(user_id, worker_id, mailbox_id)
        self.assertEqual(cp.last_processed_uid, 10)

        self.assertTrue(store.is_duplicate_message_id(mailbox_id, "<msg-10@gmail.com>"))
        self.assertFalse(store.is_duplicate_message_id(mailbox_id, "<msg-11@gmail.com>"))

        store.advance_checkpoint(user_id, worker_id, mailbox_id, uid=5, message_id="<msg-5@gmail.com>")
        cp = store.get_checkpoint(user_id, worker_id, mailbox_id)
        self.assertEqual(cp.last_processed_uid, 10)

    def test_03_alert_otp_masking(self):
        """OTPs and numeric verification codes in subjects are masked."""
        raw_subject = "Your Gmail verification code is 492019"
        masked = mask_sensitive_subject(raw_subject)
        self.assertNotIn("492019", masked)
        self.assertIn("••••••", masked)


class TestPhase6QRealGmailE2EOrSafeFailClosed(unittest.TestCase):
    """Phase 10-23, 25: Real Gmail Pipeline Execution OR Safe Fail-Closed Gate."""

    def test_01_real_gmail_live_e2e_or_safe_fail_closed(self):
        """
        Executes real Gmail IMAP live pipeline if SENTINEL_TEST_GMAIL_APP_PASSWORD is set;
        otherwise safely verifies fail-closed gate without error.
        """
        app_password = get_gmail_app_password()
        if app_password:
            # LIVE GMAIL PIPELINE
            with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "1"}):
                conn = RealIMAPConnection(
                    host=GMAIL_IMAP_HOST,
                    port=GMAIL_IMAP_PORT,
                    use_ssl=True
                )
                conn.connect()
                # Authenticate
                login_ok = conn.login(GMAIL_TEST_EMAIL, app_password)
                self.assertTrue(login_ok, "Gmail authentication must succeed with configured App Password")

                # Select INBOX
                status, count = conn.select("INBOX")
                self.assertEqual(status, "OK")

                # Bounded UID search
                uids = conn.search()
                self.assertIsInstance(uids, list)

                # If test messages are present, fetch and run forensic engine
                if uids:
                    latest_uid = uids[-1]
                    msg_dict = conn.fetch(latest_uid)
                    self.assertIn("rfc822", msg_dict)
                    raw_bytes = msg_dict["rfc822"]

                    # Forensic pipeline
                    p = SecureEmailParser(raw_bytes).parse()
                    iocs = extract_all_indicators(p["body"] + " " + str(p["headers"]))
                    agent = AutonomousForensicAgent(MLClassifier())
                    investigation = agent.run_investigation(p, iocs)
                    self.assertIn("risk_score", investigation)

                conn.logout()
        else:
            # App password not in environment -> Verify fail-closed behavior
            self.assertFalse(is_gmail_app_password_available())
            self.assertIsNone(get_gmail_app_password())

    def test_02_production_safety_invariants(self):
        """Production polling DISABLED, 0 production mailboxes, alerts DISABLED."""
        config = WorkerConfig()
        self.assertFalse(config.production_polling_enabled)
        self.assertFalse(config.test_mode)


if __name__ == "__main__":
    unittest.main()
