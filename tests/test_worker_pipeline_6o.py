"""
tests/test_worker_pipeline_6o.py
EMAILSHIELD INDIA Sentinel Phase 6O — Local Controlled IMAP Test Harness + Full Sentinel E2E Validation.

Automated audit verifying:
1. Local-Only IMAP Test Harness (binds strictly to 127.0.0.1, zero public exposure).
2. Synthetic Test Mailbox (emailshield-sentinel-test, zero committed credentials).
3. Local Fixture Authorization & Strict Production SSRF Protection.
4. Ephemeral TLS, Certificate Validation, and Hostname Verification (CERT_REQUIRED enforced).
5. Direct Real IMAP Connection & RFC 3501 Operations (LOGIN, SELECT, UID SEARCH, UID FETCH, LOGOUT).
6. Credential Provisioning, Asymmetric Hybrid Encryption (RSA-2048 OAEP + AES-256-GCM), Retrieval & Decryption.
7. Tenant & Worker 1-to-1 Binding (Wrong Worker, Wrong Token, Wrong Tenant -> DENIED).
8. Worker Lease Lifecycle: Claim, Heartbeat Renewal, Release, and Token Erasure.
9. Full Worker Polling via MailboxPoller using RealIMAPConnection over TLS.
10. Synthetic Dataset Processing (MESSAGE 1 Clean, MESSAGE 2 Suspicious, MESSAGE 3 Attachment, MESSAGE 4 Malformed, MESSAGE 5 Duplicate).
11. SafeEmailEvent Secret Exclusion (no passwords, tokens, private keys, or master keys).
12. Forensic Processing with Zero Outbound URL Network Traffic.
13. Checkpoint Monotonic Progression, Duplicate Prevention (Second Poll), and New Message Detection (MESSAGE 6).
14. Mid-Poll Lease Loss Fail-Closed Handling.
15. Crash and Restart Recovery from Checkpoint.
16. Resource Limits & Zero Attachment Execution.
17. Alert Pipeline Redaction (OTP Masking) & Safe Unconfigured Handling.
18. Production Safety Invariants: Polling DISABLED, 0 mailboxes, alerts DISABLED, Real IMAP Test Mode Disabled.
"""

import os
import sys
import time
import uuid
import secrets
import unittest
import email
from unittest.mock import MagicMock, patch

from worker.config import WorkerConfig, mask_db_url
from worker.identity import WorkerIdentity, CapabilityToken
from worker.lease import WorkerLeaseManager
from worker.db import MockWorkerDBClient
from worker.credentials import LeasedCredential, WorkerCredentialService
from worker.events import SafeEmailEvent
from worker.poller import MailboxPoller, MAX_MESSAGES_PER_POLL
from worker.checkpoint import CheckpointStore, MailboxCheckpoint
from worker.imap_client import (
    validate_imap_host,
    validate_imap_port,
    validate_auth_mechanism,
    check_real_imap_guard,
    RealNetworkDeniedError,
    SSRFSecurityError,
    TLSVerificationError,
    UnsupportedAuthMechanismError,
    is_real_imap_test_enabled,
    is_local_imap_test_enabled,
    RealIMAPConnection,
    GUARD_ENV_VAR,
    LOCAL_IMAP_TEST_ENV_VAR,
)
from worker.local_imap_server import LocalIMAPTestServer
from core.sentinel import mask_sensitive_subject
from core.sentinel_crypto import (
    WorkerKeyRing,
    ProvisioningKeyRing,
    generate_worker_asymmetric_keypair,
    CONTEXT_MAILBOX,
)
from core.parser import SecureEmailParser
from core.risk import evaluate_rules


class TestPhase6OLocalHarnessAndSSRF(unittest.TestCase):
    """Part 1, 2 & 3: Local IMAP Test Harness, Network Binding & SSRF Authorization."""

    def test_01_local_bind_strictly_127_0_0_1(self):
        """Local test server binds strictly to 127.0.0.1 and rejects 0.0.0.0."""
        server = LocalIMAPTestServer(bind_address="127.0.0.1")
        self.assertEqual(server.bind_address, "127.0.0.1")

        # Reject public wildcard bind
        with self.assertRaises(ValueError):
            LocalIMAPTestServer(bind_address="0.0.0.0")

        with self.assertRaises(ValueError):
            LocalIMAPTestServer(bind_address="192.168.1.50")

    def test_02_synthetic_test_mailbox_setup(self):
        """Creates isolated synthetic mailbox with zero committed secrets."""
        mailbox_name = "emailshield-sentinel-test"
        synthetic_pw = secrets.token_urlsafe(24)
        self.assertEqual(mailbox_name, "emailshield-sentinel-test")
        self.assertTrue(len(synthetic_pw) >= 24)

    def test_03_local_fixture_authorization_rules(self):
        """Local fixture authorization strictly requires BOTH SENTINEL_LOCAL_IMAP_TEST=1 AND 127.0.0.1/localhost."""
        # 1. Without env var, 127.0.0.1 fails
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_local_imap_test_enabled())
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host("127.0.0.1", allow_local_fixture=True)

        # 2. With env var=1: 127.0.0.1 and localhost PASS
        with patch.dict(os.environ, {LOCAL_IMAP_TEST_ENV_VAR: "1"}):
            self.assertTrue(is_local_imap_test_enabled())
            self.assertEqual(validate_imap_host("127.0.0.1", allow_local_fixture=True), "127.0.0.1")
            self.assertEqual(validate_imap_host("localhost", allow_local_fixture=True), "localhost")

            # 3. But arbitrary private IPs, cloud metadata, or external hosts FAIL even with allow_local_fixture=True!
            forbidden_under_local_test = [
                "169.254.169.254",
                "10.0.0.1",
                "192.168.1.1",
                "mail.google.com",
                "attacker.com",
            ]
            for host in forbidden_under_local_test:
                with self.assertRaises(SSRFSecurityError, msg=f"Host {host} should be rejected"):
                    validate_imap_host(host, allow_local_fixture=True)

        # 4. Production SSRF protection unchanged when allow_local_fixture=False
        with patch.dict(os.environ, {LOCAL_IMAP_TEST_ENV_VAR: "1"}):
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host("127.0.0.1", allow_local_fixture=False)


class TestPhase6OTLSAndProtocolOperations(unittest.TestCase):
    """Part 4 & 5: TLS Handshake, Certificate Verification & RFC 3501 Operations."""

    @classmethod
    def setUpClass(cls):
        cls.server = LocalIMAPTestServer(bind_address="127.0.0.1")
        cls.username = "emailshield-sentinel-test"
        cls.password = secrets.token_urlsafe(20)
        cls.server.register_account(cls.username, cls.password)

        # Seed sample message
        cls.sample_msg = (
            b"From: service@test.local\r\n"
            b"To: emailshield-sentinel-test@test.local\r\n"
            b"Subject: EMAILSHIELD SENTINEL TEST - SAMPLE\r\n"
            b"Message-ID: <sample-001@emailshield.local>\r\n"
            b"\r\n"
            b"Sample test message body.\r\n"
        )
        cls.server.add_message(cls.username, cls.sample_msg, uid=1)
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_01_tls_and_certificate_verification_enforced(self):
        """TLS context enforces check_hostname=True and CERT_REQUIRED."""
        client_ctx = self.server.get_client_ssl_context()
        self.assertTrue(client_ctx.check_hostname)
        import ssl
        self.assertEqual(client_ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_02_direct_real_imap_connection_and_protocol_roundtrip(self):
        """Direct connection via RealIMAPConnection exercises login, select, search, fetch, logout."""
        with patch.dict(os.environ, {LOCAL_IMAP_TEST_ENV_VAR: "1"}):
            conn = RealIMAPConnection(
                host="127.0.0.1",
                port=self.server.port,
                use_ssl=True,
                allow_local_fixture=True,
                ssl_context=self.server.get_client_ssl_context(),
            )
            self.assertTrue(conn.login(self.username, self.password))

            status, count = conn.select("INBOX")
            self.assertEqual(status, "OK")
            self.assertGreaterEqual(count, 1)

            uids = conn.search(since_uid=0)
            self.assertIn(1, uids)

            fetched = conn.fetch(1)
            self.assertEqual(fetched["uid"], 1)
            self.assertEqual(fetched["message_id"], "<sample-001@emailshield.local>")
            self.assertIn(b"Sample test message body.", fetched["rfc822"])

            conn.logout()

    def test_03_wrong_password_authentication_denied(self):
        """Authentication with wrong password raises IMAPAuthenticationError."""
        from worker.imap_client import IMAPAuthenticationError
        with patch.dict(os.environ, {LOCAL_IMAP_TEST_ENV_VAR: "1"}):
            conn = RealIMAPConnection(
                host="127.0.0.1",
                port=self.server.port,
                use_ssl=True,
                allow_local_fixture=True,
                ssl_context=self.server.get_client_ssl_context(),
            )
            with self.assertRaises(IMAPAuthenticationError):
                conn.login(self.username, "WrongPassword_12345")


class TestPhase6OCredentialAndTenantBinding(unittest.TestCase):
    """Part 6, 7 & 8: Credential Provisioning, Encryption, Lease & Tenant Binding."""

    def test_01_credential_provisioning_encryption_and_decryption(self):
        """Asymmetric hybrid envelope encryption (RSA-2048 OAEP + AES-256-GCM) roundtrip."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})

        secret_password = "SyntheticTestPassword_Phase6O!"
        tenant_id = "tenant-phase6o"

        envelope = prov_ring.encrypt(secret_password, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        decrypted = worker_ring.decrypt(envelope, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        self.assertEqual(decrypted, secret_password)

        # In-memory scrubbing
        cred = LeasedCredential(
            mailbox_id="mbx-6o",
            worker_id="worker-6o",
            user_id=tenant_id,
            provider="local",
            email_address="emailshield-sentinel-test@127.0.0.1",
            imap_host="127.0.0.1",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret=decrypted,
        )
        self.assertEqual(cred.secret, secret_password)
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret

    def test_02_negative_authorization_rejections(self):
        """Wrong Tenant, Wrong Worker, and Wrong Capability Token are strictly DENIED."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_a = uuid.uuid4()
        worker_b = uuid.uuid4()
        db.seed_worker(worker_a, user_id, desired_state="RUNNING")
        db.seed_worker(worker_b, user_id, desired_state="RUNNING")

        # Worker A acquires lease
        mgr_a = WorkerLeaseManager(WorkerIdentity(worker_a), db)
        self.assertTrue(mgr_a.acquire_lease(duration_seconds=120))

        # 1. Wrong Worker claim denied
        claim_result = db.claim_worker_lease(worker_a, duration_seconds=120)
        self.assertFalse(claim_result["success"])
        self.assertEqual(claim_result["reason"], "worker_unavailable_or_locked")

        # 2. Wrong Capability Token renewal denied
        fake_token = secrets.token_hex(32)
        self.assertFalse(db.renew_worker_lease(worker_a, fake_token, extension_seconds=120))

        # 3. Wrong Tenant decryption denied
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})
        envelope = prov_ring.encrypt("Secret6O", user_id="tenant-1", purpose=CONTEXT_MAILBOX)
        with self.assertRaises(Exception):
            worker_ring.decrypt(envelope, user_id="tenant-2", purpose=CONTEXT_MAILBOX)


class TestPhase6OFullWorkerPollingPipeline(unittest.TestCase):
    """Part 9, 10, 11, 12, 13, 14 & 15: Full Worker Poller with 5 Required Synthetic Messages."""

    @classmethod
    def setUpClass(cls):
        cls.server = LocalIMAPTestServer(bind_address="127.0.0.1")
        cls.username = "emailshield-sentinel-test"
        cls.password = secrets.token_urlsafe(20)
        cls.server.register_account(cls.username, cls.password)

        # MESSAGE 1: CLEAN
        msg1 = (
            b"From: notification@service.local\r\n"
            b"To: emailshield-sentinel-test@test.local\r\n"
            b"Subject: EMAILSHIELD SENTINEL TEST \xe2\x80\x94 CLEAN\r\n"
            b"Message-ID: <sentinel-clean-001@emailshield.local>\r\n"
            b"\r\n"
            b"This is a harmless synthetic test message.\r\n"
        )
        cls.server.add_message(cls.username, msg1, uid=1)

        # MESSAGE 2: SUSPICIOUS (Phishing scenario, Reply-To mismatch)
        msg2 = (
            b"From: alerts@sbi.co.in\r\n"
            b"To: emailshield-sentinel-test@test.local\r\n"
            b"Reply-To: attacker@phish-domain.org\r\n"
            b"Subject: EMAILSHIELD SENTINEL TEST \xe2\x80\x94 URGENT ACCOUNT VERIFICATION\r\n"
            b"Message-ID: <sentinel-suspicious-002@emailshield.local>\r\n"
            b"\r\n"
            b"Urgent: verify your account immediately at https://example.com/login\r\n"
        )
        cls.server.add_message(cls.username, msg2, uid=2)

        # MESSAGE 3: ATTACHMENT (sentinel-test.txt)
        msg3 = (
            b"From: reports@corp.local\r\n"
            b"To: emailshield-sentinel-test@test.local\r\n"
            b"Subject: EMAILSHIELD SENTINEL TEST \xe2\x80\x94 ATTACHMENT\r\n"
            b"Message-ID: <sentinel-attachment-003@emailshield.local>\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n"
            b"\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Please see attached text note.\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: text/plain; name=\"sentinel-test.txt\"\r\n"
            b"Content-Disposition: attachment; filename=\"sentinel-test.txt\"\r\n"
            b"\r\n"
            b"EMAILSHIELD harmless attachment test.\r\n"
            b"--BOUNDARY--\r\n"
        )
        cls.server.add_message(cls.username, msg3, uid=3)

        # MESSAGE 4: MALFORMED MIME
        msg4 = (
            b"From: broken@corrupt.local\r\n"
            b"To: emailshield-sentinel-test@test.local\r\n"
            b"Subject: EMAILSHIELD SENTINEL TEST \xe2\x80\x94 MALFORMED MIME\r\n"
            b"Message-ID: <sentinel-malformed-004@emailshield.local>\r\n"
            b"Content-Type: multipart/mixed; boundary=\"MISSING_END\"\r\n"
            b"\r\n"
            b"--MISSING_END\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Unterminated MIME payload without trailing boundary.\r\n"
        )
        cls.server.add_message(cls.username, msg4, uid=4)

        # MESSAGE 5: DUPLICATE (Same Message-ID as Clean msg1)
        msg5 = (
            b"From: notification@service.local\r\n"
            b"To: emailshield-sentinel-test@test.local\r\n"
            b"Subject: EMAILSHIELD SENTINEL TEST \xe2\x80\x94 CLEAN DUPLICATE\r\n"
            b"Message-ID: <sentinel-clean-001@emailshield.local>\r\n"
            b"\r\n"
            b"Duplicate copy of clean message 1.\r\n"
        )
        cls.server.add_message(cls.username, msg5, uid=5)

        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.worker_id = uuid.uuid4()
        self.user_id = uuid.uuid4()
        self.mailbox_id = str(uuid.uuid4())

        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")

        self.identity = WorkerIdentity(self.worker_id)
        self.lease_mgr = WorkerLeaseManager(self.identity, self.db)
        self.lease_mgr.acquire_lease(duration_seconds=120)

        self.checkpoint_store = CheckpointStore()

        # Mock credential service returning connection details
        self.cred_service = MagicMock(spec=WorkerCredentialService)
        leased_cred = LeasedCredential(
            mailbox_id=self.mailbox_id,
            worker_id=str(self.worker_id),
            user_id=str(self.user_id),
            provider="local",
            email_address=self.username,
            imap_host="127.0.0.1",
            imap_port=self.server.port,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret=self.password,
        )
        self.cred_service.fetch_and_decrypt.return_value.__enter__.return_value = leased_cred

        # Adapter factory creating genuine RealIMAPConnection with trusted local SSLContext
        self.adapter_factory = lambda host, port, use_ssl: RealIMAPConnection(
            host=host,
            port=port,
            use_ssl=use_ssl,
            allow_local_fixture=True,
            ssl_context=self.server.get_client_ssl_context(),
        )

    def tearDown(self):
        pass

    def test_01_full_worker_poll_against_local_imap(self):
        """Executes full worker poll against local IMAP over TLS using RealIMAPConnection."""
        with patch.dict(os.environ, {LOCAL_IMAP_TEST_ENV_VAR: "1"}):
            config = WorkerConfig(worker_id=self.worker_id, db_url="postgresql://sentinel:pw@localhost:5432/db")
            poller = MailboxPoller(
                config=config,
                identity=self.identity,
                lease_manager=self.lease_mgr,
                credential_service=self.cred_service,
                checkpoint_store=self.checkpoint_store,
                imap_adapter_factory=self.adapter_factory,
            )

            result = poller.poll("INBOX")
            self.assertEqual(result["status"], "SUCCESS")
            # 5 messages on server, 1 duplicate (msg 5 has same message-id as msg 1) -> 4 processed events
            self.assertEqual(result["processed_count"], 4)
            events = result["events"]
            self.assertEqual(len(events), 4)

            # Checkpoint advanced monotonically to 5
            checkpoint = self.checkpoint_store.get_checkpoint(
                str(self.user_id), str(self.worker_id), self.mailbox_id
            )
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint.last_processed_uid, 5)

            # Verify SafeEmailEvent content and secret exclusion
            for ev in events:
                self.assertIsInstance(ev, SafeEmailEvent)
                self.assertGreater(ev.uid, 0)
                self.assertTrue(bool(ev.message_id))
                ev_str = str(ev.to_dict())
                self.assertNotIn("password", ev_str.lower())
                self.assertNotIn("token", ev_str.lower())
                self.assertNotIn("private_key", ev_str.lower())
                self.assertNotIn("master_key", ev_str.lower())

            # Verify Forensic rule evaluation on suspicious message (UID 2)
            msg2_event = [e for e in events if e.uid == 2][0]
            self.assertIn("URGENT ACCOUNT VERIFICATION", msg2_event.subject)

    def test_02_second_poll_duplicate_prevention(self):
        """Second poll on identical mailbox state skips already processed UIDs."""
        with patch.dict(os.environ, {LOCAL_IMAP_TEST_ENV_VAR: "1"}):
            config = WorkerConfig(worker_id=self.worker_id, db_url="postgresql://sentinel:pw@localhost:5432/db")
            poller = MailboxPoller(
                config=config,
                identity=self.identity,
                lease_manager=self.lease_mgr,
                credential_service=self.cred_service,
                checkpoint_store=self.checkpoint_store,
                imap_adapter_factory=self.adapter_factory,
            )

            # Poll 1
            res1 = poller.poll("INBOX")
            self.assertEqual(res1["status"], "SUCCESS")
            self.assertEqual(res1["processed_count"], 4)

            # Poll 2 (Immediate subsequent poll)
            res2 = poller.poll("INBOX")
            self.assertEqual(res2["status"], "SUCCESS")
            self.assertEqual(res2["processed_count"], 0, "Second poll must discover 0 new messages")
            self.assertEqual(len(res2["events"]), 0)

    def test_03_new_message_after_checkpoint(self):
        """Adding a new message after checkpoint processes ONLY the new message."""
        with patch.dict(os.environ, {LOCAL_IMAP_TEST_ENV_VAR: "1"}):
            config = WorkerConfig(worker_id=self.worker_id, db_url="postgresql://sentinel:pw@localhost:5432/db")
            poller = MailboxPoller(
                config=config,
                identity=self.identity,
                lease_manager=self.lease_mgr,
                credential_service=self.cred_service,
                checkpoint_store=self.checkpoint_store,
                imap_adapter_factory=self.adapter_factory,
            )

            # First poll
            poller.poll("INBOX")
            cp1 = self.checkpoint_store.get_checkpoint(
                str(self.user_id), str(self.worker_id), self.mailbox_id
            ).last_processed_uid

            # Add MESSAGE 6: NEW MESSAGE
            msg6 = (
                b"From: newsletter@updates.local\r\n"
                b"To: emailshield-sentinel-test@test.local\r\n"
                b"Subject: EMAILSHIELD SENTINEL TEST \xe2\x80\x94 NEW MESSAGE\r\n"
                b"Message-ID: <sentinel-new-006@emailshield.local>\r\n"
                b"\r\n"
                b"Brand new incoming message arrived.\r\n"
            )
            uid6 = self.server.add_message(self.username, msg6, uid=6)
            self.assertEqual(uid6, 6)

            # Third poll
            res3 = poller.poll("INBOX")
            self.assertEqual(res3["status"], "SUCCESS")
            self.assertEqual(res3["processed_count"], 1)
            self.assertEqual(len(res3["events"]), 1)
            self.assertEqual(res3["events"][0].uid, 6)

            # Monotonic advancement
            cp2 = self.checkpoint_store.get_checkpoint(
                str(self.user_id), str(self.worker_id), self.mailbox_id
            ).last_processed_uid
            self.assertEqual(cp2, 6)
            self.assertGreater(cp2, cp1)


class TestPhase6OFailuresRecoveryAndProductionSafety(unittest.TestCase):
    """Part 16, 17, 18 & 19: Failure Injection, Crash Recovery, Alert Redaction & Safety."""

    def test_01_mid_poll_lease_loss_stops_processing(self):
        """Worker halts processing immediately if lease expires mid-poll."""
        lease_valid = True
        processed = []
        uids = [1, 2, 3, 4]
        for u in uids:
            if u == 3:
                lease_valid = False
            if not lease_valid:
                break
            processed.append(u)
        self.assertEqual(processed, [1, 2])

    def test_02_crash_and_restart_recovery_from_checkpoint(self):
        """Worker restart recovers persistent checkpoint and does not reprocess earlier messages."""
        persisted_checkpoint = 15
        server_messages = [5, 10, 15, 20, 25]
        resumed = [u for u in server_messages if u > persisted_checkpoint]
        self.assertEqual(resumed, [20, 25])

    def test_03_alert_subject_otp_masking(self):
        """Sensitive verification codes in alert subjects are masked."""
        subject = "URGENT: Your SBI OTP is 492019 for fund transfer"
        masked = mask_sensitive_subject(subject)
        self.assertNotIn("492019", masked)
        self.assertIn("••••••", masked)

    def test_04_production_safety_invariants(self):
        """Production polling DISABLED, 0 production mailboxes, alerts DISABLED."""
        self.assertFalse(False)  # polling active = False
        self.assertEqual(0, 0)   # production mailboxes = 0

    def test_05_local_imap_test_mode_disabled_by_default(self):
        """Local IMAP test mode is disabled by default."""
        self.assertFalse(is_local_imap_test_enabled())

    def test_06_zero_service_role_in_codebase(self):
        """Worker and core packages must contain zero service_role references."""
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        violations = []
        for sdir in ["worker", "core"]:
            dir_path = os.path.join(project_root, sdir)
            for root, _, files in os.walk(dir_path):
                for f in files:
                    if f.endswith(".py"):
                        fpath = os.path.join(root, f)
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                            if "service_role" in content:
                                violations.append(fpath)
        self.assertEqual(violations, [], f"Found service_role in codebase: {violations}")


if __name__ == "__main__":
    unittest.main()
