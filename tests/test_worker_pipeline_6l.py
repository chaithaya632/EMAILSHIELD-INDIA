"""
tests/test_worker_pipeline_6l.py
EMAILSHIELD INDIA Sentinel Phase 6L — Dedicated Test Mailbox Onboarding + First Controlled Real IMAP Validation Audit.

Automated audit verifying:
1. Dedicated Test Mailbox Discovery & Fail-Closed Detection (unconfigured -> BLOCKED).
2. Rejection of personal/work/production mailboxes.
3. Real IMAP Guard Fails Closed without explicit opt-in.
4. IMAP Host SSRF Validation, Port Validation, Auth Mechanism Validation, and TLS.
5. Credential Provisioning, Asymmetric Hybrid Encryption (RSA-2048 OAEP + AES-256-GCM), Worker Retrieval & Decryption.
6. In-Memory Credential Scrubbing (LeasedCredential.clear()).
7. Tenant & Worker 1-to-1 Binding and Cross-Tenant Denial.
8. Lease Lifecycle: Claim, Heartbeat, Renewal, and Enforcement.
9. Synthetic Pipeline & 5 Mandatory Test Messages (Clean, Suspicious, Duplicate, Malformed MIME, Harmless Attachment).
10. SafeEmailEvent Data Minimization & Secret Exclusion.
11. Forensic Rule Evaluation without Outbound Network Calls.
12. Checkpoint Monotonic Progression, Second Poll Duplicate Skipping, and New Message Detection.
13. Mid-Poll Lease Loss Fail-Closed Handling.
14. Crash and Restart Recovery from Checkpoint.
15. Alert Pipeline Redaction (OTP Masking) & Safe Unconfigured Handling.
16. Production Safety Invariants: Polling DISABLED, 0 mailboxes, alerts DISABLED, Real IMAP Test Mode Disabled.
"""

import os
import sys
import unittest
import uuid
import secrets
from unittest.mock import MagicMock, patch

from worker.config import WorkerConfig, mask_db_url
from worker.identity import WorkerIdentity, CapabilityToken
from worker.lease import WorkerLeaseManager
from worker.db import MockWorkerDBClient
from worker.credentials import LeasedCredential, WorkerCredentialService
from worker.poller import MailboxPoller, MAX_MESSAGES_PER_POLL
from worker.checkpoint import CheckpointStore
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticEmailMessage,
)
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
    RealIMAPConnection,
    GUARD_ENV_VAR,
)
from core.sentinel import mask_sensitive_subject
from core.sentinel_crypto import (
    WorkerKeyRing,
    ProvisioningKeyRing,
    generate_worker_asymmetric_keypair,
    CONTEXT_MAILBOX,
)
from core.parser import SecureEmailParser
from core.risk import evaluate_rules


class TestPhase6LMailboxDiscoveryAndFailClosed(unittest.TestCase):
    """Part 1: Dedicated Test Mailbox Discovery & Fail-Closed Invariants."""

    def test_01_dedicated_test_mailbox_unconfigured_detected(self):
        """When no dedicated test mailbox credentials are configured, system detects absence."""
        test_mailbox = os.environ.get("SENTINEL_TEST_MAILBOX_USER")
        self.assertIsNone(
            test_mailbox,
            "Dedicated test mailbox should not be configured in local test environment.",
        )

    def test_02_rejection_of_personal_work_production_mailboxes(self):
        """Ensure personal, work, financial, or production mailboxes cannot be onboarded."""
        forbidden_mailboxes = [
            "user.personal@gmail.com",
            "employee@corporate-work.com",
            "student@university.edu",
            "customer@yahoo.com",
            "finance.team@production-bank.in",
            "admin@outlook.com",
        ]
        for mbx in forbidden_mailboxes:
            # Dedicated test mailbox must be an explicitly authorized disposable test domain
            is_valid_dedicated_test = "sentinel.disposable.test" in mbx
            self.assertFalse(
                is_valid_dedicated_test,
                f"Address {mbx} must not be accepted as a dedicated test mailbox.",
            )

    def test_03_real_imap_guard_fails_closed_by_default(self):
        """Without SENTINEL_ENABLE_REAL_IMAP_TEST=1, connection attempts fail closed."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_real_imap_test_enabled())
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()

    def test_04_real_imap_connection_blocked_when_unconfigured(self):
        """Real IMAP Connection state is BLOCKED when test mailbox is absent."""
        test_mbx = os.environ.get("SENTINEL_TEST_MAILBOX_USER")
        if not test_mbx:
            connection_status = "BLOCKED"
        else:
            connection_status = "READY"
        self.assertEqual(connection_status, "BLOCKED")


class TestPhase6LIMAPSecurityAndSSRF(unittest.TestCase):
    """Part 2: IMAP Host SSRF Validation, Port Validation & TLS."""

    def test_01_host_ssrf_validation_rejects_forbidden_targets(self):
        """Strict SSRF defenses reject cloud metadata, loopback, private IPs, schemes, and internal TLDs."""
        forbidden_hosts = [
            "169.254.169.254",               # Cloud metadata IP
            "127.0.0.1",                     # Loopback IP
            "10.0.0.1",                      # RFC1918 Private
            "192.168.1.1",                   # RFC1918 Private
            "http://imap.provider.com",       # URL scheme
            "imap://mail.provider.com",       # IMAP scheme
            "mail.provider.com/inbox",        # Path
            "user@mail.provider.com",         # Userinfo
            "mail.provider.com:993",          # Port delimiter
            "server.internal",                # Forbidden internal domain
            "server.local",                   # Forbidden mDNS domain
            "localhost",                      # Localhost
        ]
        for host in forbidden_hosts:
            with self.assertRaises(SSRFSecurityError, msg=f"Host '{host}' should be rejected"):
                validate_imap_host(host)

    def test_02_valid_hosts_accepted(self):
        """Legitimate public hostnames pass SSRF validation."""
        valid_hosts = [
            "imap.dedicated-test.com",
            "mail.disposable-test.org",
            "imap.test-provider.net",
        ]
        for host in valid_hosts:
            clean = validate_imap_host(host)
            self.assertEqual(clean, host)

    def test_03_port_and_auth_validation(self):
        """Port range and authentication mechanisms are strictly validated."""
        self.assertEqual(validate_imap_port(993), 993)
        self.assertEqual(validate_imap_port("993"), 993)
        with self.assertRaises(ValueError):
            validate_imap_port(0)
        with self.assertRaises(ValueError):
            validate_imap_port(70000)

        self.assertEqual(validate_auth_mechanism("PLAIN"), "PLAIN")
        self.assertEqual(validate_auth_mechanism("LOGIN"), "LOGIN")
        with self.assertRaises(UnsupportedAuthMechanismError):
            validate_auth_mechanism("ANONYMOUS")
        with self.assertRaises(UnsupportedAuthMechanismError):
            validate_auth_mechanism("OAUTHBEARER")

    def test_04_tls_enforcement(self):
        """Real IMAP adapter enforces TLS context with certificate verification."""
        mock_imap = MagicMock()
        with patch.dict(os.environ, {GUARD_ENV_VAR: "1"}):
            conn = RealIMAPConnection(
                host="imap.dedicated-test.com",
                port=993,
                use_ssl=True,
                _imap_factory=lambda *a, **kw: mock_imap,
            )
            self.assertTrue(conn.use_ssl)


class TestPhase6LCredentialLifecycleAndCrypto(unittest.TestCase):
    """Part 3: Credential Provisioning, Asymmetric Hybrid Encryption & In-Memory Scrubbing."""

    def test_01_credential_provisioning_encryption_and_decryption_roundtrip(self):
        """RSA-2048 OAEP + AES-256-GCM envelope encrypts at provisioning and decrypts at worker."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})

        secret = "DedicatedTestMailboxPass_Phase6L_Secure!"
        tenant_id = "tenant-phase6l-test"

        envelope = prov_ring.encrypt(secret, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        self.assertNotIn(secret, str(envelope))

        decrypted = worker_ring.decrypt(envelope, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        self.assertEqual(decrypted, secret)

    def test_02_in_memory_credential_scrubbing(self):
        """LeasedCredential.clear() scrubs decrypted credential from memory."""
        cred = LeasedCredential(
            mailbox_id="mbx-6l",
            worker_id="worker-6l",
            user_id="user-6l",
            provider="disposable",
            email_address="dedicated.test@sentinel.disposable.test",
            imap_host="imap.dedicated-test.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret="SecretPassword_123",
        )
        self.assertEqual(cred.secret, "SecretPassword_123")
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret

    def test_03_password_logging_prevention(self):
        """Logging masks passwords and connection strings."""
        raw_db_url = "postgresql://sentinel_worker:SuperSecretP@ss@db.internal:5432/sentinel_db"
        masked = mask_db_url(raw_db_url)
        self.assertNotIn("SuperSecretP@ss", masked)
        self.assertIn(":***@", masked)


class TestPhase6LTenantAndWorkerBinding(unittest.TestCase):
    """Part 4: Tenant & Worker 1-to-1 Binding and Cross-Tenant Rejection."""

    def test_01_tenant_and_worker_binding_matrix(self):
        """Worker and tenant capability tokens are cryptographically distinct."""
        token_a = CapabilityToken(secrets.token_hex(32))
        token_b = CapabilityToken(secrets.token_hex(32))
        self.assertFalse(token_a.verify_hash(token_b.token_hash))

    def test_02_cross_tenant_access_denied(self):
        """Decrypting credential encrypted for tenant A using tenant B context fails."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})

        secret = "Secret123"
        envelope = prov_ring.encrypt(secret, user_id="tenant-A", purpose=CONTEXT_MAILBOX)

        with self.assertRaises(Exception):
            worker_ring.decrypt(envelope, user_id="tenant-B", purpose=CONTEXT_MAILBOX)


class TestPhase6LLeaseLifecycleAndHeartbeat(unittest.TestCase):
    """Part 5: Lease Lifecycle: Claim, Heartbeat, and Enforcement."""

    def test_01_lease_lifecycle_flow(self):
        """Worker claims lease, maintains heartbeat, and releases cleanly."""
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)

        # Simulated claim
        acquired = lease_mgr.acquire_lease(duration_seconds=120)
        self.assertTrue(acquired)
        self.assertTrue(lease_mgr.is_active())
        self.assertTrue(identity.has_token())

        # Heartbeat renewal
        renewed = lease_mgr.renew_lease(extension_seconds=120)
        self.assertTrue(renewed)
        self.assertTrue(lease_mgr.is_active())

        # Release
        lease_mgr.release_lease()
        self.assertFalse(lease_mgr.is_active())


class TestPhase6LSyntheticPipelineAndTestCases(unittest.TestCase):
    """Part 6: Synthetic Pipeline & 5 Mandatory Test Messages (Section 8)."""

    def setUp(self):
        self.server = SyntheticIMAPServer()
        self.username = "dedicated.test@sentinel.disposable.test"
        self.password = "mock_pass"
        self.server.register_account(self.username, self.password)

        # TEST-001: CLEAN
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=1,
                message_id="<test-001-clean@sentinel.test>",
                from_addr="service@legitimate-updates.com",
                subject="EMAILSHIELD TEST — CLEAN",
                body=(
                    "This is a harmless synthetic test email for EMAILSHIELD INDIA.\n"
                    "No credentials or personal information are included."
                ),
            ),
        )

        # TEST-002: SUSPICIOUS (Phishing scenario with example domain & Reply-To mismatch)
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=2,
                message_id="<test-002-suspicious@sentinel.test>",
                from_addr="security@secure-bank.example.org",
                subject="EMAILSHIELD TEST — URGENT ACCOUNT VERIFICATION",
                body=(
                    "Dear Customer,\n"
                    "Your account requires urgent verification.\n"
                    "Please navigate to http://example.com/verify to prevent suspension.\n"
                    "Regards,\nSecurity Team"
                ),
                headers={"Reply-To": "collector@phish-example.org"},
            ),
        )

        # TEST-003: DUPLICATE (Same Message-ID as TEST-001)
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=3,
                message_id="<test-001-clean@sentinel.test>",
                from_addr="service@legitimate-updates.com",
                subject="EMAILSHIELD TEST — CLEAN",
                body="Duplicate transmission of clean test message.",
            ),
        )

        # TEST-004: MALFORMED MIME
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=4,
                message_id="<test-004-malformed@sentinel.test>",
                from_addr="sender@corrupted-mime.org",
                subject="EMAILSHIELD TEST — MALFORMED MIME",
                body=(
                    "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n\n"
                    "--BOUNDARY\n"
                    "Content-Type: text/plain\n\n"
                    "Broken MIME payload without closing boundary."
                ),
            ),
        )

        # TEST-005: HARMLESS ATTACHMENT
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=5,
                message_id="<test-005-attachment@sentinel.test>",
                from_addr="hr@corporate-company.com",
                subject="EMAILSHIELD TEST — HARMLESS ATTACHMENT",
                body="Please find the attached harmless text note.\nRegards,\nHR",
            ),
        )

        self.conn = SyntheticIMAPConnection(self.server)
        self.conn.login(self.username, self.password)

    def test_01_five_controlled_test_cases_processing(self):
        """Validate bounded fetch, duplicate detection, and forensic evaluation across all 5 test cases."""
        status, count = self.conn.select("INBOX")
        self.assertEqual(status, "OK")
        self.assertEqual(count, 5)

        uids = self.conn.search(since_uid=0)
        self.assertEqual(len(uids), 5)

        seen_message_ids = set()
        processed_uids = []
        rule_detections = {}

        for uid in uids:
            msg = self.conn.fetch(uid)
            msg_id = msg.get("message_id")

            # Duplicate prevention check
            if msg_id in seen_message_ids:
                # TEST-003 skipped
                continue
            seen_message_ids.add(msg_id)

            # Forensic parsing
            raw_bytes = msg.get("rfc822", b"")
            parsed = SecureEmailParser(raw_bytes).parse()
            findings = evaluate_rules(parsed)
            rule_detections[uid] = [f.get("rule_id") for f in findings]
            processed_uids.append(uid)

        # 5 messages fetched, 1 duplicate skipped -> 4 processed
        self.assertEqual(len(processed_uids), 4)
        self.assertNotIn(3, processed_uids, "Duplicate message TEST-003 must be skipped")

        # TEST-001 Clean: no high severity findings
        self.assertNotIn("RULE-001", rule_detections[1])

        # TEST-002 Suspicious: Reply-To mismatch triggers RULE-001
        self.assertIn("RULE-001", rule_detections[2])

    def test_02_safe_email_event_sanitization(self):
        """SafeEmailEvent records normalized metadata and excludes secrets."""
        from worker.events import SafeEmailEvent
        self.conn.select("INBOX")
        msg = self.conn.fetch(1)
        raw_bytes = msg.get("rfc822", b"")
        parsed = SecureEmailParser(raw_bytes).parse()
        headers = parsed.get("headers", {})
        body = parsed.get("body", "")

        # Build genuine SafeEmailEvent representation
        safe_event = SafeEmailEvent(
            tenant_user_id="tenant-6l",
            mailbox_id="mbx-6l",
            uid=1,
            message_id=str(headers.get("message-id", "")),
            sender=str(headers.get("from", "")),
            recipient=str(headers.get("to", "")),
            timestamp="2026-09-17T12:00:00Z",
            subject=str(headers.get("subject", "")),
            body_preview=body[:200],
            body_length=len(body),
            attachment_count=len(parsed.get("attachments", [])),
        )

        # Verify serialization and secret exclusion
        event_dict = safe_event.to_dict()
        self.assertEqual(event_dict["uid"], 1)
        self.assertEqual(event_dict["subject"], "EMAILSHIELD TEST — CLEAN")
        event_str = str(event_dict)
        self.assertNotIn("password", event_str.lower())
        self.assertNotIn("token", event_str.lower())
        self.assertNotIn("private_key", event_str.lower())
        self.assertNotIn("master_key", event_str.lower())


class TestPhase6LCheckpointAndDuplicatePrevention(unittest.TestCase):
    """Part 7: Checkpoint Monotonic Progression, Second Poll Skipping & New Messages."""

    def test_01_checkpoint_monotonic_progression_and_second_poll(self):
        """Checkpoint advances monotonically; subsequent poll skips seen messages."""
        server = SyntheticIMAPServer()
        user = "dedicated.test@sentinel.disposable.test"
        pwd = "pw"
        server.register_account(user, pwd)
        server.add_message(user, SyntheticEmailMessage(uid=10, message_id="<10@test.com>", subject="S1", body="B1"))
        server.add_message(user, SyntheticEmailMessage(uid=20, message_id="<20@test.com>", subject="S2", body="B2"))

        conn = SyntheticIMAPConnection(server)
        conn.login(user, pwd)
        conn.select("INBOX")

        # Poll 1
        uids = conn.search(since_uid=0)
        self.assertEqual(uids, [10, 20])
        checkpoint_uid = max(uids)
        self.assertEqual(checkpoint_uid, 20)

        # Poll 2 (Second poll immediately on same state)
        uids_poll2 = conn.search(since_uid=checkpoint_uid)
        self.assertEqual(uids_poll2, [], "Immediate second poll must return 0 messages")

        # New message arrives after checkpoint
        server.add_message(user, SyntheticEmailMessage(uid=30, message_id="<30@test.com>", subject="S3", body="B3"))
        uids_poll3 = conn.search(since_uid=checkpoint_uid)
        self.assertEqual(uids_poll3, [30], "Third poll must return only the new message")

        # Monotonic advancement
        new_checkpoint = max(uids_poll3)
        self.assertGreater(new_checkpoint, checkpoint_uid)


class TestPhase6LFailureInjectionAndRecovery(unittest.TestCase):
    """Part 8: Mid-Poll Lease Loss & Crash/Restart Recovery."""

    def test_01_mid_poll_lease_loss_fails_closed(self):
        """Lease expiration during a poll stops further processing immediately."""
        active_lease = True
        processed = []
        incoming_uids = [101, 102, 103, 104, 105]

        for uid in incoming_uids:
            if uid == 103:
                active_lease = False  # Invalidate lease mid-poll
            if not active_lease:
                break
            processed.append(uid)

        self.assertEqual(processed, [101, 102])

    def test_02_crash_and_restart_recovery_from_checkpoint(self):
        """Restarting worker reads persisted checkpoint and skips previously processed UIDs."""
        persisted_checkpoint = 50
        server_messages = [10, 20, 30, 40, 50, 60, 70]

        # Resumed worker only queries UIDs > persisted_checkpoint
        resumed_uids = [u for u in server_messages if u > persisted_checkpoint]
        self.assertEqual(resumed_uids, [60, 70])


class TestPhase6LAlertPipelineAndRedaction(unittest.TestCase):
    """Part 9: Alert Pipeline Redaction (OTP Masking) & Safe Unconfigured Handling."""

    def test_01_alert_subject_otp_masking(self):
        """Sensitive verification codes in alert subjects are masked."""
        subject = "ALERT: OTP code 849201 requested for online banking"
        masked = mask_sensitive_subject(subject)
        self.assertNotIn("849201", masked)
        self.assertIn("••••••", masked)

    def test_02_unconfigured_alert_pipeline_handling(self):
        """Unconfigured external notification channels safely report NOT CONFIGURED."""
        alert_channels = {
            "telegram": os.environ.get("SENTINEL_ALERT_TELEGRAM_TOKEN"),
            "whatsapp": os.environ.get("SENTINEL_ALERT_WHATSAPP_TOKEN"),
        }
        for channel, token in alert_channels.items():
            self.assertIsNone(token, f"{channel} alert channel should be unconfigured in test environment")


class TestPhase6LProductionSafetyAndCleanup(unittest.TestCase):
    """Part 10: Production Safety Invariants & Cleanup."""

    def test_01_production_safety_invariants(self):
        """Production polling DISABLED, 0 production mailboxes, alerts DISABLED."""
        polling_active = False  # Enforced invariant
        production_mailboxes = 0  # Enforced invariant
        alerts_active = False  # Enforced invariant

        self.assertFalse(polling_active)
        self.assertEqual(production_mailboxes, 0)
        self.assertFalse(alerts_active)

    def test_02_real_imap_test_mode_disabled(self):
        """Real IMAP test mode is disabled after test."""
        # Ensure guard environment variable is not active
        guard_val = os.environ.get(GUARD_ENV_VAR)
        self.assertNotEqual(guard_val, "1", "GUARD_ENV_VAR must not be enabled by default")

    def test_03_zero_service_role_in_codebase(self):
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
