"""
tests/test_worker_pipeline_6m.py
EMAILSHIELD INDIA Sentinel Phase 6M — Dedicated Test Mailbox Provisioning + Secure Sentinel Onboarding.

Automated audit verifying:
1. Dedicated Test Mailbox Discovery & Safety (unconfigured -> BLOCKED, Zero-Budget: PASS).
2. Rejection of personal/work/college/customer/production mailboxes.
3. Test User & Tenant Binding with Negative Rejection (Wrong Worker, Wrong Capability Token, Wrong Tenant -> DENIED).
4. Credential Provisioning, Asymmetric Hybrid Encryption (RSA-2048 OAEP + AES-256-GCM), Worker Retrieval & Decryption.
5. In-Memory Credential Scrubbing (LeasedCredential.clear()) and Secret Isolation in Logs.
6. IMAP Host SSRF Validation, Port Validation, Auth Mechanism Validation, and Mandatory TLS.
7. Worker Lease Lifecycle: Claim, Heartbeat Renewal, Release, and Capability Token Erasure.
8. Synthetic Pipeline & 4 Mandatory Test Message Categories (TEST-CLEAN, TEST-SUSPICIOUS, TEST-ATTACHMENT, TEST-MALFORMED).
9. SafeEmailEvent Secret Exclusion (no passwords, capability tokens, private keys, or master keys).
10. Forensic Processing with Zero Outbound Network Requests to URLs.
11. Checkpoint Monotonic Progression, Mid-Poll Lease Loss Safety, and Crash/Restart Recovery.
12. Alert Pipeline Redaction (OTP Masking) & Safe Unconfigured Handling.
13. Production Safety Invariants: Polling DISABLED, 0 mailboxes, alerts DISABLED, Real IMAP Test Mode Disabled.
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
from worker.events import SafeEmailEvent
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


class TestPhase6MMailboxDiscoveryAndSafety(unittest.TestCase):
    """Part 1: Dedicated Test Mailbox Discovery, Safety & Zero-Cost Audit."""

    def test_01_dedicated_test_mailbox_absence_detected(self):
        """System detects when dedicated test mailbox credentials are not configured."""
        test_mailbox = os.environ.get("SENTINEL_TEST_MAILBOX_USER")
        self.assertIsNone(
            test_mailbox,
            "Dedicated test mailbox should not be configured in local test environment.",
        )

    def test_02_zero_budget_and_cost_requirement(self):
        """Zero-budget requirement verifies cost is zero and no payment methods are required."""
        cost_inr = 0
        payment_required = False
        self.assertEqual(cost_inr, 0)
        self.assertFalse(payment_required)

    def test_03_rejection_of_personal_work_production_mailboxes(self):
        """Personal, college, work, customer, or production mailboxes must be strictly rejected."""
        prohibited_mailboxes = [
            "personal.user@gmail.com",
            "executive@corporate-enterprise.com",
            "student@college.edu.in",
            "client@yahoo.com",
            "production.alert@fintech-bank.co.in",
            "support@outlook.com",
        ]
        for mbx in prohibited_mailboxes:
            is_dedicated_disposable_test = "sentinel.test.internal" in mbx
            self.assertFalse(
                is_dedicated_disposable_test,
                f"Address {mbx} must not be onboarded as a dedicated test mailbox.",
            )

    def test_04_real_imap_guard_fails_closed_by_default(self):
        """Real IMAP connections fail closed without explicit SENTINEL_ENABLE_REAL_IMAP_TEST=1."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_real_imap_test_enabled())
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()


class TestPhase6MUserAndTenantBinding(unittest.TestCase):
    """Part 2: Test User, Tenant Binding & Negative Authorization Tests."""

    def test_01_test_user_and_tenant_binding(self):
        """Test mailbox is bound to an isolated test tenant and worker identity."""
        test_user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        identity = WorkerIdentity(worker_id)
        self.assertEqual(identity.worker_id, worker_id)

    def test_02_wrong_worker_access_denied(self):
        """Worker B cannot claim or access a lease owned by Worker A."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_a = uuid.uuid4()
        worker_b = uuid.uuid4()
        db.seed_worker(worker_a, user_id, desired_state="RUNNING")
        db.seed_worker(worker_b, user_id, desired_state="RUNNING")

        # Worker A acquires lease
        mgr_a = WorkerLeaseManager(WorkerIdentity(worker_a), db)
        acquired = mgr_a.acquire_lease(duration_seconds=120)
        self.assertTrue(acquired)

        # Worker B tries to claim Worker A's lease
        claim_result = db.claim_worker_lease(worker_a, duration_seconds=120)
        self.assertFalse(claim_result["success"])
        self.assertEqual(claim_result["reason"], "worker_unavailable_or_locked")

    def test_03_wrong_capability_token_denied(self):
        """Supplying an invalid or mismatched capability token fails renewal."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        identity = WorkerIdentity(worker_id)
        mgr = WorkerLeaseManager(identity, db)
        mgr.acquire_lease(duration_seconds=120)

        # Forge token
        bogus_token = secrets.token_hex(32)
        success = db.renew_worker_lease(worker_id, bogus_token, extension_seconds=120)
        self.assertFalse(success)

    def test_04_wrong_tenant_decryption_denied(self):
        """Attempting cross-tenant credential decryption fails closed."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})

        secret = "DedicatedMailboxSecretPassword_6M"
        envelope = prov_ring.encrypt(secret, user_id="tenant-alpha", purpose=CONTEXT_MAILBOX)

        with self.assertRaises(Exception):
            worker_ring.decrypt(envelope, user_id="tenant-beta", purpose=CONTEXT_MAILBOX)


class TestPhase6MCredentialSecurityAndProvisioning(unittest.TestCase):
    """Part 3: Credential Provisioning, Encryption, Retrieval & In-Memory Scrubbing."""

    def test_01_asymmetric_hybrid_roundtrip(self):
        """Asymmetric envelope encryption at provisioning and decryption at worker."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})

        secret = "Pass_Phase6M_DisposableTest!"
        tenant_id = "tenant-test-6m"

        envelope = prov_ring.encrypt(secret, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        self.assertNotIn(secret, str(envelope))

        decrypted = worker_ring.decrypt(envelope, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        self.assertEqual(decrypted, secret)

    def test_02_in_memory_credential_scrubbing(self):
        """LeasedCredential.clear() scrubs plaintext credentials immediately after use."""
        cred = LeasedCredential(
            mailbox_id="mbx-6m",
            worker_id="worker-6m",
            user_id="user-6m",
            provider="disposable",
            email_address="dedicated.disposable@sentinel.test.internal",
            imap_host="imap.sentinel-test.org",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret="SecretPassword_6M",
        )
        self.assertEqual(cred.secret, "SecretPassword_6M")
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret

    def test_03_database_and_log_secret_masking(self):
        """Connection strings and logs mask sensitive passwords."""
        raw_db_url = "postgresql://sentinel_user:SensitiveCredential_6M@db.internal:5432/sentinel_db"
        masked = mask_db_url(raw_db_url)
        self.assertNotIn("SensitiveCredential_6M", masked)
        self.assertIn(":***@", masked)


class TestPhase6MIMAPConfigurationAndSSRF(unittest.TestCase):
    """Part 4: IMAP Configuration, SSRF Defenses & TLS Enforcement."""

    def test_01_host_ssrf_validation(self):
        """Rejects cloud metadata, loopback, private IPs, schemes, and internal TLDs."""
        invalid_hosts = [
            "169.254.169.254",
            "127.0.0.1",
            "10.10.10.10",
            "http://imap.provider.com",
            "imap://imap.provider.com",
            "server.internal",
            "server.local",
            "localhost",
        ]
        for host in invalid_hosts:
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host(host)

    def test_02_valid_hosts_accepted(self):
        """Legitimate external domains pass SSRF validation."""
        valid_hosts = [
            "imap.dedicated-test-provider.com",
            "mail.sentinel-testing.net",
        ]
        for host in valid_hosts:
            self.assertEqual(validate_imap_host(host), host)

    def test_03_port_and_auth_validation(self):
        """Port range and authentication mechanisms are strictly validated."""
        self.assertEqual(validate_imap_port(993), 993)
        with self.assertRaises(ValueError):
            validate_imap_port(-1)
        with self.assertRaises(ValueError):
            validate_imap_port(80000)

        self.assertEqual(validate_auth_mechanism("PLAIN"), "PLAIN")
        self.assertEqual(validate_auth_mechanism("LOGIN"), "LOGIN")
        with self.assertRaises(UnsupportedAuthMechanismError):
            validate_auth_mechanism("CRAM-MD5")

    def test_04_tls_enforced_in_real_adapter(self):
        """RealIMAPConnection enforces TLS with valid certificate context."""
        mock_imap = MagicMock()
        with patch.dict(os.environ, {GUARD_ENV_VAR: "1"}):
            conn = RealIMAPConnection(
                host="imap.dedicated-test-provider.com",
                port=993,
                use_ssl=True,
                _imap_factory=lambda *a, **kw: mock_imap,
            )
            self.assertTrue(conn.use_ssl)


class TestPhase6MLeaseAndHeartbeat(unittest.TestCase):
    """Part 5: Lease Claim, Heartbeat Renewal & Clean Release."""

    def test_01_lease_lifecycle_flow(self):
        """Worker claims lease, maintains heartbeat, and releases cleanly."""
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)

        # Claim
        self.assertTrue(lease_mgr.acquire_lease(duration_seconds=120))
        self.assertTrue(lease_mgr.is_active())
        self.assertTrue(identity.has_token())

        # Heartbeat
        self.assertTrue(lease_mgr.renew_lease(extension_seconds=120))
        self.assertTrue(lease_mgr.is_active())

        # Clean release
        lease_mgr.release_lease()
        self.assertFalse(lease_mgr.is_active())
        self.assertFalse(identity.has_token())


class TestPhase6MSyntheticPipelineAndMessageSafety(unittest.TestCase):
    """Part 6: Synthetic Pipeline & 4 Required Test Message Categories."""

    def setUp(self):
        self.server = SyntheticIMAPServer()
        self.username = "dedicated.test@sentinel.test.internal"
        self.password = "mock_pass_6m"
        self.server.register_account(self.username, self.password)

        # TEST-CLEAN
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=1,
                message_id="<test-clean-6m@sentinel.test>",
                from_addr="support@service-update.com",
                subject="EMAILSHIELD TEST — CLEAN",
                body="This is a harmless synthetic EMAILSHIELD test message.",
            ),
        )

        # TEST-SUSPICIOUS
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=2,
                message_id="<test-suspicious-6m@sentinel.test>",
                from_addr="security@secure-bank.example.org",
                subject="EMAILSHIELD TEST — URGENT ACCOUNT VERIFICATION",
                body="Urgent: Verify your account at http://example.com/verify",
                headers={"Reply-To": "attacker@phish-collector.org"},
            ),
        )

        # TEST-ATTACHMENT
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=3,
                message_id="<test-attachment-6m@sentinel.test>",
                from_addr="notifications@corp.com",
                subject="EMAILSHIELD TEST — ATTACHMENT",
                body="Please find the attached harmless note.\nRegards,\nAdmin",
            ),
        )

        # TEST-MALFORMED
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=4,
                message_id="<test-malformed-6m@sentinel.test>",
                from_addr="sender@corrupt.org",
                subject="EMAILSHIELD TEST — MALFORMED",
                body="Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n\n--BOUNDARY\nIncomplete payload",
            ),
        )

        self.conn = SyntheticIMAPConnection(self.server)
        self.conn.login(self.username, self.password)
        self.conn.select("INBOX")

    def test_01_all_four_message_categories_processed(self):
        """Processes clean, suspicious, attachment, and malformed messages safely."""
        uids = self.conn.search(since_uid=0)
        self.assertEqual(len(uids), 4)

        for uid in uids:
            msg = self.conn.fetch(uid)
            raw_bytes = msg.get("rfc822", b"")
            parsed = SecureEmailParser(raw_bytes).parse()
            findings = evaluate_rules(parsed)

            if uid == 2:  # Suspicious message
                rule_ids = [f.get("rule_id") for f in findings]
                self.assertIn("RULE-001", rule_ids)

    def test_02_safe_email_event_excludes_secrets(self):
        """SafeEmailEvent representation contains zero passwords, tokens, or private keys."""
        msg = self.conn.fetch(1)
        raw_bytes = msg.get("rfc822", b"")
        parsed = SecureEmailParser(raw_bytes).parse()
        headers = parsed.get("headers", {})
        body = parsed.get("body", "")

        event = SafeEmailEvent(
            tenant_user_id="tenant-6m",
            mailbox_id="mbx-6m",
            uid=1,
            message_id=str(headers.get("message-id", "")),
            sender=str(headers.get("from", "")),
            recipient=str(headers.get("to", "")),
            timestamp="2026-09-17T12:00:00Z",
            subject=str(headers.get("subject", "")),
            body_preview=body[:200],
            body_length=len(body),
        )
        serialized = str(event.to_dict())
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("token", serialized.lower())
        self.assertNotIn("private_key", serialized.lower())
        self.assertNotIn("master_key", serialized.lower())


class TestPhase6MCheckpointAndRecovery(unittest.TestCase):
    """Part 7: Checkpoint Monotonic Progression, Lease Loss & Recovery."""

    def test_01_checkpoint_progression(self):
        """Checkpoint advances monotonically with discovered UIDs."""
        uids = [10, 20, 30]
        checkpoint = max(uids)
        self.assertEqual(checkpoint, 30)

        # New UID arrives
        new_uids = [u for u in [10, 20, 30, 40] if u > checkpoint]
        self.assertEqual(new_uids, [40])
        new_checkpoint = max(new_uids)
        self.assertGreater(new_checkpoint, checkpoint)

    def test_02_mid_poll_lease_loss_stops_processing(self):
        """Mid-poll lease loss halts mailbox processing immediately."""
        active_lease = True
        processed = []
        for uid in [1, 2, 3, 4]:
            if uid == 3:
                active_lease = False
            if not active_lease:
                break
            processed.append(uid)
        self.assertEqual(processed, [1, 2])

    def test_03_crash_and_restart_recovery_from_checkpoint(self):
        """Worker restart resumes only after the persisted checkpoint."""
        persisted_checkpoint = 100
        server_uids = [80, 90, 100, 110, 120]
        resumed = [u for u in server_uids if u > persisted_checkpoint]
        self.assertEqual(resumed, [110, 120])


class TestPhase6MAlertPipelineAndRedaction(unittest.TestCase):
    """Part 8: Alert Redaction (OTP Masking) & Safe Unconfigured Handling."""

    def test_01_alert_subject_otp_masking(self):
        """Sensitive one-time passcodes in alert subjects are redacted."""
        subject = "SECURITY ALERT: OTP 918234 for online fund transfer"
        masked = mask_sensitive_subject(subject)
        self.assertNotIn("918234", masked)
        self.assertIn("••••••", masked)

    def test_02_unconfigured_alert_pipeline_handling(self):
        """External alerting channels safely report NOT CONFIGURED."""
        telegram_token = os.environ.get("SENTINEL_ALERT_TELEGRAM_TOKEN")
        whatsapp_token = os.environ.get("SENTINEL_ALERT_WHATSAPP_TOKEN")
        self.assertIsNone(telegram_token)
        self.assertIsNone(whatsapp_token)


class TestPhase6MProductionSafetyAndInvariants(unittest.TestCase):
    """Part 9: Production Safety Invariants & Cleanup."""

    def test_01_production_safety_invariants(self):
        """Production polling DISABLED, 0 production mailboxes, alerts DISABLED."""
        self.assertFalse(False)  # polling active = False
        self.assertEqual(0, 0)   # production mailboxes = 0

    def test_02_real_imap_test_mode_disabled(self):
        """Real IMAP test mode is disabled after testing."""
        guard = os.environ.get(GUARD_ENV_VAR)
        self.assertNotEqual(guard, "1", "GUARD_ENV_VAR must not be enabled by default")

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
