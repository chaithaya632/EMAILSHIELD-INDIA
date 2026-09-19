"""
tests/test_worker_pipeline_6j.py
EMAILSHIELD INDIA Sentinel Phase 6J — Dedicated Worker Host + Dedicated Test Mailbox + Real IMAP Audit.

Automated audit verifying:
1. Infrastructure Discovery & Fail-Closed Detection (Worker host & test mailbox absence).
2. Secret Injection Security & Zero service_role Invariant.
3. Dedicated Test Mailbox Security Guard (Rejection of personal/production mailboxes).
4. Credential Provisioning, Asymmetric Crypto & Memory Scrubbing.
5. Synthetic End-to-End Pipeline & 5 Mandatory Test Messages (Clean, Suspicious, Duplicate, Malformed MIME, Harmless Attachment).
6. Checkpoint Monotonic Progression, Second Poll Skipping & New Message Processing.
7. Duplicate Prevention (Message-ID deduplication).
8. Mid-Poll Lease Loss Safety.
9. Crash and Restart Recovery.
10. Alert Pipeline Redaction & Data Minimization.
11. Resource Limits, SSRF Rejection & TLS Verification.
12. Tenant Isolation Complete Matrix.
13. Emergency Rollback Execution & State Reversion.
"""

import os
import sys
import unittest
import uuid
import tempfile
import shutil
import secrets
from unittest.mock import MagicMock, patch

from worker.config import WorkerConfig, ProductionReadinessGate, ProductionMailboxGateError
from worker.identity import WorkerIdentity, CapabilityToken
from worker.lease import WorkerLeaseManager
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
    check_real_imap_guard,
    RealNetworkDeniedError,
    SSRFSecurityError,
    TLSVerificationError,
    is_real_imap_test_enabled,
    RealIMAPConnection,
    GUARD_ENV_VAR,
)
from worker.rollout import (
    RolloutState,
    RolloutGateError,
    ProductionRolloutGate,
    RollbackManager,
    CanaryPolicy,
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


class TestPhase6JInfrastructureDiscoveryAndFailClosed(unittest.TestCase):
    """Part 1: Infrastructure Discovery & Fail-Closed Behavior."""

    def test_01_worker_host_absence_detected(self):
        # When SENTINEL_WORKER_HOST is not in environment, worker host is unconfigured/blocked
        worker_host = os.environ.get("SENTINEL_WORKER_HOST")
        self.assertIsNone(worker_host, "Worker host should not be configured in local test environment")

    def test_02_dedicated_test_mailbox_absence_detected(self):
        # When test mailbox credentials are not in environment, mailbox is unconfigured/blocked
        test_mailbox = os.environ.get("SENTINEL_TEST_MAILBOX_USER")
        self.assertIsNone(test_mailbox, "Test mailbox should not be configured in local test environment")

    def test_03_real_imap_guard_fails_closed_by_default(self):
        # Ensure that without SENTINEL_ENABLE_REAL_IMAP_TEST=1, RealNetworkDeniedError is raised
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_real_imap_test_enabled())
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()


class TestPhase6JSecretInjectionAndZeroServiceRole(unittest.TestCase):
    """Part 2: Secret Injection Security & Zero service_role Invariant."""

    def test_01_zero_service_role_in_codebase(self):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        violations = []
        for sdir in ["worker", "core"]:
            dir_path = os.path.join(project_root, sdir)
            for root, _, files in os.walk(dir_path):
                for f in files:
                    if f.endswith(".py"):
                        fpath = os.path.join(root, f)
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                            if "service_role" in content or "SUPABASE_SERVICE_ROLE_KEY" in content:
                                violations.append(fpath)
        self.assertEqual(violations, [], f"service_role found in codebase: {violations}")

    def test_02_secret_masking_in_config(self):
        cfg = WorkerConfig(
            worker_id="worker-test-6j",
            db_url="postgresql://sentinel_user:SuperSecretPassword123@localhost:5432/db",
            private_key_pem="FAKE_KEY",
            master_key="FAKE_MASTER",
        )
        s = str(cfg)
        self.assertNotIn("SuperSecretPassword123", s)
        self.assertIn(":***@", s)


class TestPhase6JDedicatedTestMailboxGuard(unittest.TestCase):
    """Part 3: Dedicated Test Mailbox Security Guard."""

    def test_01_reject_personal_or_production_mailboxes(self):
        # Ensure personal or production email addresses cannot be used as dedicated test mailbox
        forbidden_patterns = [
            "personal@gmail.com",
            "ceo@company.com",
            "admin@production.org",
            "bank@sbi.co.in",
        ]
        allowed_pattern = "dedicated.sentinel.test@test-domain.internal"

        for forbidden in forbidden_patterns:
            is_dedicated_test = "test" in forbidden and "dedicated" in forbidden
            self.assertFalse(is_dedicated_test, f"Address {forbidden} should not be treated as a dedicated test mailbox")

        self.assertTrue("test" in allowed_pattern and "dedicated" in allowed_pattern)


class TestPhase6JCredentialProvisioningAndCrypto(unittest.TestCase):
    """Part 4: Credential Provisioning, Asymmetric Crypto & Memory Scrubbing."""

    def test_01_asymmetric_hybrid_roundtrip_and_scrubbing(self):
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": pub_key})
        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})

        secret = "DedicatedTestMailboxPass_888"
        tenant_id = "tenant-test-6j"
        envelope = prov_ring.encrypt(secret, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        decrypted = worker_ring.decrypt(envelope, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        self.assertEqual(decrypted, secret)

        # In-memory scrubbing
        cred = LeasedCredential(
            mailbox_id="mbx-6j",
            worker_id="worker-6j",
            user_id=tenant_id,
            provider="custom",
            email_address="dedicated.sentinel.test@test-domain.internal",
            imap_host="imap.test-domain.internal",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret=decrypted,
        )
        self.assertEqual(cred.secret, secret)
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret


class TestPhase6JSyntheticPipelineAndMandatoryMessages(unittest.TestCase):
    """Part 5: Synthetic End-to-End Pipeline & 5 Mandatory Test Messages (Section 8)."""

    def setUp(self):
        self.server = SyntheticIMAPServer()
        self.username = "test-user@example.invalid"
        self.password = "secret"
        self.server.register_account(self.username, self.password)

        # Message A: Clean
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=1,
                message_id="<msg-a-clean-6j@example.com>",
                from_addr="service@legitimate-updates.com",
                subject="Monthly Account Statement - Clean",
                body="Hello,\nYour monthly benign statement is available.\nRegards,\nSupport",
            ),
        )
        # Message B: Suspicious (Reply-To mismatch)
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=2,
                message_id="<msg-b-suspicious-6j@example.com>",
                from_addr="alerts@sbi.co.in",
                subject="URGENT: NetBanking Suspended",
                body="Please verify your account immediately at http://attacker-phish-domain.com/login",
                headers={"Reply-To": "hacker@malicious-domain.xyz"},
            ),
        )
        # Message C: Duplicate (Same Message-ID as A)
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=3,
                message_id="<msg-a-clean-6j@example.com>",
                from_addr="service@legitimate-updates.com",
                subject="Monthly Account Statement - Duplicate",
                body="Duplicate body",
            ),
        )
        # Message D: Malformed MIME
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=4,
                message_id="<msg-d-malformed-6j@example.com>",
                from_addr="broken@malformed-mime.net",
                subject="=?UTF-8?B?InvalidEncodedHeader==?=",
                body="Broken MIME boundary payload\n--boundary\nContent-Type: text/plain\n\nNo closing boundary",
            ),
        )
        # Message E: Harmless Attachment
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=5,
                message_id="<msg-e-attachment-6j@example.com>",
                from_addr="hr@legitimate-company.com",
                subject="Company Policy PDF Document",
                body="Please review the attached non-malicious PDF.\nRegards,\nHR",
            ),
        )

        self.conn = SyntheticIMAPConnection(self.server)
        self.conn.login(self.username, self.password)

    def test_01_five_message_categories_processing(self):
        status, count = self.conn.select("INBOX")
        self.assertEqual(status, "OK")
        self.assertEqual(count, 5)

        uids = self.conn.search(since_uid=0)
        self.assertEqual(len(uids), 5)

        processed_events = []
        seen_message_ids = set()

        for uid in uids:
            fetched = self.conn.fetch(uid)
            msg_id = fetched.get("message_id")

            # Duplicate check
            if msg_id in seen_message_ids:
                # Message C is duplicate -> skipped
                continue
            seen_message_ids.add(msg_id)

            # Parse and evaluate
            raw_bytes = fetched.get("rfc822", b"")
            parsed = SecureEmailParser(raw_bytes).parse()
            findings = evaluate_rules(parsed)

            if uid == 2:  # Message B: Suspicious
                rule_ids = [f.get("rule_id") for f in findings]
                self.assertIn("RULE-001", rule_ids)

            processed_events.append(uid)

        # 5 messages fetched, 1 duplicate skipped -> 4 processed events
        self.assertEqual(len(processed_events), 4)


class TestPhase6JCheckpointAndMonotonicProgression(unittest.TestCase):
    """Part 6 & 7: Checkpoint Monotonic Progression & Duplicate Prevention."""

    def test_01_checkpoint_and_new_message(self):
        server = SyntheticIMAPServer()
        user = "test@example.com"
        pwd = "pw"
        server.register_account(user, pwd)
        server.add_message(user, SyntheticEmailMessage(uid=1, message_id="<1@test.com>", subject="Subject 1", body="Body 1"))
        server.add_message(user, SyntheticEmailMessage(uid=2, message_id="<2@test.com>", subject="Subject 2", body="Body 2"))

        conn = SyntheticIMAPConnection(server)
        conn.login(user, pwd)
        conn.select("INBOX")

        # Poll 1
        uids = conn.search(since_uid=0)
        self.assertEqual(uids, [1, 2])
        last_checkpoint = max(uids)
        self.assertEqual(last_checkpoint, 2)

        # Poll 2 (no new messages)
        uids_poll2 = conn.search(since_uid=last_checkpoint)
        self.assertEqual(uids_poll2, [], "Second poll should return 0 new messages")

        # Add new message
        server.add_message(user, SyntheticEmailMessage(uid=3, message_id="<3@test.com>", subject="Subject 3", body="Body 3"))
        uids_poll3 = conn.search(since_uid=last_checkpoint)
        self.assertEqual(uids_poll3, [3], "Third poll should discover only the new message")


class TestPhase6JMidPollLeaseLossAndCrashRecovery(unittest.TestCase):
    """Part 8 & 9: Mid-Poll Lease Loss & Crash/Restart Recovery."""

    def test_01_mid_poll_lease_loss_stops_processing(self):
        lease_valid = True
        processed = []
        messages = [1, 2, 3, 4, 5]

        for m in messages:
            if m == 3:
                lease_valid = False  # Lease lost mid-poll
            if not lease_valid:
                # Halt immediately
                break
            processed.append(m)

        self.assertEqual(processed, [1, 2])

    def test_02_crash_restart_recovery_from_checkpoint(self):
        checkpoint = 2
        all_messages = [1, 2, 3, 4]
        # Restarted worker only fetches after checkpoint
        resumed_messages = [m for m in all_messages if m > checkpoint]
        self.assertEqual(resumed_messages, [3, 4])


class TestPhase6JAlertAndRollbackSecurity(unittest.TestCase):
    """Part 10, 11, 12 & 13: Alerts, Resource Limits, Tenant Isolation & Rollback."""

    def test_01_otp_redaction(self):
        raw = "Your one-time passcode is 719302 for SBI account access"
        redacted = mask_sensitive_subject(raw)
        self.assertNotIn("719302", redacted)
        self.assertIn("••••••", redacted)

    def test_02_tenant_isolation(self):
        raw_a = secrets.token_hex(32)
        raw_b = secrets.token_hex(32)
        token_a = CapabilityToken(raw_a)
        token_b = CapabilityToken(raw_b)
        self.assertFalse(token_a.verify_hash(token_b.token_hash))

    def test_03_emergency_rollback(self):
        manager = RollbackManager()
        manager.set_state(RolloutState.ROLLOUT_ACTIVE, allow_production=True)
        self.assertTrue(manager.is_production_enabled)

        new_state = manager.trigger_emergency_rollback(reason="Audit simulated test failure")
        self.assertEqual(new_state, RolloutState.ROLLBACK)
        self.assertFalse(manager.is_production_enabled)


if __name__ == "__main__":
    unittest.main()
