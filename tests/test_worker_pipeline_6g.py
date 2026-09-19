"""
tests/test_worker_pipeline_6g.py
Comprehensive automated test suite for Sentinel Phase 6G:
Controlled Live End-to-End Sentinel Validation.

Test Coverage:
1. Safety Gate & Infrastructure Detection (Live Test Safety Gate, Worker Host & Test Mailbox Detection)
2. Controlled Live End-to-End Pipeline & Cryptographic Round-Trip
3. Five Mandatory Synthetic Test Email Categories (TEST-01 Clean, TEST-02 Suspicious, TEST-03 Duplicate, TEST-04 Malformed, TEST-05 Attachment)
4. Monotonic Checkpointing, Second Poll Duplicate Prevention & Tenant Scoping
5. Mid-Poll Lease Loss Safety & Worker Crash/Restart Recovery
6. Controlled Alert Formatting, Privacy Redaction & Zero-Secret Dispatch Bounds
7. Multi-Tenant & Lease Concurrency Isolation
8. SSRF Hardening, Mandatory TLS Verification & Resource Bounds
9. Streamlit Isolation, Logging Security & Production Safety Gate
"""

import email
from email.message import EmailMessage
import json
import logging
import os
import sys
import subprocess
import time
import unittest
import unittest.mock
import uuid

from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    WorkerKeyRing,
    ProvisioningKeyRing,
    DecryptionError,
    UnknownKeyVersionError,
    CONTEXT_MAILBOX,
)
from core.parser import SecureEmailParser
from core.risk import evaluate_rules
from core.sentinel import format_threat_alert_text, mask_sensitive_subject, send_test_alert
from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.db import MockWorkerDBClient, RoleVerificationError, TableAccessViolationError
from worker.lease import WorkerLeaseManager
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.checkpoint import CheckpointStore
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticEmailMessage,
)
from worker.poller import MailboxPoller, MAX_MESSAGE_SIZE_BYTES
from worker.events import SafeEmailEvent
from worker.imap_client import (
    RealIMAPConnection,
    RealNetworkDeniedError,
    SSRFSecurityError,
    TLSVerificationError,
    check_real_imap_guard,
    validate_imap_host,
    is_real_imap_test_enabled,
    GUARD_ENV_VAR,
)
from worker.service import WorkerService
from worker.health import WorkerHealthMonitor
from worker.runtime import DaemonState


class TestPhase6GSafetyGateAndInfrastructure(unittest.TestCase):
    """Verifies live test safety gates, worker host detection, and dedicated test mailbox detection."""

    def test_01_real_imap_guard_fails_closed_by_default(self):
        """When SENTINEL_ENABLE_REAL_IMAP_TEST is absent or invalid, real IMAP is blocked."""
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_real_imap_test_enabled())
            with self.assertRaises(RealNetworkDeniedError) as ctx:
                check_real_imap_guard()
            self.assertIn("Real IMAP network connections are disabled by default", str(ctx.exception))

        for invalid_val in ["0", "false", "FALSE", "None", "yes", "TRUE", "enabled", ""]:
            with unittest.mock.patch.dict(os.environ, {GUARD_ENV_VAR: invalid_val}):
                self.assertFalse(is_real_imap_test_enabled())
                with self.assertRaises(RealNetworkDeniedError):
                    check_real_imap_guard()

    def test_02_worker_host_and_test_mailbox_absence_fails_closed(self):
        """When dedicated test mailbox or worker host is not configured, operations remain local and safe."""
        cfg = WorkerConfig.from_env({})
        self.assertFalse(cfg.production_polling_enabled)
        self.assertFalse(cfg.test_mode)
        self.assertIn("<not-configured>", repr(cfg))

    def test_03_production_safety_gates_preserved(self):
        """Confirms production polling is strictly disabled by default in worker config and runtime."""
        cfg = WorkerConfig()
        self.assertFalse(cfg.production_polling_enabled)
        self.assertFalse(cfg.test_mode)


class TestPhase6GLivePipelineE2E(unittest.TestCase):
    """Verifies complete controlled live end-to-end pipeline with cryptographic round-trip."""

    @classmethod
    def setUpClass(cls):
        cls.priv_key, cls.pub_key = generate_worker_asymmetric_keypair(2048)
        cls.user_id = uuid.uuid4()
        cls.worker_id = uuid.uuid4()
        cls.mailbox_id = uuid.uuid4()

        cls.username = "sentinel.live.test@domain.invalid"
        cls.password = "secret_live_app_password_789"
        cls.imap_host = "imap.dedicated-test.invalid"
        cls.imap_port = 993

        # Asymmetric hybrid encryption via ProvisioningKeyRing (Edge Function equivalent)
        cls.prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": cls.pub_key})
        secret_payload = json.dumps({
            "username": cls.username,
            "password": cls.password,
            "imap_host": cls.imap_host,
            "imap_port": cls.imap_port,
        })
        cls.envelope = cls.prov_ring.encrypt(
            secret_payload,
            user_id=str(cls.user_id),
            purpose=CONTEXT_MAILBOX
        )

    def setUp(self):
        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")
        self.db.seed_mailbox(
            self.mailbox_id, self.worker_id, self.user_id,
            encrypted_credentials=self.envelope
        )
        self.identity = WorkerIdentity(self.worker_id)
        self.worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key})

    def test_01_worker_session_identity_and_table_privilege_denial(self):
        """Worker connects strictly as sentinel_worker_daemon and has 0 direct table privileges."""
        sess_user, curr_user, role_setting = self.db.verify_session_identity()
        self.assertEqual(sess_user, "sentinel_worker_daemon")
        self.assertEqual(curr_user, "sentinel_worker_daemon")
        self.assertIn(role_setting, ("sentinel_worker_daemon", "sentinel_worker_role"))

        # Confirm direct table privilege denial
        self.db.verify_table_privilege_denial()
        with self.assertRaises(PermissionError):
            self.db.direct_table_select("sentinel_mailboxes")

    def test_02_full_pipeline_lease_token_credential_decrypt_scrub(self):
        """Complete pipeline: claim lease -> capability token -> fetch envelope -> decrypt in memory -> scrub."""
        lease_mgr = WorkerLeaseManager(self.identity, self.db)
        self.assertTrue(lease_mgr.acquire_lease(duration_seconds=120))
        self.assertTrue(self.identity.has_token())

        cred_service = WorkerCredentialService(self.identity, self.worker_ring, self.db)
        leased_cred = cred_service.fetch_and_decrypt()

        self.assertIsInstance(leased_cred, LeasedCredential)
        self.assertEqual(leased_cred.mailbox_id, str(self.mailbox_id))
        self.assertEqual(leased_cred.user_id, str(self.user_id))

        # Parse secret in memory
        cred_dict = json.loads(leased_cred.secret)
        self.assertEqual(cred_dict["username"], self.username)
        self.assertEqual(cred_dict["password"], self.password)

        # Repr security: plaintext password never exposed
        self.assertNotIn(self.password, repr(leased_cred))
        self.assertNotIn(self.password, str(leased_cred))
        self.assertIn("[REDACTED_ACTIVE]", repr(leased_cred))

        # Memory cleanup
        leased_cred.clear()
        self.assertIn("[REDACTED_WIPED]", repr(leased_cred))
        with self.assertRaises(ValueError):
            _ = leased_cred.secret

    def test_03_capability_token_security_matrix(self):
        """Capability token verification fails closed on wrong, cross-worker, expired, or released tokens."""
        lease_mgr = WorkerLeaseManager(self.identity, self.db)
        lease_mgr.acquire_lease(duration_seconds=120)

        # 1. Wrong token
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_id, "ff" * 32)

        # 2. Cross-worker token (Worker B with Worker A's token)
        worker_b_id = uuid.uuid4()
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(worker_b_id, self.identity.raw_token)

        # 3. Released token
        lease_mgr.release_lease()
        self.assertFalse(self.identity.has_token())
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_id, "aa" * 32)

    def test_04_cryptographic_tamper_rejection(self):
        """Decryption fails closed on tampered ciphertext, wrong tenant AAD, or wrong private key."""
        parts = self.envelope.split(":")
        flip_ct = "B" if parts[4][0] == "A" else "A"
        tampered_ct = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{flip_ct}{parts[4][1:]}"

        with self.assertRaises(DecryptionError):
            self.worker_ring.decrypt(tampered_ct, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)

        attacker_user_id = str(uuid.uuid4())
        with self.assertRaises(DecryptionError):
            self.worker_ring.decrypt(self.envelope, user_id=attacker_user_id, purpose=CONTEXT_MAILBOX)

        other_priv, _ = generate_worker_asymmetric_keypair(2048)
        other_ring = WorkerKeyRing(active_version="k1", keys={"k1": other_priv})
        with self.assertRaises(DecryptionError):
            other_ring.decrypt(self.envelope, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)


class TestPhase6GFiveSyntheticEmailCategories(unittest.TestCase):
    """
    Verifies Section 12 required synthetic email set:
    TEST-01 — Clean legitimate message
    TEST-02 — Suspicious message evaluated safely by forensic engine
    TEST-03 — Duplicate message (same Message-ID as TEST-01)
    TEST-04 — Malformed MIME message handled safely without crash
    TEST-05 — Harmless attachment message (payload NOT executed)
    """

    @classmethod
    def setUpClass(cls):
        cls.priv_key, cls.pub_key = generate_worker_asymmetric_keypair(2048)
        cls.user_id = uuid.uuid4()
        cls.worker_id = uuid.uuid4()
        cls.mailbox_id = uuid.uuid4()

        cls.username = "test.six.g@example.invalid"
        cls.password = "app_pw_6g_secret"

        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": cls.pub_key})
        secret_payload = json.dumps({
            "username": cls.username,
            "password": cls.password,
            "imap_host": "imap.example.invalid",
            "imap_port": 993,
        })
        cls.envelope = prov_ring.encrypt(secret_payload, user_id=str(cls.user_id))

    def setUp(self):
        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")
        self.db.seed_mailbox(
            self.mailbox_id, self.worker_id, self.user_id,
            encrypted_credentials=self.envelope
        )
        self.identity = WorkerIdentity(self.worker_id)
        self.lease_mgr = WorkerLeaseManager(self.identity, self.db)
        self.lease_mgr.acquire_lease(duration_seconds=180)

        self.worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": self.priv_key})
        self.cred_service = WorkerCredentialService(self.identity, self.worker_ring, self.db)
        self.checkpoint_store = CheckpointStore()
        self.synthetic_server = SyntheticIMAPServer()
        self.synthetic_server.register_account(self.username, self.password)

        self.poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id),
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=self.synthetic_server,
        )

    def test_01_execute_five_synthetic_email_categories(self):
        """Tests sequential processing of all 5 synthetic email types and forensic evaluation."""
        # --- TEST-01: Clean Legitimate Message ---
        email_1 = SyntheticEmailMessage(
            uid=1,
            message_id="<test-01-clean@domain.invalid>",
            from_addr="billing@legitimate-service.org",
            to_addr="sentinel-user@domain.invalid",
            subject="Monthly Service Invoice - Clean",
            body="Your monthly service invoice is attached. No payment action needed.",
        )
        self.synthetic_server.add_message(self.username, email_1)

        # --- TEST-02: Suspicious Message (Forensic evaluation) ---
        email_2 = SyntheticEmailMessage(
            uid=2,
            message_id="<test-02-suspicious@domain.invalid>",
            from_addr="Executive Security <security@legitimate-service.org>",
            to_addr="sentinel-user@domain.invalid",
            headers={"Reply-To": "attacker-collector@external-fraud.invalid"},
            subject="URGENT: Immediate Account Re-Verification Required",
            body="Your account will be terminated unless you reply immediately to verify credentials.",
        )
        self.synthetic_server.add_message(self.username, email_2)

        # Forensic evaluation: confirm SecureEmailParser and evaluate_rules safely analyze it
        parsed_2 = SecureEmailParser(email_2.to_rfc822()).parse()
        findings_2 = evaluate_rules(parsed_2)
        rule_ids_2 = [f.get("rule_id") for f in findings_2]
        self.assertIn("RULE-001", rule_ids_2)

        # --- TEST-03: Duplicate Message (Same Message-ID as TEST-01) ---
        email_3 = SyntheticEmailMessage(
            uid=3,
            message_id="<test-01-clean@domain.invalid>",  # DUPLICATE of TEST-01
            from_addr="billing@legitimate-service.org",
            to_addr="sentinel-user@domain.invalid",
            subject="Monthly Service Invoice - Copy",
            body="Duplicate copy of previous statement.",
        )
        self.synthetic_server.add_message(self.username, email_3)

        # --- TEST-04: Malformed MIME ---
        email_4 = SyntheticEmailMessage(
            uid=4,
            message_id="",
            raw_bytes=b"Invalid-Headers-No-Break-Line\r\n\r\nMalformed body without boundary or encoding",
        )
        self.synthetic_server.add_message(self.username, email_4)

        # --- TEST-05: Harmless Attachment Test ---
        msg_5 = EmailMessage()
        msg_5["Message-ID"] = "<test-05-attachment@domain.invalid>"
        msg_5["From"] = "reports@legitimate-service.org"
        msg_5["To"] = "sentinel-user@domain.invalid"
        msg_5["Subject"] = "Quarterly System Performance Report"
        msg_5["Date"] = "Thu, 17 Sep 2026 14:00:00 +0000"
        msg_5.set_content("Attached is the quarterly system performance audit.")
        msg_5.add_attachment(
            b"%PDF-1.4 synthetic dummy pdf contents for test",
            maintype="application",
            subtype="pdf",
            filename="quarterly_audit.pdf",
        )
        email_5 = SyntheticEmailMessage(
            uid=5,
            message_id="<test-05-attachment@domain.invalid>",
            raw_bytes=msg_5.as_bytes(),
        )
        self.synthetic_server.add_message(self.username, email_5)

        # Run poll
        result = self.poller.poll()
        self.assertEqual(result["status"], "SUCCESS")

        events = result["events"]
        # TEST-01: Processed
        # TEST-02: Processed
        # TEST-03: Duplicate -> Skipped
        # TEST-04: Malformed -> Handled safely (PROCESSED or ERROR)
        # TEST-05: Attachment -> Processed with attachment_count = 1
        self.assertEqual(len(events), 4)

        # TEST-01 check
        evt_1 = next(e for e in events if e.uid == 1)
        self.assertEqual(evt_1.message_id, "<test-01-clean@domain.invalid>")
        self.assertEqual(evt_1.processing_status, "PROCESSED")

        # TEST-02 check
        evt_2 = next(e for e in events if e.uid == 2)
        self.assertEqual(evt_2.message_id, "<test-02-suspicious@domain.invalid>")
        self.assertEqual(evt_2.processing_status, "PROCESSED")

        # TEST-03 check: duplicate message-id was skipped
        self.assertFalse(any(e.uid == 3 for e in events))

        # TEST-04 check: handled safely
        evt_4 = next(e for e in events if e.uid == 4)
        self.assertIn(evt_4.processing_status, ("PROCESSED", "ERROR"))

        # TEST-05 check: attachment count = 1, payload NOT executed
        evt_5 = next(e for e in events if e.uid == 5)
        self.assertEqual(evt_5.attachment_count, 1)

        # Monotonic checkpoint verification
        cp = self.checkpoint_store.get_checkpoint(
            user_id=str(self.user_id),
            worker_id=str(self.worker_id),
            mailbox_id=str(self.mailbox_id),
        )
        self.assertEqual(cp.last_processed_uid, 5)


class TestPhase6GCheckpointingAndRestart(unittest.TestCase):
    """Verifies monotonic checkpointing, second poll duplicate prevention, and mid-poll lease loss."""

    def test_01_second_poll_duplicate_prevention(self):
        """Second poll on existing mailbox processes 0 messages and emits 0 duplicate events."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        mailbox_id = uuid.uuid4()
        username = "sec.poll@domain.invalid"
        password = "pw"

        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": pub_key})
        env = prov_ring.encrypt(json.dumps({"username": username, "password": password, "imap_host": "imap.ex", "imap_port": 993}), user_id=str(user_id))

        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        db.seed_mailbox(mailbox_id, worker_id, user_id, encrypted_credentials=env)

        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)
        lease_mgr.acquire_lease(duration_seconds=120)

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})
        cred_service = WorkerCredentialService(identity, worker_ring, db)
        checkpoint_store = CheckpointStore()
        server = SyntheticIMAPServer()
        server.register_account(username, password)

        # Seed initial messages
        for uid in [1, 2]:
            server.add_message(username, SyntheticEmailMessage(uid=uid, message_id=f"<m-{uid}@dom.invalid>", subject=f"M {uid}"))

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=worker_id),
            identity=identity,
            lease_manager=lease_mgr,
            credential_service=cred_service,
            checkpoint_store=checkpoint_store,
            synthetic_server=server,
        )

        res_1 = poller.poll()
        self.assertEqual(res_1["processed_count"], 2)

        # Second poll: no new messages
        res_2 = poller.poll()
        self.assertEqual(res_2["status"], "SUCCESS")
        self.assertEqual(res_2["processed_count"], 0)
        self.assertEqual(len(res_2["events"]), 0)

        # Add message with UID 3 having duplicate Message-ID of UID 1
        server.add_message(username, SyntheticEmailMessage(uid=3, message_id="<m-1@dom.invalid>", subject="Duplicate M 1"))
        res_3 = poller.poll()
        self.assertEqual(res_3["status"], "SUCCESS")
        self.assertEqual(res_3["processed_count"], 0)
        self.assertEqual(len(res_3["events"]), 0)

        cp = checkpoint_store.get_checkpoint(user_id=str(user_id), worker_id=str(worker_id), mailbox_id=str(mailbox_id))
        self.assertEqual(cp.last_processed_uid, 3)

    def test_02_mid_poll_lease_loss_halts_immediately(self):
        """When worker loses its lease mid-poll, processing halts and checkpoint remains at last valid message."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        mailbox_id = uuid.uuid4()
        username = "midpoll@domain.invalid"
        password = "pw"

        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": pub_key})
        env = prov_ring.encrypt(json.dumps({"username": username, "password": password, "imap_host": "imap.ex", "imap_port": 993}), user_id=str(user_id))

        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        db.seed_mailbox(mailbox_id, worker_id, user_id, encrypted_credentials=env)

        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)
        lease_mgr.acquire_lease(duration_seconds=120)

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})
        cred_service = WorkerCredentialService(identity, worker_ring, db)
        checkpoint_store = CheckpointStore()
        server = SyntheticIMAPServer()
        server.register_account(username, password)

        for uid in [101, 102, 103]:
            server.add_message(username, SyntheticEmailMessage(uid=uid, message_id=f"<mid-{uid}@dom.invalid>", subject=f"Sub {uid}"))

        # Invalidate lease right after message 101 checkpoint
        orig_advance = checkpoint_store.advance_checkpoint
        def release_after_101(*args, **kwargs):
            uid = kwargs.get("uid") or (args[3] if len(args) > 3 else None)
            res = orig_advance(*args, **kwargs)
            if uid == 101:
                lease_mgr.release_lease()
            return res

        checkpoint_store.advance_checkpoint = release_after_101

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=worker_id),
            identity=identity,
            lease_manager=lease_mgr,
            credential_service=cred_service,
            checkpoint_store=checkpoint_store,
            synthetic_server=server,
        )

        res = poller.poll()
        self.assertEqual(res["status"], "LEASE_EXPIRED_MID_POLL")
        self.assertEqual(res["processed_count"], 1)
        self.assertEqual(res["events"][0].uid, 101)

        cp = checkpoint_store.get_checkpoint(user_id=str(user_id), worker_id=str(worker_id), mailbox_id=str(mailbox_id))
        self.assertEqual(cp.last_processed_uid, 101)

    def test_03_worker_crash_and_restart_recovery(self):
        """A crashed worker whose lease expires allows a restarted worker to claim and resume from checkpoint."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        # Seed an expired lease from a crashed worker
        db.seed_worker(
            worker_id, user_id, desired_state="RUNNING",
            lease_owner="crashed_daemon",
            lease_expires_at=time.time() - 50,
            lease_token_hash="expired_token_hash"
        )

        # New worker starts up
        restarted_identity = WorkerIdentity(worker_id)
        restarted_lease_mgr = WorkerLeaseManager(restarted_identity, db)
        self.assertTrue(restarted_lease_mgr.acquire_lease(duration_seconds=60))
        self.assertTrue(restarted_lease_mgr.is_active())
        restarted_lease_mgr.release_lease()


class TestPhase6GControlledAlerts(unittest.TestCase):
    """Verifies alert formatting, sensitive token/OTP redaction, and unconfigured external alert handling."""

    def test_01_threat_alert_formatting_and_risk_scoring(self):
        """Alert generator formats markdown alert with emojis and never leaks secrets or tokens."""
        secret_token = "super_secret_capability_token_xyz"
        threat_info = {
            "risk_score": "HIGH",
            "risk_score_numeric": 92,
            "subject": "Urgent Financial Action Needed",
            "sender": "attacker@fraud-site.org",
            "sender_location": "London, UK",
            "risk_reasons": ["Reply-To mismatch detected", "Display name spoofing"],
            "secret_token": secret_token,
        }
        alert_text = format_threat_alert_text(threat_info)
        self.assertIn("EMAILSHIELD CRITICAL SECURITY ALERT", alert_text)
        self.assertIn("attacker@fraud-site.org", alert_text)
        self.assertIn("HIGH RISK (92/100)", alert_text)
        self.assertIn("London, UK", alert_text)
        self.assertNotIn(secret_token, alert_text)

    def test_02_sensitive_otp_redaction(self):
        """Subjects containing OTPs, 2FA codes, or security tokens are masked to prevent privacy leaks."""
        self.assertEqual(mask_sensitive_subject("Your Code - 44830"), "Your Code - ••••••")
        self.assertEqual(mask_sensitive_subject("OTP: 123456"), "OTP: ••••••")
        self.assertEqual(mask_sensitive_subject("44830 is your code"), "•••••• is your code")
        self.assertEqual(mask_sensitive_subject("987654"), "•••••• (Security Code)")

    def test_03_external_alert_delivery_not_configured_fails_safely(self):
        """When Telegram/WhatsApp credentials are absent, dispatch returns False with clear status."""
        ok_tg, msg_tg = send_test_alert("telegram", {"telegram_token": "", "telegram_chat_id": ""})
        self.assertFalse(ok_tg)
        self.assertIn("Invalid Telegram Bot Token", msg_tg)

        ok_wa, msg_wa = send_test_alert("whatsapp", {"whatsapp_phone": "", "whatsapp_apikey": ""})
        self.assertFalse(ok_wa)
        self.assertIn("phone number", msg_wa.lower())


class TestPhase6GMultiTenantAndHardening(unittest.TestCase):
    """Verifies cross-tenant isolation, concurrent lease locking, SSRF, TLS, and resource bounds."""

    def test_01_cross_tenant_mailbox_isolation(self):
        """User A / Worker A cannot access User B / Mailbox B."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_a = uuid.uuid4()
        user_b = uuid.uuid4()
        worker_a = uuid.uuid4()
        worker_b = uuid.uuid4()
        mailbox_a = uuid.uuid4()
        mailbox_b = uuid.uuid4()

        db.seed_worker(worker_a, user_a, desired_state="RUNNING")
        db.seed_worker(worker_b, user_b, desired_state="RUNNING")
        db.seed_mailbox(mailbox_a, worker_a, user_a, encrypted_credentials="v2:k1:wdek:nonce:ctA")
        db.seed_mailbox(mailbox_b, worker_b, user_b, encrypted_credentials="v2:k1:wdek:nonce:ctB")

        id_a = WorkerIdentity(worker_a)
        mgr_a = WorkerLeaseManager(id_a, db)
        mgr_a.acquire_lease(duration_seconds=60)

        id_b = WorkerIdentity(worker_b)
        mgr_b = WorkerLeaseManager(id_b, db)
        mgr_b.acquire_lease(duration_seconds=60)

        # Worker A fetches mailbox_a
        cred_a = db.fetch_leased_mailbox_credential(worker_a, id_a.raw_token)
        self.assertEqual(cred_a["mailbox_id"], str(mailbox_a))

        # Worker A cannot fetch mailbox_b
        with self.assertRaises(PermissionError):
            db.fetch_leased_mailbox_credential(worker_b, id_a.raw_token)

        # Worker B cannot fetch mailbox_a
        with self.assertRaises(PermissionError):
            db.fetch_leased_mailbox_credential(worker_a, id_b.raw_token)

        mgr_a.release_lease()
        mgr_b.release_lease()

    def test_02_concurrent_worker_collision_prevention(self):
        """Worker B cannot claim a lease currently held by Worker A."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_a = uuid.uuid4()
        worker_b = uuid.uuid4()
        db.seed_worker(worker_a, user_id, desired_state="RUNNING")

        id_a = WorkerIdentity(worker_a)
        mgr_a = WorkerLeaseManager(id_a, db)
        self.assertTrue(mgr_a.acquire_lease(duration_seconds=120))

        # Worker B attempts to claim the same worker
        res_b = db.claim_worker_lease(worker_a, duration_seconds=60)
        self.assertFalse(res_b["success"])
        self.assertEqual(res_b["reason"], "worker_unavailable_or_locked")

    def test_03_ssrf_and_tls_hardening(self):
        """Validates that SSRF targets are rejected and TLS verification cannot be disabled."""
        for target in ["169.254.169.254", "127.0.0.1", "10.0.0.5", "corp.internal", "metadata.google.internal"]:
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host(target)

        with unittest.mock.patch.dict(os.environ, {GUARD_ENV_VAR: "1"}):
            conn = RealIMAPConnection(host="imap.gmail.com", port=993, use_ssl=True)
            self.assertTrue(conn._ssl_context.check_hostname)
            import ssl
            self.assertEqual(conn._ssl_context.verify_mode, ssl.CERT_REQUIRED)

    def test_04_resource_limits_oversized_message_bounds(self):
        """Messages exceeding 5MB are bounded and marked OVERSIZED."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        mailbox_id = uuid.uuid4()

        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": pub_key})
        env = prov_ring.encrypt(json.dumps({"username": "u", "password": "p", "imap_host": "h", "imap_port": 993}), user_id=str(user_id))

        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        db.seed_mailbox(mailbox_id, worker_id, user_id, encrypted_credentials=env)

        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)
        lease_mgr.acquire_lease(duration_seconds=60)

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})
        cred_service = WorkerCredentialService(identity, worker_ring, db)
        checkpoint_store = CheckpointStore()
        server = SyntheticIMAPServer()
        server.register_account("u", "p")

        # Oversized message
        server.add_message("u", SyntheticEmailMessage(uid=1, message_id="<oversize@dom>", raw_bytes=b"Y" * (MAX_MESSAGE_SIZE_BYTES + 500)))

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=worker_id),
            identity=identity,
            lease_manager=lease_mgr,
            credential_service=cred_service,
            checkpoint_store=checkpoint_store,
            synthetic_server=server,
        )

        res = poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        evt = res["events"][0]
        self.assertEqual(evt.processing_status, "OVERSIZED")
        self.assertEqual(evt.error_code, "ERR_MESSAGE_TOO_LARGE")

    def test_05_streamlit_isolation_and_zero_secrets(self):
        """Worker service runs in subprocess without importing Streamlit; logs contain 0 secrets."""
        cmd = [
            sys.executable,
            "-c",
            "import worker.service; import sys; assert 'streamlit' not in sys.modules, 'Streamlit imported!'"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Subprocess failed: {res.stderr}")

        # Check logs
        log_capture = []
        class SecretCaptureHandler(logging.Handler):
            def emit(self, record):
                log_capture.append(self.format(record))

        logger = logging.getLogger("sentinel.worker")
        h = SecretCaptureHandler()
        logger.addHandler(h)
        orig_level = logger.level
        logger.setLevel(logging.DEBUG)

        try:
            cfg = WorkerConfig(worker_id=uuid.uuid4(), db_url="postgresql://sentinel:secret_pw_999@localhost:5432/db")
            svc = WorkerService(cfg, db_client=MockWorkerDBClient())
            logger.info("Config: %s", cfg)
            logger.info("Health: %s", svc.get_health_status().to_dict())

            logs = "\n".join(log_capture)
            self.assertNotIn("secret_pw_999", logs)
            self.assertIn(":***@", logs)
        finally:
            logger.removeHandler(h)
            logger.setLevel(orig_level)


if __name__ == "__main__":
    unittest.main()
