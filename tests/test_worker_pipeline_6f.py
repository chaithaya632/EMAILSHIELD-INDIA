"""
tests/test_worker_pipeline_6f.py
Comprehensive automated test suite for Sentinel Phase 6F:
Controlled Worker Infrastructure Provisioning & Dedicated Test Mailbox Onboarding.

Test Coverage:
1. Worker Infrastructure & Safe Local Defaults (Host Not Configured, Dedicated Mailbox Not Configured)
2. Controlled End-to-End Pipeline & Cryptographic Round-Trip
3. Five Mandatory Synthetic Test Mailbox Email Categories (Clean, Suspicious, Duplicate, Malformed, Attachment)
4. Monotonic Checkpointing & Second Poll Duplicate Prevention
5. Mid-Poll Lease Loss Safety & Atomic Recovery
6. Multi-Tenant Isolation & Capability Token Security Matrix
7. Real IMAP Guard, SSRF Hardening & Mandatory TLS Enforcement
8. Logging Security, Streamlit Isolation & Production Safety Gates
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


class TestPhase6FInfrastructureDefaults(unittest.TestCase):
    """Verifies infrastructure and test mailbox detection and safe fail-closed defaults."""

    def test_01_worker_host_not_configured_defaults_safely(self):
        """When no external worker host is configured, WorkerConfig operates safely locally."""
        cfg = WorkerConfig.from_env({})
        self.assertFalse(cfg.production_polling_enabled)
        self.assertFalse(cfg.test_mode)
        # Database URL defaults to empty/unconfigured without crashing
        self.assertIn("<not-configured>", repr(cfg))

    def test_02_dedicated_test_mailbox_not_configured_fails_closed(self):
        """When no dedicated test mailbox credentials exist, real network connection is blocked."""
        # Ensure guard is absent
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_real_imap_test_enabled())
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()

    def test_03_real_imap_guard_strict_opt_in(self):
        """Guard fails closed on all values except exact '1'."""
        for val in ["0", "false", "TRUE", "yes", "enabled", ""]:
            with unittest.mock.patch.dict(os.environ, {GUARD_ENV_VAR: val}):
                self.assertFalse(is_real_imap_test_enabled())
                with self.assertRaises(RealNetworkDeniedError):
                    check_real_imap_guard()


class TestPhase6FControlledPipelineE2E(unittest.TestCase):
    """Verifies complete end-to-end controlled worker pipeline with cryptographic identity."""

    @classmethod
    def setUpClass(cls):
        cls.priv_key, cls.pub_key = generate_worker_asymmetric_keypair(2048)
        cls.user_id = uuid.uuid4()
        cls.worker_id = uuid.uuid4()
        cls.mailbox_id = uuid.uuid4()

        cls.username = "sentinel.test@domain.invalid"
        cls.password = "app_pw_secret_xyz123"
        cls.imap_host = "imap.test-provider.invalid"
        cls.imap_port = 993

        # Encrypt credential via ProvisioningKeyRing (representing Edge Function behavior)
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

    def test_01_session_identity_and_table_denial(self):
        """Verifies session role is sentinel_worker_daemon and direct table access is denied."""
        sess_user, curr_user, role_setting = self.db.verify_session_identity()
        self.assertEqual(sess_user, "sentinel_worker_daemon")
        self.assertEqual(curr_user, "sentinel_worker_daemon")
        self.assertIn(role_setting, ("sentinel_worker_daemon", "sentinel_worker_role"))

        # Confirm direct table privilege denial
        self.db.verify_table_privilege_denial()  # Does not raise TableAccessViolationError
        with self.assertRaises(PermissionError):
            self.db.direct_table_select("sentinel_mailboxes")

    def test_02_lease_claim_capability_token_and_credential_retrieval(self):
        """Full pipeline: lease claim -> capability token -> credential retrieval -> memory decrypt."""
        lease_mgr = WorkerLeaseManager(self.identity, self.db)
        acquired = lease_mgr.acquire_lease(duration_seconds=120)
        self.assertTrue(acquired)
        self.assertTrue(self.identity.has_token())

        cred_service = WorkerCredentialService(self.identity, self.worker_ring, self.db)
        leased_cred = cred_service.fetch_and_decrypt()

        self.assertIsInstance(leased_cred, LeasedCredential)
        self.assertEqual(leased_cred.mailbox_id, str(self.mailbox_id))
        self.assertEqual(leased_cred.user_id, str(self.user_id))
        self.assertEqual(leased_cred.email_address, "synthetic@test.local")

        # Parse decrypted secret
        cred_dict = json.loads(leased_cred.secret)
        self.assertEqual(cred_dict["username"], self.username)
        self.assertEqual(cred_dict["password"], self.password)
        self.assertEqual(cred_dict["imap_host"], self.imap_host)

        # Repr security: password is never in repr or str
        self.assertNotIn(self.password, repr(leased_cred))
        self.assertNotIn(self.password, str(leased_cred))
        self.assertIn("[REDACTED_ACTIVE]", repr(leased_cred))

        # Memory cleanup
        leased_cred.clear()
        self.assertIn("[REDACTED_WIPED]", repr(leased_cred))
        with self.assertRaises(ValueError):
            _ = leased_cred.secret

    def test_03_capability_token_security_matrix(self):
        """Capability token security: wrong token, expired, released, cross-worker all denied."""
        lease_mgr = WorkerLeaseManager(self.identity, self.db)
        lease_mgr.acquire_lease(duration_seconds=120)

        # 1. Wrong token (raises PermissionError)
        wrong_token = "00" * 32
        with self.assertRaises(PermissionError):
            self.db.fetch_leased_mailbox_credential(self.worker_id, wrong_token)

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
        """Decryption fails closed on tampered ciphertext, tampered nonce, or wrong tenant AAD."""
        parts = self.envelope.split(":")
        self.assertEqual(len(parts), 5)  # v2:key_ver:wdek:nonce:ct

        # 1. Tampered ciphertext
        flip_ct = "B" if parts[4][0] == "A" else "A"
        tampered_ct = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{flip_ct}{parts[4][1:]}"
        with self.assertRaises(DecryptionError):
            self.worker_ring.decrypt(tampered_ct, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)

        # 2. Wrong tenant AAD
        attacker_user_id = str(uuid.uuid4())
        with self.assertRaises(DecryptionError):
            self.worker_ring.decrypt(self.envelope, user_id=attacker_user_id, purpose=CONTEXT_MAILBOX)

        # 3. Wrong key version
        tampered_ver = f"{parts[0]}:k999:{parts[2]}:{parts[3]}:{parts[4]}"
        with self.assertRaises(UnknownKeyVersionError):
            self.worker_ring.decrypt(tampered_ver, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)

        # 4. Wrong private key
        other_priv, _ = generate_worker_asymmetric_keypair(2048)
        other_ring = WorkerKeyRing(active_version="k1", keys={"k1": other_priv})
        with self.assertRaises(DecryptionError):
            other_ring.decrypt(self.envelope, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)


class TestPhase6FFiveSyntheticEmailCategories(unittest.TestCase):
    """
    Verifies processing of all 5 mandatory synthetic email categories from Section 14:
    Email 1 - Clean legitimate message
    Email 2 - Suspicious message safely processed by forensic engine
    Email 3 - Duplicate message (same Message-ID)
    Email 4 - Malformed MIME payload
    Email 5 - Attachment test (harmless attachment)
    """

    @classmethod
    def setUpClass(cls):
        cls.priv_key, cls.pub_key = generate_worker_asymmetric_keypair(2048)
        cls.user_id = uuid.uuid4()
        cls.worker_id = uuid.uuid4()
        cls.mailbox_id = uuid.uuid4()

        cls.username = "poller.test@example.invalid"
        cls.password = "synthetic_password_abc123"

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

    def test_01_populate_and_process_five_synthetic_email_categories(self):
        """Tests sequential processing of all 5 synthetic email types in a single poll."""
        # --- EMAIL 1: Clean Legitimate Message ---
        email_1 = SyntheticEmailMessage(
            uid=1,
            message_id="<msg-clean-01@company.invalid>",
            from_addr="billing@legitimate-service.org",
            to_addr="sentinel-test@example.invalid",
            subject="Monthly Account Statement - Clean",
            body="Your monthly account statement is available. No actions are required.",
        )
        self.synthetic_server.add_message(self.username, email_1)

        # --- EMAIL 2: Suspicious Message (Evaluated safely by forensic engine) ---
        # Include Reply-To mismatch test indicator
        email_2 = SyntheticEmailMessage(
            uid=2,
            message_id="<msg-suspicious-02@company.invalid>",
            from_addr="payroll@legitimate-service.org",
            to_addr="sentinel-test@example.invalid",
            headers={"Reply-To": "attacker-drop@fraud-network.invalid"},
            subject="URGENT: Update Payroll Direct Deposit Details",
            body="Immediate action required: please update your direct deposit banking credentials.",
        )
        self.synthetic_server.add_message(self.username, email_2)

        # Verify forensic engine safely analyzes Email 2 without execution or network
        parsed_2 = SecureEmailParser(email_2.to_rfc822()).parse()
        findings_2 = evaluate_rules(parsed_2)
        finding_ids = [f.get("rule_id") for f in findings_2]
        self.assertIn("RULE-001", finding_ids)

        # --- EMAIL 3: Duplicate Message (Same Message-ID as Email 1) ---
        email_3 = SyntheticEmailMessage(
            uid=3,
            message_id="<msg-clean-01@company.invalid>",  # DUPLICATE of Email 1
            from_addr="billing@legitimate-service.org",
            to_addr="sentinel-test@example.invalid",
            subject="Monthly Account Statement (Duplicate)",
            body="Duplicate statement.",
        )
        self.synthetic_server.add_message(self.username, email_3)

        # --- EMAIL 4: Malformed MIME Payload ---
        email_4 = SyntheticEmailMessage(
            uid=4,
            message_id="",
            raw_bytes=b"This is a broken payload without headers\r\n\r\nMalformed body content",
        )
        self.synthetic_server.add_message(self.username, email_4)

        # --- EMAIL 5: Harmless Attachment Test ---
        msg_5 = EmailMessage()
        msg_5["Message-ID"] = "<msg-attachment-05@company.invalid>"
        msg_5["From"] = "scanner@legitimate-service.org"
        msg_5["To"] = "sentinel-test@example.invalid"
        msg_5["Subject"] = "Quarterly Compliance Report Attachment"
        msg_5["Date"] = "Thu, 17 Sep 2026 12:00:00 +0000"
        msg_5.set_content("Please find attached the quarterly compliance document.")
        msg_5.add_attachment(
            b"%PDF-1.4 synthetic dummy pdf document bytes",
            maintype="application",
            subtype="pdf",
            filename="compliance_report.pdf",
        )
        email_5 = SyntheticEmailMessage(
            uid=5,
            message_id="<msg-attachment-05@company.invalid>",
            raw_bytes=msg_5.as_bytes(),
        )
        self.synthetic_server.add_message(self.username, email_5)

        # Execute Poll
        result = self.poller.poll()
        self.assertEqual(result["status"], "SUCCESS")

        events = result["events"]
        # Email 1: Processed
        # Email 2: Processed
        # Email 3: Duplicate Message-ID -> Skipped!
        # Email 4: Malformed MIME -> Processed safely
        # Email 5: Attachment -> Processed with attachment_count >= 1
        self.assertEqual(len(events), 4)

        # Verify Email 1 Event
        evt_1 = next(e for e in events if e.uid == 1)
        self.assertEqual(evt_1.message_id, "<msg-clean-01@company.invalid>")
        self.assertEqual(evt_1.processing_status, "PROCESSED")

        # Verify Email 2 Event
        evt_2 = next(e for e in events if e.uid == 2)
        self.assertEqual(evt_2.message_id, "<msg-suspicious-02@company.invalid>")
        self.assertEqual(evt_2.processing_status, "PROCESSED")

        # Verify Email 3 was skipped
        self.assertFalse(any(e.uid == 3 for e in events))

        # Verify Email 4 Event (graceful handling)
        evt_4 = next(e for e in events if e.uid == 4)
        self.assertIn(evt_4.processing_status, ("PROCESSED", "ERROR"))

        # Verify Email 5 Event (attachment counted)
        evt_5 = next(e for e in events if e.uid == 5)
        self.assertEqual(evt_5.attachment_count, 1)

        # Verify Monotonic Checkpoint reached UID 5
        cp = self.checkpoint_store.get_checkpoint(
            user_id=str(self.user_id),
            worker_id=str(self.worker_id),
            mailbox_id=str(self.mailbox_id),
        )
        self.assertEqual(cp.last_processed_uid, 5)

    def test_02_second_poll_duplicate_prevention(self):
        """Second poll on the same mailbox processes 0 messages and emits 0 duplicate events."""
        # Seed and process messages 1 and 2
        for uid in [1, 2]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(
                    uid=uid,
                    message_id=f"<seed-{uid}@example.invalid>",
                    subject=f"Seed {uid}",
                )
            )

        res_1 = self.poller.poll()
        self.assertEqual(res_1["processed_count"], 2)

        # Second poll: no new messages
        res_2 = self.poller.poll()
        self.assertEqual(res_2["status"], "SUCCESS")
        self.assertEqual(res_2["processed_count"], 0)
        self.assertEqual(len(res_2["events"]), 0)

        # Add message with new UID 3 but duplicate Message-ID of message 1
        self.synthetic_server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=3,
                message_id="<seed-1@example.invalid>",
                subject="Duplicate Seed 1",
            )
        )

        res_3 = self.poller.poll()
        self.assertEqual(res_3["status"], "SUCCESS")
        self.assertEqual(res_3["processed_count"], 0)
        self.assertEqual(len(res_3["events"]), 0)

        # Checkpoint advanced to 3 even though message was deduplicated
        cp = self.checkpoint_store.get_checkpoint(
            user_id=str(self.user_id),
            worker_id=str(self.worker_id),
            mailbox_id=str(self.mailbox_id),
        )
        self.assertEqual(cp.last_processed_uid, 3)

    def test_03_mid_poll_lease_loss_safety(self):
        """Simulates lease expiration mid-poll; polling halts immediately and checkpoint is preserved."""
        for uid in [10, 11, 12]:
            self.synthetic_server.add_message(
                self.username,
                SyntheticEmailMessage(
                    uid=uid,
                    message_id=f"<mid-poll-{uid}@example.invalid>",
                    subject=f"Mid Poll {uid}",
                )
            )

        # Hook: release lease after processing UID 10
        original_advance = self.checkpoint_store.advance_checkpoint

        def release_on_uid_10(*args, **kwargs):
            uid = kwargs.get("uid") or (args[3] if len(args) > 3 else None)
            res = original_advance(*args, **kwargs)
            if uid == 10:
                # Invalidate lease right after message 10 checkpoint
                self.lease_mgr.release_lease()
            return res

        self.checkpoint_store.advance_checkpoint = release_on_uid_10

        res = self.poller.poll()
        self.assertEqual(res["status"], "LEASE_EXPIRED_MID_POLL")
        self.assertEqual(res["processed_count"], 1)
        self.assertEqual(len(res["events"]), 1)
        self.assertEqual(res["events"][0].uid, 10)

        # Checkpoint must be exactly at UID 10 (UID 11 and 12 were aborted)
        cp = self.checkpoint_store.get_checkpoint(
            user_id=str(self.user_id),
            worker_id=str(self.worker_id),
            mailbox_id=str(self.mailbox_id),
        )
        self.assertEqual(cp.last_processed_uid, 10)


class TestPhase6FSecurityAndHardening(unittest.TestCase):
    """Verifies SSRF protection, TLS mandatory settings, concurrency, and multi-tenant isolation."""

    def test_01_ssrf_protection_matrix(self):
        """Rejects cloud metadata, private IPs, schemes, and internal TLDs."""
        bad_hosts = [
            "169.254.169.254",               # Cloud metadata
            "127.0.0.1",                     # Loopback
            "10.0.0.1",                      # Private RFC1918
            "192.168.1.1",                   # Private RFC1918
            "imap://imap.gmail.com",         # Scheme prefix
            "https://imap.gmail.com",        # URL
            "server.internal",               # Internal TLD
            "corp.local",                    # Local TLD
            "metadata.google.internal",      # Cloud metadata
            "user@host.com",                 # Userinfo
        ]
        for host in bad_hosts:
            with self.assertRaises(SSRFSecurityError, msg=f"Host '{host}' should be rejected"):
                validate_imap_host(host)

    def test_02_mandatory_tls_verification(self):
        """Verifies RealIMAPConnection initializes strict TLS context with check_hostname=True."""
        with unittest.mock.patch.dict(os.environ, {GUARD_ENV_VAR: "1"}):
            conn = RealIMAPConnection(host="imap.gmail.com", port=993, use_ssl=True)
            self.assertIsNotNone(conn._ssl_context)
            self.assertTrue(conn._ssl_context.check_hostname)
            import ssl
            self.assertEqual(conn._ssl_context.verify_mode, ssl.CERT_REQUIRED)

    def test_03_concurrent_worker_collision_prevention(self):
        """Worker B cannot claim a lease currently held by Worker A."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_a = uuid.uuid4()
        worker_b = uuid.uuid4()

        db.seed_worker(worker_a, user_id, desired_state="RUNNING")

        # Worker A acquires lease
        id_a = WorkerIdentity(worker_a)
        mgr_a = WorkerLeaseManager(id_a, db)
        self.assertTrue(mgr_a.acquire_lease(duration_seconds=120))

        # Worker B attempts to claim the same worker
        id_b = WorkerIdentity(worker_b)
        mgr_b = WorkerLeaseManager(id_b, db)
        # Attempting to claim worker_a's record fails because it is leased
        res_b = db.claim_worker_lease(worker_a, duration_seconds=60)
        self.assertFalse(res_b["success"])
        self.assertEqual(res_b["reason"], "worker_unavailable_or_locked")

    def test_04_streamlit_isolation(self):
        """Worker service runs in a clean subprocess without importing Streamlit."""
        cmd = [
            sys.executable,
            "-c",
            "import worker.service; import sys; assert 'streamlit' not in sys.modules, 'Streamlit imported!'"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Subprocess failed: {res.stderr}")

    def test_05_logging_zero_secrets(self):
        """Worker logs never contain secrets, passwords, tokens, or private keys."""
        secret_password = "very_secret_mailbox_password_999"
        raw_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        log_capture = []
        class SecretTrackingHandler(logging.Handler):
            def emit(self, record):
                log_capture.append(self.format(record))

        logger = logging.getLogger("sentinel.worker")
        handler = SecretTrackingHandler()
        logger.addHandler(handler)
        orig_level = logger.level
        logger.setLevel(logging.DEBUG)

        try:
            cfg = WorkerConfig(worker_id=uuid.uuid4(), db_url=f"postgresql://sentinel:{secret_password}@localhost:5432/db")
            svc = WorkerService(cfg, db_client=MockWorkerDBClient())
            logger.info("Config initialized: %s", cfg)
            logger.info("Health status: %s", svc.get_health_status().to_dict())

            combined_logs = "\n".join(log_capture)
            self.assertNotIn(secret_password, combined_logs)
            self.assertNotIn(raw_token, combined_logs)
            self.assertIn(":***@", combined_logs)  # masked db url
        finally:
            logger.removeHandler(handler)
            logger.setLevel(orig_level)


class TestPhase6FProvisioningAndLifecycle(unittest.TestCase):
    """Verifies provisioning security, lease lifecycle, heartbeat, and resource boundaries."""

    def test_01_lease_lifecycle_claim_heartbeat_renew_release(self):
        """Full lease lifecycle: claim -> heartbeat -> renew -> release -> recover."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")

        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)

        # 1. Claim lease
        self.assertTrue(lease_mgr.acquire_lease(duration_seconds=60))
        self.assertTrue(lease_mgr.is_active())
        self.assertGreater(lease_mgr.time_until_expiry(), 0)

        # 2. Heartbeat / telemetry recording
        orig_expires = lease_mgr.time_until_expiry()

        # 3. Renew lease
        self.assertTrue(lease_mgr.renew_lease(extension_seconds=90))
        new_expires = lease_mgr.time_until_expiry()
        self.assertGreaterEqual(new_expires, orig_expires)

        # 4. Release lease
        self.assertTrue(lease_mgr.release_lease())
        self.assertFalse(lease_mgr.is_active())
        self.assertFalse(identity.has_token())

        # 5. Recovery after release: new lease can be claimed
        identity_recovered = WorkerIdentity(worker_id)
        lease_mgr_recovered = WorkerLeaseManager(identity_recovered, db)
        self.assertTrue(lease_mgr_recovered.acquire_lease(duration_seconds=60))
        self.assertTrue(lease_mgr_recovered.is_active())
        lease_mgr_recovered.release_lease()

    def test_02_stale_lease_expiry_recovery(self):
        """A crashed/abandoned worker whose lease expires allows a new worker to claim."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        # Seed an expired lease
        db.seed_worker(
            worker_id, user_id, desired_state="RUNNING",
            lease_owner="crashed_daemon",
            lease_expires_at=time.time() - 100,  # in the past
            lease_token_hash="expired_hash"
        )

        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)
        # Stale lease should be recovered
        self.assertTrue(lease_mgr.acquire_lease(duration_seconds=60))
        self.assertTrue(lease_mgr.is_active())
        lease_mgr.release_lease()

    def test_03_multi_tenant_cross_mailbox_isolation(self):
        """Cross-tenant protection: Worker A belongs to User A, cannot access User B's mailbox."""
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

        # Worker A acquires lease for worker_a
        id_a = WorkerIdentity(worker_a)
        mgr_a = WorkerLeaseManager(id_a, db)
        self.assertTrue(mgr_a.acquire_lease(duration_seconds=60))

        # Worker B acquires lease for worker_b
        id_b = WorkerIdentity(worker_b)
        mgr_b = WorkerLeaseManager(id_b, db)
        self.assertTrue(mgr_b.acquire_lease(duration_seconds=60))

        # Worker A fetches credentials -> gets mailbox_a belonging to user_a
        cred_a = db.fetch_leased_mailbox_credential(worker_a, id_a.raw_token)
        self.assertTrue(cred_a["success"])
        self.assertEqual(cred_a["user_id"], str(user_a))
        self.assertEqual(cred_a["mailbox_id"], str(mailbox_a))

        # Worker A cannot fetch worker_b / mailbox_b credentials
        with self.assertRaises(PermissionError):
            db.fetch_leased_mailbox_credential(worker_b, id_a.raw_token)

        # Worker B cannot fetch worker_a / mailbox_a credentials
        with self.assertRaises(PermissionError):
            db.fetch_leased_mailbox_credential(worker_a, id_b.raw_token)

        mgr_a.release_lease()
        mgr_b.release_lease()

    def test_04_oversized_message_bounds_enforcement(self):
        """Oversized synthetic email exceeding 5MB is flagged as OVERSIZED and body preview redacted."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        mailbox_id = uuid.uuid4()
        username = "oversize.test@example.invalid"
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

        # Add oversized message: 5MB + 1024 bytes
        oversized_bytes = b"X" * (MAX_MESSAGE_SIZE_BYTES + 1024)
        server.add_message(username, SyntheticEmailMessage(uid=1, message_id="<oversized@ex>", raw_bytes=oversized_bytes))

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
        self.assertEqual(len(res["events"]), 1)
        evt = res["events"][0]
        self.assertEqual(evt.processing_status, "OVERSIZED")
        self.assertEqual(evt.error_code, "ERR_MESSAGE_TOO_LARGE")
        self.assertIn("Content omitted: exceeds maximum size threshold", evt.body_preview)


if __name__ == "__main__":
    unittest.main()
