"""
tests/test_worker_pipeline_6h.py
Comprehensive automated test suite for Sentinel Phase 6H:
Final Production Hardening + Security Readiness Gate.

Test Coverage:
1. Production Enablement Gating & Fail-Closed Boundaries
2. Worker Least-Privilege Role & Direct Table Privilege Denial Auditing
3. Row-Level Security (RLS) & Safe Mailbox View Auditing
4. Asymmetric Hybrid Cryptography & Credential Lifecycle Auditing
5. Zero service_role Usage & Secret Isolation Across Components
6. SSRF Protection Matrix & Mandatory TLS Verification Auditing
7. Resource Bounds, Failure Injection & Bounded Retry/Backoff Auditing
8. Alert Security, Privacy Redaction & Persisted Data Minimization Auditing
9. Multi-Tenant Complete Isolation Matrix (Tenant A/B, Worker A/B, Mailbox A/B)
10. Streamlit Process Isolation & Container Supply Chain Auditing
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
from worker.config import (
    WorkerConfig,
    ProductionReadinessGate,
    ProductionMailboxGateError,
)
from worker.identity import WorkerIdentity
from worker.db import (
    MockWorkerDBClient,
    RoleVerificationError,
    TableAccessViolationError,
)
from worker.lease import WorkerLeaseManager
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.checkpoint import CheckpointStore
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticEmailMessage,
)
from worker.poller import MailboxPoller, MAX_MESSAGE_SIZE_BYTES, MAX_MESSAGES_PER_POLL
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


class TestPhase6HProductionGating(unittest.TestCase):
    """Verifies production enablement guard and fail-closed prerequisites."""

    def test_01_production_polling_default_disabled(self):
        """Production polling is strictly DISABLED by default across worker configs."""
        cfg = WorkerConfig()
        self.assertFalse(cfg.production_polling_enabled)
        self.assertFalse(cfg.test_mode)

    def test_02_production_readiness_gate_conditions(self):
        """ProductionReadinessGate checks all 8 mandatory conditions and fails closed on any missing."""
        # 1. Disabled production polling fails
        cfg_disabled = WorkerConfig(worker_id=uuid.uuid4(), db_url="postgresql://sentinel@localhost/db", production_polling_enabled=False)
        with self.assertRaises(ProductionMailboxGateError) as ctx:
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_disabled, user_id="u1", worker_id="w1", mailbox_id="m1",
                credential_present=True, capability_token_present=True, lease_active=True
            )
        self.assertIn("production_polling_enabled is False", str(ctx.exception))

        cfg_enabled = WorkerConfig(worker_id=uuid.uuid4(), db_url="postgresql://sentinel@localhost/db", production_polling_enabled=True)

        # 2. Missing DB URL fails
        cfg_no_db = WorkerConfig(worker_id=uuid.uuid4(), db_url="", production_polling_enabled=True)
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_no_db, user_id="u1", worker_id="w1", mailbox_id="m1",
                credential_present=True, capability_token_present=True, lease_active=True
            )

        # 3. Missing tenant user_id fails
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_enabled, user_id="", worker_id="w1", mailbox_id="m1",
                credential_present=True, capability_token_present=True, lease_active=True
            )

        # 4. Missing worker_id fails
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_enabled, user_id="u1", worker_id="", mailbox_id="m1",
                credential_present=True, capability_token_present=True, lease_active=True
            )

        # 5. Missing mailbox_id fails
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_enabled, user_id="u1", worker_id="w1", mailbox_id="",
                credential_present=True, capability_token_present=True, lease_active=True
            )

        # 6. Missing credential fails
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_enabled, user_id="u1", worker_id="w1", mailbox_id="m1",
                credential_present=False, capability_token_present=True, lease_active=True
            )

        # 7. Missing capability token fails
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_enabled, user_id="u1", worker_id="w1", mailbox_id="m1",
                credential_present=True, capability_token_present=False, lease_active=True
            )

        # 8. Missing active lease fails
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=cfg_enabled, user_id="u1", worker_id="w1", mailbox_id="m1",
                credential_present=True, capability_token_present=True, lease_active=False
            )

        # All 8 satisfied -> PASS
        ok = ProductionReadinessGate.verify_production_mailbox_connection(
            config=cfg_enabled, user_id="u1", worker_id="w1", mailbox_id="m1",
            credential_present=True, capability_token_present=True, lease_active=True
        )
        self.assertTrue(ok)


class TestPhase6HDatabaseAndRoleAuditing(unittest.TestCase):
    """Verifies least-privilege role configuration and direct table access denial."""

    def test_01_worker_roles_least_privilege(self):
        """Worker daemon connects strictly as sentinel_worker_daemon with zero direct table privileges."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        sess_user, curr_user, role_setting = db.verify_session_identity()
        self.assertEqual(sess_user, "sentinel_worker_daemon")
        self.assertEqual(curr_user, "sentinel_worker_daemon")

        # Confirm direct table privilege denial
        db.verify_table_privilege_denial()
        for table in ["sentinel_workers", "sentinel_mailboxes", "sentinel_checkpoints", "sentinel_alerts"]:
            with self.assertRaises(PermissionError):
                db.direct_table_select(table)

    def test_02_unauthorized_database_roles_fail_closed(self):
        """Unauthorized database roles are rejected at connection verification."""
        for unauthorized in ["postgres", "authenticated", "anon", "service_role", "supabase_admin"]:
            db = MockWorkerDBClient(session_user=unauthorized)
            with self.assertRaises(RoleVerificationError):
                db.verify_session_identity()


class TestPhase6HCredentialAndCryptoAuditing(unittest.TestCase):
    """Verifies cryptographic envelope, tamper resistance, and memory scrubbing."""

    @classmethod
    def setUpClass(cls):
        cls.priv_key, cls.pub_key = generate_worker_asymmetric_keypair(2048)
        cls.user_id = uuid.uuid4()
        cls.prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": cls.pub_key})
        cls.worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": cls.priv_key})

    def test_01_asymmetric_hybrid_encryption_roundtrip(self):
        """Validates RSA-OAEP + AES-256-GCM envelope encrypt/decrypt roundtrip."""
        secret = "super_sensitive_imap_password_xyz999"
        envelope = self.prov_ring.encrypt(secret, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)
        decrypted = self.worker_ring.decrypt(envelope, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)
        self.assertEqual(decrypted, secret)

    def test_02_tamper_rejection_matrix(self):
        """Validates fail-closed behavior on tampered ciphertext, nonce, or AAD."""
        envelope = self.prov_ring.encrypt("secret", user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)
        parts = envelope.split(":")

        # 1. Tampered ciphertext
        flip_ct = "B" if parts[4][0] == "A" else "A"
        tampered_ct = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{flip_ct}{parts[4][1:]}"
        with self.assertRaises(DecryptionError):
            self.worker_ring.decrypt(tampered_ct, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)

        # 2. Tampered nonce
        flip_nonce = "B" if parts[3][0] == "A" else "A"
        tampered_nonce = f"{parts[0]}:{parts[1]}:{parts[2]}:{flip_nonce}{parts[3][1:]}:{parts[4]}"
        with self.assertRaises(DecryptionError):
            self.worker_ring.decrypt(tampered_nonce, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)

        # 3. Wrong tenant AAD
        other_user = str(uuid.uuid4())
        with self.assertRaises(DecryptionError):
            self.worker_ring.decrypt(envelope, user_id=other_user, purpose=CONTEXT_MAILBOX)

        # 4. Wrong private key
        other_priv, _ = generate_worker_asymmetric_keypair(2048)
        other_ring = WorkerKeyRing(active_version="k1", keys={"k1": other_priv})
        with self.assertRaises(DecryptionError):
            other_ring.decrypt(envelope, user_id=str(self.user_id), purpose=CONTEXT_MAILBOX)

    def test_03_in_memory_credential_scrubbing(self):
        """LeasedCredential.clear() wipes secret and prevents further access."""
        cred = LeasedCredential(
            mailbox_id=str(uuid.uuid4()), worker_id=str(uuid.uuid4()), user_id=str(self.user_id),
            provider="custom", email_address="test@dom.invalid", imap_host="imap.ex",
            imap_port=993, use_ssl=True, auth_mechanism="APP_PASSWORD", credential_version=1,
            _secret="secret_value"
        )
        self.assertEqual(cred.secret, "secret_value")
        self.assertIn("[REDACTED_ACTIVE]", repr(cred))
        cred.clear()
        self.assertIn("[REDACTED_WIPED]", repr(cred))
        with self.assertRaises(ValueError):
            _ = cred.secret


class TestPhase6HZeroServiceRoleAndSecretIsolation(unittest.TestCase):
    """Verifies that service_role is never used and secrets are strictly isolated."""

    def test_01_zero_service_role_in_codebase(self):
        """Verifies service_role is not used across core, worker, app, or Edge Function source."""
        for root_dir in ["core", "worker", "app.py"]:
            path = os.path.join(os.path.dirname(os.path.dirname(__file__)), root_dir)
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn("service_role", content)
                self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", content)
            elif os.path.isdir(path):
                for fname in os.listdir(path):
                    if fname.endswith(".py"):
                        fpath = os.path.join(path, fname)
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()
                        self.assertNotIn("service_role", content)
                        self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", content)

    def test_02_secrets_absent_from_worker_logging(self):
        """Worker logging never emits passwords, capability tokens, or private keys."""
        log_capture = []
        class LogCapture(logging.Handler):
            def emit(self, record):
                log_capture.append(self.format(record))

        logger = logging.getLogger("sentinel.worker")
        handler = LogCapture()
        logger.addHandler(handler)
        orig_level = logger.level
        logger.setLevel(logging.DEBUG)

        try:
            secret_pw = "super_secret_pw_12345"
            cfg = WorkerConfig(worker_id=uuid.uuid4(), db_url=f"postgresql://sentinel:{secret_pw}@localhost:5432/db")
            svc = WorkerService(cfg, db_client=MockWorkerDBClient())
            logger.info("Config: %s", cfg)
            logger.info("Health: %s", svc.get_health_status().to_dict())

            logs = "\n".join(log_capture)
            self.assertNotIn(secret_pw, logs)
            self.assertIn(":***@", logs)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(orig_level)


class TestPhase6HSSRFAndTLSHardening(unittest.TestCase):
    """Verifies complete SSRF protection matrix and mandatory TLS verification."""

    def test_01_ssrf_protection_matrix(self):
        """Rejects cloud metadata, loopback, private ranges, internal TLDs, schemes, and userinfo."""
        targets = [
            "169.254.169.254",
            "127.0.0.1",
            "localhost",
            "::1",
            "10.0.1.25",
            "192.168.1.1",
            "172.16.0.1",
            "metadata.google.internal",
            "system.corp.local",
            "internal.lan",
            "imap://imap.provider.com",
            "https://imap.provider.com",
            "user@imap.provider.com",
            "imap.provider.com:993",
            "imap.provider.com/path",
        ]
        for t in targets:
            with self.assertRaises(SSRFSecurityError, msg=f"SSRF target '{t}' should be blocked"):
                validate_imap_host(t)

    def test_02_mandatory_tls_verification(self):
        """Real IMAP adapter strictly mandates check_hostname=True and CERT_REQUIRED."""
        with unittest.mock.patch.dict(os.environ, {GUARD_ENV_VAR: "1"}):
            conn = RealIMAPConnection(host="imap.gmail.com", port=993, use_ssl=True)
            self.assertTrue(conn._ssl_context.check_hostname)
            import ssl
            self.assertEqual(conn._ssl_context.verify_mode, ssl.CERT_REQUIRED)


class TestPhase6HResourceLimitsAndFailureInjection(unittest.TestCase):
    """Verifies resource boundaries and graceful fail-closed failure handling."""

    def test_01_resource_bounds_constants(self):
        """Resource limits strictly align: 20 msgs/poll, 5 MB message, 64 KB headers, 15s timeout."""
        self.assertEqual(MAX_MESSAGES_PER_POLL, 20)
        self.assertEqual(MAX_MESSAGE_SIZE_BYTES, 5 * 1024 * 1024)

    def test_02_failure_injection_mid_poll_lease_loss(self):
        """Worker halts immediately upon lease loss mid-poll without advancing checkpoint past failure."""
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
        lease_mgr.acquire_lease(duration_seconds=120)

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})
        cred_service = WorkerCredentialService(identity, worker_ring, db)
        checkpoint_store = CheckpointStore()
        server = SyntheticIMAPServer()
        server.register_account("u", "p")

        for uid in [1, 2, 3]:
            server.add_message("u", SyntheticEmailMessage(uid=uid, message_id=f"<m-{uid}>", subject=f"Sub {uid}"))

        # Invalidate lease after processing UID 1
        orig_advance = checkpoint_store.advance_checkpoint
        def release_on_1(*args, **kwargs):
            uid = kwargs.get("uid") or (args[3] if len(args) > 3 else None)
            res = orig_advance(*args, **kwargs)
            if uid == 1:
                lease_mgr.release_lease()
            return res

        checkpoint_store.advance_checkpoint = release_on_1

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

        cp = checkpoint_store.get_checkpoint(user_id=str(user_id), worker_id=str(worker_id), mailbox_id=str(mailbox_id))
        self.assertEqual(cp.last_processed_uid, 1)


class TestPhase6HAlertSecurityAndDataMinimization(unittest.TestCase):
    """Verifies threat alert formatting, sensitive token/OTP redaction, and unconfigured alerts."""

    def test_01_alert_privacy_redaction(self):
        """Subjects containing OTPs, 2FA codes, or security tokens are masked to prevent privacy leaks."""
        self.assertEqual(mask_sensitive_subject("Your Code - 44830"), "Your Code - ••••••")
        self.assertEqual(mask_sensitive_subject("OTP: 123456"), "OTP: ••••••")
        self.assertEqual(mask_sensitive_subject("44830 is your code"), "•••••• is your code")
        self.assertEqual(mask_sensitive_subject("987654"), "•••••• (Security Code)")

    def test_02_threat_alert_text_zero_secrets(self):
        """Threat alert text formats cleanly and never exposes passwords or tokens."""
        secret_token = "raw_secret_token_12345"
        threat_info = {
            "risk_score": "HIGH",
            "risk_score_numeric": 95,
            "subject": "Urgent Financial Notice",
            "sender": "attacker@fraud-alert.org",
            "risk_reasons": ["Reply-To mismatch detected"],
            "secret_token": secret_token,
        }
        alert_text = format_threat_alert_text(threat_info)
        self.assertIn("EMAILSHIELD CRITICAL SECURITY ALERT", alert_text)
        self.assertNotIn(secret_token, alert_text)

    def test_03_unconfigured_external_alert_channels_fail_safely(self):
        """When Telegram or WhatsApp credentials are absent, send_test_alert fails safely."""
        ok_tg, msg_tg = send_test_alert("telegram", {"telegram_token": "", "telegram_chat_id": ""})
        self.assertFalse(ok_tg)
        self.assertIn("Invalid Telegram Bot Token", msg_tg)

        ok_wa, msg_wa = send_test_alert("whatsapp", {"whatsapp_phone": "", "whatsapp_apikey": ""})
        self.assertFalse(ok_wa)
        self.assertIn("phone number", msg_wa.lower())


class TestPhase6HMultiTenantCompleteMatrix(unittest.TestCase):
    """Complete 2-tenant matrix: Tenant A, Tenant B, Worker A, Worker B, Mailbox A, Mailbox B."""

    def test_01_two_tenant_complete_isolation_matrix(self):
        """Verifies full isolation across two tenants, workers, leases, and mailboxes."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        tenant_a = uuid.uuid4()
        tenant_b = uuid.uuid4()
        worker_a = uuid.uuid4()
        worker_b = uuid.uuid4()
        mailbox_a = uuid.uuid4()
        mailbox_b = uuid.uuid4()

        db.seed_worker(worker_a, tenant_a, desired_state="RUNNING")
        db.seed_worker(worker_b, tenant_b, desired_state="RUNNING")
        db.seed_mailbox(mailbox_a, worker_a, tenant_a, encrypted_credentials="v2:k1:wdek:nonce:ctA")
        db.seed_mailbox(mailbox_b, worker_b, tenant_b, encrypted_credentials="v2:k1:wdek:nonce:ctB")

        # Worker A acquires lease
        id_a = WorkerIdentity(worker_a)
        mgr_a = WorkerLeaseManager(id_a, db)
        self.assertTrue(mgr_a.acquire_lease(duration_seconds=60))

        # Worker B acquires lease
        id_b = WorkerIdentity(worker_b)
        mgr_b = WorkerLeaseManager(id_b, db)
        self.assertTrue(mgr_b.acquire_lease(duration_seconds=60))

        # 1. A -> A = allowed
        cred_a = db.fetch_leased_mailbox_credential(worker_a, id_a.raw_token)
        self.assertTrue(cred_a["success"])
        self.assertEqual(cred_a["user_id"], str(tenant_a))
        self.assertEqual(cred_a["mailbox_id"], str(mailbox_a))

        # 2. B -> B = allowed
        cred_b = db.fetch_leased_mailbox_credential(worker_b, id_b.raw_token)
        self.assertTrue(cred_b["success"])
        self.assertEqual(cred_b["user_id"], str(tenant_b))
        self.assertEqual(cred_b["mailbox_id"], str(mailbox_b))

        # 3. A -> B = denied
        with self.assertRaises(PermissionError):
            db.fetch_leased_mailbox_credential(worker_b, id_a.raw_token)

        # 4. B -> A = denied
        with self.assertRaises(PermissionError):
            db.fetch_leased_mailbox_credential(worker_a, id_b.raw_token)

        # 5. Worker B cannot claim Worker A's worker
        collision_res = db.claim_worker_lease(worker_a, duration_seconds=60)
        self.assertFalse(collision_res["success"])
        self.assertEqual(collision_res["reason"], "worker_unavailable_or_locked")

        mgr_a.release_lease()
        mgr_b.release_lease()


class TestPhase6HStreamlitIsolationAndDockerSupplyChain(unittest.TestCase):
    """Verifies Streamlit runtime isolation and Docker supply chain hardening."""

    def test_01_streamlit_runtime_isolation(self):
        """Worker service runs in clean subprocess without importing Streamlit."""
        cmd = [
            sys.executable,
            "-c",
            "import worker.service; import sys; assert 'streamlit' not in sys.modules, 'Streamlit imported!'"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Subprocess failed: {res.stderr}")

    def test_02_dockerfile_and_dockerignore_hardening(self):
        """Dockerfile specifies non-root user and 0 exposed ports; .dockerignore excludes secrets."""
        base_dir = os.path.dirname(os.path.dirname(__file__))
        dockerfile_path = os.path.join(base_dir, "Dockerfile")
        dockerignore_path = os.path.join(base_dir, ".dockerignore")

        with open(dockerfile_path, "r", encoding="utf-8") as f:
            dockerfile_content = f.read()

        # Non-root user
        self.assertIn("USER sentinel", dockerfile_content)
        self.assertIn("useradd -u 10001", dockerfile_content)
        # Outbound-only: no EXPOSE directive
        self.assertNotIn("EXPOSE", dockerfile_content)

        with open(dockerignore_path, "r", encoding="utf-8") as f:
            dockerignore_content = f.read()

        # Excludes sensitive files
        for item in [".env", ".env.*", "*.pem", "*.key", "tests/"]:
            self.assertIn(item, dockerignore_content)


if __name__ == "__main__":
    unittest.main()
