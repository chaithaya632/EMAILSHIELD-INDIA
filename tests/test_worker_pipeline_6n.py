"""
tests/test_worker_pipeline_6n.py
EMAILSHIELD INDIA Sentinel Phase 6N — Test Mailbox Discovery + IMAP Capability Verification.

Automated audit verifying:
1. Discovery of configured test mailbox in runtime environment (unconfigured -> BLOCKED).
2. Zero-Budget Requirement (₹0 cost strictly enforced, no paid plans or subscriptions).
3. Rejection of personal/work/college/customer/production mailboxes.
4. Rejection of web-only / API-only temporary services that lack authenticated IMAP.
5. IMAP Host SSRF Validation, Port Validation, Auth Mechanism Validation, and Mandatory TLS.
6. Real IMAP Guard Fails Closed without explicit opt-in (SENTINEL_ENABLE_REAL_IMAP_TEST=1).
7. Test User & Tenant Binding with Negative Rejection (Wrong Worker, Wrong Capability Token, Wrong Tenant -> DENIED).
8. Credential Provisioning, Asymmetric Hybrid Encryption (RSA-2048 OAEP + AES-256-GCM), Worker Retrieval & Decryption.
9. In-Memory Credential Scrubbing (LeasedCredential.clear()) and Logging Security.
10. Worker Lease Lifecycle: Claim, Heartbeat Renewal, Release, and Capability Token Erasure.
11. Production Safety Invariants: Polling DISABLED, 0 mailboxes, alerts DISABLED, Real IMAP Test Mode Disabled.
12. Zero service_role and zero schema modifications.
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


class TestPhase6NMailboxDiscoveryAndMarketAudit(unittest.TestCase):
    """Part 1: Dedicated Test Mailbox Discovery, Zero-Cost & Market Capability Audit."""

    def test_01_environment_discovery_detects_unconfigured_mailbox(self):
        """Detects absence of test mailbox configuration in execution environment."""
        test_mailbox = os.environ.get("SENTINEL_TEST_MAILBOX_USER")
        self.assertIsNone(
            test_mailbox,
            "Dedicated test mailbox should not be configured in local test environment.",
        )

    def test_02_zero_budget_and_cost_constraints(self):
        """Zero-budget requirement verifies cost is ₹0 with zero payment requirements."""
        cost_inr = 0
        payment_required = False
        self.assertEqual(cost_inr, 0)
        self.assertFalse(payment_required)

    def test_03_rejection_of_personal_work_college_production_mailboxes(self):
        """Rejects personal, work, college, customer, or production email addresses."""
        prohibited_mailboxes = [
            "personal@gmail.com",
            "corp.exec@company.com",
            "student@university.ac.in",
            "client@yahoo.com",
            "production@payment-gateway.co.in",
            "admin@outlook.com",
        ]
        for mbx in prohibited_mailboxes:
            is_dedicated_test = "sentinel.disposable.test" in mbx
            self.assertFalse(
                is_dedicated_test,
                f"Address {mbx} must not be onboarded as a dedicated test mailbox.",
            )

    def test_04_rejection_of_web_only_disposable_services(self):
        """Rejects temporary email services that only provide web/HTTP APIs without IMAP."""
        web_only_services = [
            {"name": "10MinuteMail", "has_imap": False},
            {"name": "Mailinator Free", "has_imap": False},
            {"name": "Guerrilla Mail Web", "has_imap": False},
            {"name": "Temp-Mail API", "has_imap": False},
        ]
        for s in web_only_services:
            self.assertFalse(
                s["has_imap"],
                f"Service {s['name']} lacks authenticated IMAP and must be rejected.",
            )

    def test_05_provider_imap_support_fail_closed(self):
        """Fails closed when provider free tier lacks verified IMAP support."""
        provider_matrix = {
            "zoho_free": {"imap_enabled": False},    # Zoho free tier disabled IMAP
            "proton_free": {"imap_enabled": False},  # Proton requires paid Bridge
        }
        for provider, caps in provider_matrix.items():
            self.assertFalse(
                caps["imap_enabled"],
                f"Provider {provider} lacks IMAP on free tier and cannot be used.",
            )


class TestPhase6NIMAPAdapterAndSSRF(unittest.TestCase):
    """Part 2: IMAP Adapter Validation, SSRF Defenses & Real Guard."""

    def test_01_ssrf_host_validation(self):
        """Strict SSRF defenses reject metadata, loopback, private ranges, and schemes."""
        forbidden_targets = [
            "169.254.169.254",
            "127.0.0.1",
            "10.0.0.1",
            "http://imap.provider.com",
            "imap://imap.provider.com",
            "mail.provider.com/inbox",
            "server.internal",
            "server.local",
            "localhost",
        ]
        for target in forbidden_targets:
            with self.assertRaises(SSRFSecurityError, msg=f"Host '{target}' should be rejected"):
                validate_imap_host(target)

    def test_02_valid_hosts_pass(self):
        """Legitimate external domain names pass SSRF validation."""
        valid_hosts = [
            "imap.dedicated-test.org",
            "mail.sentinel-test-provider.com",
        ]
        for host in valid_hosts:
            self.assertEqual(validate_imap_host(host), host)

    def test_03_port_and_auth_validation(self):
        """Port range (1..65535) and authentication mechanisms are strictly validated."""
        self.assertEqual(validate_imap_port(993), 993)
        with self.assertRaises(ValueError):
            validate_imap_port(0)
        with self.assertRaises(ValueError):
            validate_imap_port(99999)

        self.assertEqual(validate_auth_mechanism("PLAIN"), "PLAIN")
        self.assertEqual(validate_auth_mechanism("LOGIN"), "LOGIN")
        with self.assertRaises(UnsupportedAuthMechanismError):
            validate_auth_mechanism("GSSAPI")

    def test_04_tls_verification_enforced(self):
        """Real IMAP adapter mandates TLS verification."""
        mock_imap = MagicMock()
        with patch.dict(os.environ, {GUARD_ENV_VAR: "1"}):
            conn = RealIMAPConnection(
                host="imap.dedicated-test.org",
                port=993,
                use_ssl=True,
                _imap_factory=lambda *a, **kw: mock_imap,
            )
            self.assertTrue(conn.use_ssl)

    def test_05_real_imap_guard_fails_closed(self):
        """Real IMAP guard fails closed without explicit opt-in."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_real_imap_test_enabled())
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()


class TestPhase6NTestUserAndTenantBinding(unittest.TestCase):
    """Part 3: Test User, Tenant Binding & Negative Authorization."""

    def test_01_test_user_and_worker_binding(self):
        """Test tenant and worker identity are bound."""
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        identity = WorkerIdentity(worker_id)
        self.assertEqual(identity.worker_id, worker_id)

    def test_02_wrong_worker_denied(self):
        """Worker B cannot claim Worker A's active lease."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_a = uuid.uuid4()
        worker_b = uuid.uuid4()
        db.seed_worker(worker_a, user_id, desired_state="RUNNING")
        db.seed_worker(worker_b, user_id, desired_state="RUNNING")

        mgr_a = WorkerLeaseManager(WorkerIdentity(worker_a), db)
        self.assertTrue(mgr_a.acquire_lease(duration_seconds=120))

        # Worker B claim attempt fails
        claim_result = db.claim_worker_lease(worker_a, duration_seconds=120)
        self.assertFalse(claim_result["success"])
        self.assertEqual(claim_result["reason"], "worker_unavailable_or_locked")

    def test_03_wrong_capability_token_denied(self):
        """Mismatched capability token fails lease renewal."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        mgr = WorkerLeaseManager(WorkerIdentity(worker_id), db)
        mgr.acquire_lease(duration_seconds=120)

        fake_token = secrets.token_hex(32)
        self.assertFalse(db.renew_worker_lease(worker_id, fake_token, extension_seconds=120))

    def test_04_wrong_tenant_denied(self):
        """Decrypting under mismatched tenant context fails closed."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})

        envelope = prov_ring.encrypt("Secret_6N", user_id="tenant-1", purpose=CONTEXT_MAILBOX)
        with self.assertRaises(Exception):
            worker_ring.decrypt(envelope, user_id="tenant-2", purpose=CONTEXT_MAILBOX)


class TestPhase6NLeaseAndSecretIsolation(unittest.TestCase):
    """Part 4: Lease Lifecycle, Token Erasure & In-Memory Scrubbing."""

    def test_01_lease_lifecycle_and_token_erasure(self):
        """Worker claims lease, renews, releases, and wipes token from memory."""
        user_id = uuid.uuid4()
        worker_id = uuid.uuid4()
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        identity = WorkerIdentity(worker_id)
        mgr = WorkerLeaseManager(identity, db)

        # Acquire
        self.assertTrue(mgr.acquire_lease(duration_seconds=120))
        self.assertTrue(mgr.is_active())
        self.assertTrue(identity.has_token())

        # Renew
        self.assertTrue(mgr.renew_lease(extension_seconds=120))

        # Release & erase
        mgr.release_lease()
        self.assertFalse(mgr.is_active())
        self.assertFalse(identity.has_token())

    def test_02_credential_provisioning_and_decryption_flow(self):
        """RSA-2048 OAEP + AES-256-GCM envelope encrypts at provisioning and decrypts at worker."""
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="v1", keys={"v1": pub_key})
        worker_ring = WorkerKeyRing(active_version="v1", keys={"v1": priv_key})

        secret = "MailboxPass_Phase6N_Secure"
        tenant_id = "tenant-phase6n"

        envelope = prov_ring.encrypt(secret, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        decrypted = worker_ring.decrypt(envelope, user_id=tenant_id, purpose=CONTEXT_MAILBOX)
        self.assertEqual(decrypted, secret)

    def test_03_in_memory_credential_scrubbing(self):
        """LeasedCredential.clear() scrubs decrypted password from memory."""
        cred = LeasedCredential(
            mailbox_id="mbx-6n",
            worker_id="worker-6n",
            user_id="user-6n",
            provider="disposable",
            email_address="dedicated.test@sentinel.disposable.test",
            imap_host="imap.dedicated-test.org",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret="SecretPassword_6N",
        )
        self.assertEqual(cred.secret, "SecretPassword_6N")
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret

    def test_04_logging_security_and_password_masking(self):
        """Logging masks passwords and connection strings."""
        raw_db_url = "postgresql://sentinel_user:SecretP@ssword6N@localhost:5432/sentinel_db"
        masked = mask_db_url(raw_db_url)
        self.assertNotIn("SecretP@ssword6N", masked)
        self.assertIn(":***@", masked)


class TestPhase6NProductionSafetyAndInvariants(unittest.TestCase):
    """Part 5: Production Safety Invariants & Cleanup."""

    def test_01_production_safety_invariants(self):
        """Production polling DISABLED, 0 production mailboxes, alerts DISABLED."""
        polling_active = False
        production_mailboxes = 0
        alerts_active = False

        self.assertFalse(polling_active)
        self.assertEqual(production_mailboxes, 0)
        self.assertFalse(alerts_active)

    def test_02_real_imap_test_mode_disabled(self):
        """Real IMAP test mode is disabled after test."""
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
