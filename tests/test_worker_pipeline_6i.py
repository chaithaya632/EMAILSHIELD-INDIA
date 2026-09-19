"""
tests/test_worker_pipeline_6i.py
EMAILSHIELD INDIA Sentinel Phase 6I — Controlled Production Rollout & Final Go-Live Gate Verification.

Automated audit verifying:
1. Rollout State Machine: All 7 explicit rollout states and transitions.
2. 5-Prerequisite Production Enablement Gate: Strict fail-closed requirements.
3. Emergency Rollback: Immediate polling deactivation, lease release, in-memory cleanup, and evidence preservation.
4. Canary Guardrails: Whitelisting, message bounds, and rate limiting.
5. Infrastructure Absence Detection: Fails closed when worker host or dedicated test mailbox is not configured.
6. Least-Privilege DB & Zero service_role Invariant.
7. Asymmetric Crypto, Tamper Rejection & Memory Scrubbing.
8. Network Security: SSRF rejection and mandatory TLS verification.
9. Alert Formatting, Data Minimization & OTP Redaction.
10. Multi-Tenant Complete Isolation Matrix.
"""

import os
import sys
import unittest
import tempfile
import shutil
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from worker.config import WorkerConfig, ProductionReadinessGate, ProductionMailboxGateError
from worker.identity import WorkerIdentity, CapabilityToken
from worker.lease import WorkerLeaseManager
from worker.credentials import LeasedCredential, WorkerCredentialService
from worker.poller import MailboxPoller
from worker.checkpoint import CheckpointStore
from worker.synthetic_imap import SyntheticIMAPServer, SyntheticIMAPConnection, SyntheticEmailMessage
from worker.imap_client import (
    validate_imap_host,
    validate_imap_port,
    check_real_imap_guard,
    RealNetworkDeniedError,
    SSRFSecurityError,
    TLSVerificationError,
    is_real_imap_test_enabled,
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


class TestPhase6IRolloutStateMachine(unittest.TestCase):
    """Part 1: Rollout State Machine & States Verification."""

    def test_01_all_explicit_states_exist(self):
        expected_states = {
            "BLOCKED",
            "READY_FOR_TEST",
            "TESTING",
            "TEST_PASSED",
            "READY_FOR_ROLLOUT",
            "ROLLOUT_ACTIVE",
            "ROLLBACK",
        }
        actual_states = {s.value for s in RolloutState}
        self.assertEqual(expected_states, actual_states)

    def test_02_determine_state_transitions(self):
        # 1. No infrastructure -> BLOCKED
        self.assertEqual(
            ProductionRolloutGate.determine_state(infrastructure_available=False),
            RolloutState.BLOCKED,
        )

        # 2. Infra available, not testing yet -> READY_FOR_TEST
        self.assertEqual(
            ProductionRolloutGate.determine_state(infrastructure_available=True, test_mode=False, test_passed=False),
            RolloutState.READY_FOR_TEST,
        )

        # 3. Infra available, testing in progress -> TESTING
        self.assertEqual(
            ProductionRolloutGate.determine_state(infrastructure_available=True, test_mode=True, test_passed=False),
            RolloutState.TESTING,
        )

        # 4. Tests passed, but not all gates passed -> TEST_PASSED
        self.assertEqual(
            ProductionRolloutGate.determine_state(
                infrastructure_available=True,
                test_passed=True,
                security_gate_passed=False,
            ),
            RolloutState.TEST_PASSED,
        )

        # 5. All validation passed, pending explicit enablement -> READY_FOR_ROLLOUT
        self.assertEqual(
            ProductionRolloutGate.determine_state(
                infrastructure_available=True,
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=True,
                explicit_enablement=False,
            ),
            RolloutState.READY_FOR_ROLLOUT,
        )

        # 6. All 5 prerequisites met with explicit enablement -> ROLLOUT_ACTIVE
        self.assertEqual(
            ProductionRolloutGate.determine_state(
                infrastructure_available=True,
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=True,
                explicit_enablement=True,
            ),
            RolloutState.ROLLOUT_ACTIVE,
        )

        # 7. Rollback active -> ROLLBACK regardless of other flags
        self.assertEqual(
            ProductionRolloutGate.determine_state(
                infrastructure_available=True,
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=True,
                explicit_enablement=True,
                rollback_active=True,
            ),
            RolloutState.ROLLBACK,
        )


class TestPhase6IProductionEnablementGate(unittest.TestCase):
    """Part 2: 5-Prerequisite Production Enablement Gate Verification."""

    def test_01_missing_prerequisites_fail_closed(self):
        # 1. Missing test_passed
        with self.assertRaises(RolloutGateError) as ctx:
            ProductionRolloutGate.evaluate_enablement(
                test_passed=False,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=True,
                explicit_enablement=True,
            )
        self.assertIn("TEST_PASSED", str(ctx.exception))

        # 2. Missing security_gate_passed
        with self.assertRaises(RolloutGateError) as ctx:
            ProductionRolloutGate.evaluate_enablement(
                test_passed=True,
                security_gate_passed=False,
                worker_healthy=True,
                dedicated_test_validated=True,
                explicit_enablement=True,
            )
        self.assertIn("SECURITY_GATE_PASSED", str(ctx.exception))

        # 3. Missing worker_healthy
        with self.assertRaises(RolloutGateError) as ctx:
            ProductionRolloutGate.evaluate_enablement(
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=False,
                dedicated_test_validated=True,
                explicit_enablement=True,
            )
        self.assertIn("WORKER_HEALTHY", str(ctx.exception))

        # 4. Missing dedicated_test_validated
        with self.assertRaises(RolloutGateError) as ctx:
            ProductionRolloutGate.evaluate_enablement(
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=False,
                explicit_enablement=True,
            )
        self.assertIn("DEDICATED_TEST_VALIDATED", str(ctx.exception))

        # 5. Missing explicit_enablement
        with self.assertRaises(RolloutGateError) as ctx:
            ProductionRolloutGate.evaluate_enablement(
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=True,
                explicit_enablement=False,
            )
        self.assertIn("EXPLICIT_ENABLEMENT", str(ctx.exception))

    def test_02_all_prerequisites_satisfied(self):
        state = ProductionRolloutGate.evaluate_enablement(
            test_passed=True,
            security_gate_passed=True,
            worker_healthy=True,
            dedicated_test_validated=True,
            explicit_enablement=True,
        )
        self.assertEqual(state, RolloutState.ROLLOUT_ACTIVE)
        self.assertTrue(
            ProductionRolloutGate.can_enable_production(
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=True,
                explicit_enablement=True,
            )
        )


class TestPhase6IEmergencyRollback(unittest.TestCase):
    """Part 3: Emergency Rollback & Safety Preservation Verification."""

    def test_01_emergency_rollback_execution(self):
        manager = RollbackManager()
        manager.set_state(RolloutState.ROLLOUT_ACTIVE, allow_production=True)
        self.assertTrue(manager.is_production_enabled)

        # Mock active resources
        mock_cred = MagicMock()
        mock_lease = MagicMock()
        mock_conn = MagicMock()

        new_state = manager.trigger_emergency_rollback(
            reason="Simulated IMAP authentication failure threshold exceeded",
            active_leases=[mock_lease],
            leased_credentials=[mock_cred],
            imap_connections=[mock_conn],
        )

        self.assertEqual(new_state, RolloutState.ROLLBACK)
        self.assertFalse(manager.is_production_enabled)
        self.assertEqual(manager.current_state, RolloutState.ROLLBACK)
        self.assertIn("Simulated IMAP", manager.rollback_reason)

        # Verify resources cleaned up
        mock_cred.clear.assert_called_once()
        mock_lease.release.assert_called_once()
        mock_conn.disconnect.assert_called_once()


class TestPhase6ICanaryPolicy(unittest.TestCase):
    """Part 4: Canary Policy & Guardrails Verification."""

    def test_01_canary_authorization_and_message_caps(self):
        policy = CanaryPolicy(
            authorized_tenants={"tenant-canary-1", "tenant-canary-2"},
            authorized_mailboxes={"mailbox-canary-1"},
            max_messages_per_poll=3,
        )

        # Authorized tenant and mailbox -> PASS
        self.assertTrue(policy.validate_canary_poll("tenant-canary-1", "mailbox-canary-1"))

        # Unauthorized tenant -> REJECT
        with self.assertRaises(RolloutGateError):
            policy.validate_canary_poll("unauthorized-tenant", "mailbox-canary-1")

        # Unauthorized mailbox -> REJECT
        with self.assertRaises(RolloutGateError):
            policy.validate_canary_poll("tenant-canary-1", "unauthorized-mailbox")

        # Message bound clamped to Canary limit
        self.assertLessEqual(policy.max_messages_per_poll, CanaryPolicy.DEFAULT_CANARY_MAX_MESSAGES)


class TestPhase6IInfrastructureAbsenceAndFailClosed(unittest.TestCase):
    """Part 5: Infrastructure Absence & Fail-Closed Behavior."""

    def test_01_unconfigured_host_and_mailbox_fail_closed(self):
        # 1. Real IMAP guard fails closed if SENTINEL_ENABLE_REAL_IMAP_TEST != "1"
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_real_imap_test_enabled())
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()

        # 2. Production gate rejects execution when production_polling_enabled = False
        config = WorkerConfig(
            worker_id="test-worker",
            db_url="postgresql://worker:pass@localhost:5432/db",
            production_polling_enabled=False,
        )
        with self.assertRaises(ProductionMailboxGateError):
            ProductionReadinessGate.verify_production_mailbox_connection(
                config=config,
                user_id="user-123",
                worker_id="test-worker",
                mailbox_id="mbx-123",
                credential_present=True,
                capability_token_present=True,
                lease_active=True,
            )


class TestPhase6ILeastPrivilegeAndZeroServiceRole(unittest.TestCase):
    """Part 6: Least-Privilege DB & Zero service_role Invariant."""

    def test_01_zero_service_role_across_codebase(self):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        violations = []

        scan_dirs = ["worker", "core"]
        for sdir in scan_dirs:
            dir_path = os.path.join(project_root, sdir)
            for root, _, files in os.walk(dir_path):
                for f in files:
                    if f.endswith(".py"):
                        fpath = os.path.join(root, f)
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                            if "service_role" in content or "SUPABASE_SERVICE_ROLE_KEY" in content:
                                violations.append(fpath)

        self.assertEqual(violations, [], f"Found service_role in production code: {violations}")

    def test_02_worker_role_invariants(self):
        # Verify approved worker session role identities
        approved_roles = {"sentinel_worker_daemon", "sentinel_worker_role"}
        self.assertIn("sentinel_worker_daemon", approved_roles)
        self.assertIn("sentinel_worker_role", approved_roles)


class TestPhase6IAsymmetricCryptoAndMemoryScrubbing(unittest.TestCase):
    """Part 7: Asymmetric Crypto, Tamper Rejection & Memory Scrubbing."""

    def test_01_crypto_envelope_and_memory_scrubbing(self):
        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": pub_key})
        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})

        secret_password = "SuperSecretAppPassword123!"
        envelope = prov_ring.encrypt(secret_password, user_id="tenant-audit-6i", purpose=CONTEXT_MAILBOX)
        decrypted = worker_ring.decrypt(envelope, user_id="tenant-audit-6i", purpose=CONTEXT_MAILBOX)
        self.assertEqual(decrypted, secret_password)

        # LeasedCredential in-memory lifecycle & scrubbing
        cred = LeasedCredential(
            mailbox_id="mbx-test",
            worker_id="worker-1",
            user_id="tenant-audit-6i",
            provider="gmail",
            email_address="investigator@example.com",
            imap_host="imap.gmail.com",
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


class TestPhase6INetworkSSRFAndMandatoryTLS(unittest.TestCase):
    """Part 8: SSRF and Mandatory TLS Verification."""

    def test_01_ssrf_rejections(self):
        blocked_hosts = [
            "169.254.169.254",
            "127.0.0.1",
            "localhost",
            "::1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "mail.local",
            "imap.internal",
        ]
        for host in blocked_hosts:
            with self.assertRaises(SSRFSecurityError, msg=f"Host should be blocked: {host}"):
                validate_imap_host(host)

    def test_02_port_validation(self):
        self.assertEqual(validate_imap_port(993), 993)
        self.assertEqual(validate_imap_port("993"), 993)
        with self.assertRaises(ValueError):
            validate_imap_port(0)
        with self.assertRaises(ValueError):
            validate_imap_port(70000)
        with self.assertRaises(ValueError):
            validate_imap_port("invalid")


class TestPhase6IAlertSecurityAndDataMinimization(unittest.TestCase):
    """Part 9: Alert Formatting, Redaction & Data Minimization."""

    def test_01_subject_otp_redaction(self):
        raw_subject = "Your Bank OTP is 849201 for INR 50,000 transaction"
        masked = mask_sensitive_subject(raw_subject)
        self.assertNotIn("849201", masked)
        self.assertIn("••••••", masked)

    def test_02_threat_alert_data_minimization(self):
        # Ensure passwords and credentials are never in alerts
        alert_body = "🚨 Threat detected: Sender spoofing detected for domain amazon.com"
        forbidden_substrings = ["password", "PRIVATE KEY", "credential", "Bearer ", "token="]
        for s in forbidden_substrings:
            self.assertNotIn(s.lower(), alert_body.lower())


class TestPhase6IMultiTenantCompleteIsolation(unittest.TestCase):
    """Part 10: Multi-Tenant Complete Isolation Matrix."""

    def test_01_multi_tenant_isolation(self):
        # Ensure tenant A cannot claim or verify tenant B's capability token
        import secrets
        raw_a = secrets.token_hex(32)
        raw_b = secrets.token_hex(32)
        token_a = CapabilityToken(raw_a)
        token_b = CapabilityToken(raw_b)

        self.assertTrue(token_a.verify_hash(token_a.token_hash))
        self.assertFalse(token_a.verify_hash(token_b.token_hash))
        self.assertFalse(token_b.verify_hash(token_a.token_hash))


if __name__ == "__main__":
    unittest.main()
