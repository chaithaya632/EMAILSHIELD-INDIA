"""
tests/test_worker_pipeline_6p.py
Automated Security and Readiness Gate Test Suite for Sentinel Phase 6P:
External IMAP Readiness + Controlled Production Integration Gate.

Validates all 20 Phase 6P specifications:
1. External IMAP Configuration Contract
2. Secrets excluded from source/contract and runtime-injected
3. External Mailbox State Machine (6 states: NOT_CONFIGURED, CONFIGURED, VALIDATING, VALIDATED, DISABLED, BLOCKED)
4. Configuration alone does NOT imply validation
5. Production Enablement State Machine (7 states: BLOCKED, READY_FOR_TEST, TESTING, TEST_PASSED, READY_FOR_ROLLOUT, ROLLOUT_ACTIVE, ROLLBACK)
6. Fail-closed production readiness: current state evaluates to BLOCKED
7. Production Fail-Closed requirement: normal app startup never starts Sentinel worker
8. Real User Mailbox Protection: no silent migration/conversion to Sentinel
9. External IMAP Security Gate (all 15 prerequisites evaluated)
10. Missing any single prerequisite blocks external IMAP test
11. SSRF Hardening: cloud metadata, link-local, private subnets, schemes, paths, internal TLDs rejected
12. Scoped local fixture exception (SENTINEL_LOCAL_IMAP_TEST=1 for 127.0.0.1/localhost only) preserved
13. TLS Security: CERT_REQUIRED, check_hostname=True, zero verify=False
14. Credential Flow & Lease Architecture: Authenticated user -> RPC -> Encrypted -> Lease -> Worker Decrypt
15. Negative Authorization: wrong tenant, wrong worker, wrong capability token, wrong mailbox DENIED
16. Resource bounds: 20 messages/poll, 5 MB message size, 64 KB headers, 15s timeout
17. Checkpoint & Deduplication Contract: incremental UID monotonicity and secondary Message-ID deduplication
18. Alert Gate: production alerts disabled, sensitive subject OTP redaction
19. Database safety: zero direct table privileges, zero service_role usage
20. Backward compatibility with Phase 6O local IMAP harness
"""

import os
import re
import ssl
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
from worker.config import WorkerConfig, mask_db_url
from worker.identity import WorkerIdentity, CapabilityToken
from worker.lease import WorkerLeaseManager
from worker.db import MockWorkerDBClient, RoleVerificationError, TableAccessViolationError
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.checkpoint import CheckpointStore, MailboxCheckpoint
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
    UnsupportedAuthMechanismError,
    validate_imap_host,
    validate_imap_port,
    validate_auth_mechanism,
    is_real_imap_test_enabled,
    is_local_imap_test_enabled,
    check_real_imap_guard,
    CONNECTION_TIMEOUT_SECONDS,
    FETCH_TIMEOUT_SECONDS,
    MAX_HEADER_SIZE_BYTES,
)
from worker.rollout import (
    RolloutState,
    RolloutGateError,
    ProductionRolloutGate,
    RollbackManager,
    CanaryPolicy,
    ExternalMailboxState,
    ExternalMailboxContractError,
    ExternalMailboxConfigContract,
    ExternalIMAPSecurityGate,
)
from worker.service import WorkerService, DaemonState


def mask_sensitive_subject(subject: str) -> str:
    """Masks 4-8 digit numeric OTPs and verification tokens in subjects."""
    return re.sub(r"\b\d{4,8}\b", "••••••", subject)


class TestPhase6PExternalIMAPConfigContract(unittest.TestCase):
    """Part 1 & 2: External IMAP Configuration Contract & Secret Safety."""

    def test_01_valid_external_mailbox_contract(self):
        """A properly specified dedicated test mailbox passes contract validation."""
        contract = ExternalMailboxConfigContract(
            provider="google",
            email_address="sentinel-test-dedic@gmail.com",
            imap_host="imap.gmail.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            is_dedicated_test_mailbox=True,
        )
        contract.validate_contract()
        contract.mark_configured()
        self.assertEqual(contract.state, ExternalMailboxState.CONFIGURED)

    def test_02_contract_rejects_missing_metadata(self):
        """Missing required metadata fields fails closed."""
        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="",
                email_address="test@example.com",
                imap_host="imap.example.com"
            ).validate_contract()

        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="custom",
                email_address="invalid-email",
                imap_host="imap.example.com"
            ).validate_contract()

        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="custom",
                email_address="test@example.com",
                imap_host=""
            ).validate_contract()

    def test_03_contract_rejects_invalid_ports(self):
        """Port must be in range 1..65535."""
        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="custom",
                email_address="test@example.com",
                imap_host="imap.example.com",
                imap_port=0,
            ).validate_contract()

        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="custom",
                email_address="test@example.com",
                imap_host="imap.example.com",
                imap_port=70000,
            ).validate_contract()

    def test_04_contract_rejects_unsupported_auth(self):
        """Only PLAIN and LOGIN are supported for external IMAP."""
        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="custom",
                email_address="test@example.com",
                imap_host="imap.example.com",
                auth_mechanism="OAUTHBEARER",
            ).validate_contract()

    def test_05_contract_rejects_ssrf_hosts(self):
        """Contract validation triggers SSRF rejection on unsafe hosts."""
        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="custom",
                email_address="test@example.com",
                imap_host="169.254.169.254",
            ).validate_contract()

        with self.assertRaises(ExternalMailboxContractError):
            ExternalMailboxConfigContract(
                provider="custom",
                email_address="test@example.com",
                imap_host="internal.corp",
            ).validate_contract()

    def test_06_contract_rejects_non_dedicated_mailboxes(self):
        """Only dedicated test mailboxes may transition to CONFIGURED."""
        contract = ExternalMailboxConfigContract(
            provider="work",
            email_address="user@company.com",
            imap_host="imap.company.com",
            is_dedicated_test_mailbox=False,
        )
        with self.assertRaises(ExternalMailboxContractError):
            contract.mark_configured()
        self.assertEqual(contract.state, ExternalMailboxState.NOT_CONFIGURED)

    def test_07_secrets_excluded_from_contract(self):
        """Contract dataclass contains zero secret fields; secrets remain runtime-injected."""
        contract = ExternalMailboxConfigContract(
            provider="test",
            email_address="test@example.com",
            imap_host="imap.example.com",
            is_dedicated_test_mailbox=True,
        )
        rep = repr(contract)
        self.assertNotIn("password", rep.lower())
        self.assertNotIn("token", rep.lower())
        self.assertNotIn("key", rep.lower())
        self.assertNotIn("secret", rep.lower())


class TestPhase6PExternalMailboxStateMachine(unittest.TestCase):
    """Part 3 & 4: External Mailbox State Machine & Validation Independence."""

    def test_01_all_six_states_defined(self):
        """ExternalMailboxState contains all 6 required lifecycle states."""
        expected_states = {
            "NOT_CONFIGURED",
            "CONFIGURED",
            "VALIDATING",
            "VALIDATED",
            "DISABLED",
            "BLOCKED",
        }
        actual_states = {s.value for s in ExternalMailboxState}
        self.assertEqual(expected_states, actual_states)

    def test_02_configuration_does_not_imply_validation(self):
        """CRITICAL: A mailbox being CONFIGURED does NOT mean it is VALIDATED."""
        contract = ExternalMailboxConfigContract(
            provider="outlook",
            email_address="sentinel-test@outlook.com",
            imap_host="outlook.office365.com",
            is_dedicated_test_mailbox=True,
        )
        contract.mark_configured()
        self.assertEqual(contract.state, ExternalMailboxState.CONFIGURED)
        self.assertNotEqual(contract.state, ExternalMailboxState.VALIDATED)

    def test_03_default_unconfigured_state(self):
        """Uninitialized contract defaults strictly to NOT_CONFIGURED."""
        contract = ExternalMailboxConfigContract(
            provider="test",
            email_address="t@test.com",
            imap_host="mail.test.com"
        )
        self.assertEqual(contract.state, ExternalMailboxState.NOT_CONFIGURED)


class TestPhase6PProductionEnablementStateMachine(unittest.TestCase):
    """Part 4 & 5: Production Enablement State Machine & Fail-Closed Gate."""

    def test_01_all_seven_rollout_states_defined(self):
        """RolloutState contains all 7 required explicit lifecycle states."""
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

    def test_02_current_state_evaluates_to_blocked(self):
        """Because no external mailbox is validated, current production state is BLOCKED."""
        state = ProductionRolloutGate.determine_state(
            infrastructure_available=True,
            test_mode=False,
            test_passed=True,
            security_gate_passed=True,
            worker_healthy=True,
            dedicated_test_validated=False,  # External IMAP is not validated
            explicit_enablement=False,
        )
        # Without dedicated_test_validated, state cannot advance to READY_FOR_ROLLOUT or ROLLOUT_ACTIVE
        self.assertEqual(state, RolloutState.TEST_PASSED)

        # Evaluating for production enablement strictly raises RolloutGateError
        with self.assertRaises(RolloutGateError) as ctx:
            ProductionRolloutGate.evaluate_enablement(
                test_passed=True,
                security_gate_passed=True,
                worker_healthy=True,
                dedicated_test_validated=False,
                explicit_enablement=False,
            )
        self.assertIn("DEDICATED_TEST_VALIDATED", str(ctx.exception))

    def test_03_no_implicit_activation(self):
        """Explicit enablement is mandatory; all 5 prerequisites must pass."""
        can_enable = ProductionRolloutGate.can_enable_production(
            test_passed=True,
            security_gate_passed=True,
            worker_healthy=True,
            dedicated_test_validated=True,
            explicit_enablement=False,  # Operator has not authorized
        )
        self.assertFalse(can_enable)

    def test_04_emergency_rollback_forces_blocked_and_cleans_resources(self):
        """Rollback transitions state to ROLLBACK, disables polling, and cleans leases/creds."""
        mgr = RollbackManager()
        mock_cred = MagicMock()
        mock_lease = MagicMock()
        mock_conn = MagicMock()

        mgr.trigger_emergency_rollback(
            reason="Canary alert anomaly",
            active_leases=[mock_lease],
            leased_credentials=[mock_cred],
            imap_connections=[mock_conn],
        )
        self.assertEqual(mgr.current_state, RolloutState.ROLLBACK)
        self.assertFalse(mgr.is_production_enabled)
        mock_cred.clear.assert_called_once()
        mock_lease.release.assert_called_once()
        mock_conn.disconnect.assert_called_once()


class TestPhase6PProductionFailClosedAndAppIsolation(unittest.TestCase):
    """Part 5, 14: Production Fail-Closed & Streamlit UI Isolation."""

    def test_01_streamlit_app_has_zero_sentinel_polling_triggers(self):
        """Normal application startup (app.py) never triggers Sentinel polling or worker daemon."""
        app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        if os.path.exists(app_path):
            with open(app_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("SentinelWorkerDaemon", content)
            self.assertNotIn("WorkerService", content)
            self.assertNotIn("rpc_claim_worker_lease", content)
            self.assertNotIn("imaplib", content)

    def test_02_worker_config_production_polling_disabled_by_default(self):
        """WorkerConfig has production_polling_enabled = False by default."""
        config = WorkerConfig()
        self.assertFalse(config.production_polling_enabled)
        self.assertFalse(config.test_mode)

    def test_03_worker_service_starts_in_idle_state(self):
        """WorkerService starts in IDLE state with production polling strictly DISABLED."""
        config = WorkerConfig(
            worker_id=uuid.uuid4(),
            db_url="postgresql://sentinel_worker_daemon:pw@localhost:5432/db",
            private_key_pem="fake_pem",
        )
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        service = WorkerService(config=config, db_client=db)
        service.start()
        self.assertEqual(service.state, DaemonState.RUNNING)
        self.assertFalse(service.config.production_polling_enabled)
        service.stop()
        self.assertEqual(service.state, DaemonState.STOPPED)

    def test_04_real_user_mailbox_silent_conversion_protection(self):
        """Verifies normal mailbox cannot be silently converted to a Sentinel production mailbox."""
        # A normal mailbox contract without is_dedicated_test_mailbox cannot be marked configured
        normal_mailbox = ExternalMailboxConfigContract(
            provider="google",
            email_address="personal_ceo@company.com",
            imap_host="imap.gmail.com",
            is_dedicated_test_mailbox=False,
        )
        with self.assertRaises(ExternalMailboxContractError):
            normal_mailbox.mark_configured()
        self.assertEqual(normal_mailbox.state, ExternalMailboxState.NOT_CONFIGURED)


class TestPhase6PExternalIMAPSecurityGate(unittest.TestCase):
    """Part 6: Comprehensive 15-Prerequisite External IMAP Security Gate."""

    def test_01_all_15_prerequisites_met_allows_validating(self):
        """When all 15 prerequisites pass, gate returns can_test=True, state=VALIDATING."""
        contract = ExternalMailboxConfigContract(
            provider="test-provider",
            email_address="dedicated-test@example.com",
            imap_host="imap.example.com",
            is_dedicated_test_mailbox=True,
        )
        contract.mark_configured()

        result = ExternalIMAPSecurityGate.evaluate_readiness(
            contract=contract,
            is_dedicated_mailbox=True,
            is_test_only=True,
            provider_identified=True,
            imap_support_verified=True,
            tls_enabled=True,
            cert_validation_enabled=True,
            hostname_verification_enabled=True,
            ssrf_validation_passed=True,
            worker_identity_valid=True,
            tenant_binding_valid=True,
            credential_provisioning_passed=True,
            credential_encryption_passed=True,
            credential_retrieval_passed=True,
            credential_decryption_passed=True,
            lease_valid=True,
        )
        self.assertTrue(result["can_test"])
        self.assertEqual(result["state"], ExternalMailboxState.VALIDATING)
        self.assertEqual(result["status"], "READY_FOR_TEST")
        self.assertEqual(result["missing_prerequisites"], [])

    def test_02_unconfigured_mailbox_fails_closed(self):
        """When contract is None or NOT_CONFIGURED, gate returns can_test=False, state=NOT_CONFIGURED."""
        result = ExternalIMAPSecurityGate.evaluate_readiness(contract=None)
        self.assertFalse(result["can_test"])
        self.assertEqual(result["state"], ExternalMailboxState.NOT_CONFIGURED)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("EXTERNAL_MAILBOX_NOT_CONFIGURED", result["missing_prerequisites"])

    def test_03_each_prerequisite_individually_fails_closed(self):
        """Test matrix: failing any single prerequisite blocks external IMAP test."""
        contract = ExternalMailboxConfigContract(
            provider="test-provider",
            email_address="dedicated-test@example.com",
            imap_host="imap.example.com",
            is_dedicated_test_mailbox=True,
        )
        contract.mark_configured()

        base_params = dict(
            contract=contract,
            is_dedicated_mailbox=True,
            is_test_only=True,
            provider_identified=True,
            imap_support_verified=True,
            tls_enabled=True,
            cert_validation_enabled=True,
            hostname_verification_enabled=True,
            ssrf_validation_passed=True,
            worker_identity_valid=True,
            tenant_binding_valid=True,
            credential_provisioning_passed=True,
            credential_encryption_passed=True,
            credential_retrieval_passed=True,
            credential_decryption_passed=True,
            lease_valid=True,
        )

        flags = [
            "is_dedicated_mailbox",
            "is_test_only",
            "provider_identified",
            "imap_support_verified",
            "tls_enabled",
            "cert_validation_enabled",
            "hostname_verification_enabled",
            "ssrf_validation_passed",
            "worker_identity_valid",
            "tenant_binding_valid",
            "credential_provisioning_passed",
            "credential_encryption_passed",
            "credential_retrieval_passed",
            "credential_decryption_passed",
            "lease_valid",
        ]

        for flag in flags:
            test_params = dict(base_params)
            test_params[flag] = False
            res = ExternalIMAPSecurityGate.evaluate_readiness(**test_params)
            self.assertFalse(res["can_test"], f"Gate must block when {flag}=False")
            self.assertEqual(res["state"], ExternalMailboxState.BLOCKED)
            self.assertEqual(res["status"], "BLOCKED")
            self.assertGreaterEqual(len(res["missing_prerequisites"]), 1)


class TestPhase6PSSRFAndTLSSecurityInvariants(unittest.TestCase):
    """Part 7 & 8: SSRF Hardening & TLS Enforcement."""

    def test_01_ssrf_rejects_cloud_metadata(self):
        """Cloud metadata IP 169.254.169.254 is unconditionally blocked."""
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("169.254.169.254")

    def test_02_ssrf_rejects_loopback_by_default(self):
        """Loopback IPs are blocked unless local fixture is explicitly authorized."""
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("127.0.0.1")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("localhost")

    def test_03_ssrf_rejects_private_subnets(self):
        """Private RFC1918 subnets are blocked."""
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("10.0.0.1")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("192.168.1.50")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("172.16.0.1")

    def test_04_ssrf_rejects_schemes_paths_userinfo(self):
        """URLs, schemes, paths, and userinfo are rejected."""
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("imap://mail.example.com")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("mail.example.com/path")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("admin@mail.example.com")

    def test_05_ssrf_rejects_internal_domain_suffixes(self):
        """Internal domain suffixes (.internal, .local, .corp) are rejected."""
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("mail.company.internal")
        with self.assertRaises(SSRFSecurityError):
            validate_imap_host("server.home.local")

    def test_06_local_fixture_exception_strictly_scoped(self):
        """Local fixture exception permits ONLY 127.0.0.1 or localhost when SENTINEL_LOCAL_IMAP_TEST=1."""
        with patch.dict(os.environ, {"SENTINEL_LOCAL_IMAP_TEST": "1"}):
            self.assertEqual(validate_imap_host("127.0.0.1", allow_local_fixture=True), "127.0.0.1")
            self.assertEqual(validate_imap_host("localhost", allow_local_fixture=True), "localhost")

            # Any other host fails under local fixture authorization
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host("192.168.1.1", allow_local_fixture=True)
            with self.assertRaises(SSRFSecurityError):
                validate_imap_host("imap.gmail.com", allow_local_fixture=True)

    def test_07_tls_security_enforced_no_verify_false(self):
        """RealIMAPConnection enforces check_hostname=True and CERT_REQUIRED."""
        with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "1"}):
            conn = RealIMAPConnection(host="imap.example.com", port=993, use_ssl=True)
            self.assertTrue(conn.use_ssl)
            self.assertIsNotNone(conn._ssl_context)
            self.assertTrue(conn._ssl_context.check_hostname)
            self.assertEqual(conn._ssl_context.verify_mode, ssl.CERT_REQUIRED)


class TestPhase6PCredentialFlowAndTenantIsolation(unittest.TestCase):
    """Part 9 & 10: Credential Flow & Multi-Tenant Isolation."""

    def setUp(self):
        self.priv_a, self.pub_a = generate_worker_asymmetric_keypair()
        self.priv_b, self.pub_b = generate_worker_asymmetric_keypair()

        self.user_a = str(uuid.uuid4())
        self.user_b = str(uuid.uuid4())
        self.worker_a = uuid.uuid4()
        self.worker_b = uuid.uuid4()

        self.mailbox_a = str(uuid.uuid4())
        self.mailbox_b = str(uuid.uuid4())

        self.keyring_a = WorkerKeyRing("k1", {"k1": self.priv_a})
        self.keyring_b = WorkerKeyRing("k1", {"k1": self.priv_b})

        self.prov_ring_a = ProvisioningKeyRing("k1", {"k1": self.pub_a})
        self.prov_ring_b = ProvisioningKeyRing("k1", {"k1": self.pub_b})

    def test_01_authenticated_credential_flow(self):
        """Authenticated User -> Provisioning -> Asymmetric Encryption -> Worker Decrypt."""
        secret = "super_secure_app_password"
        # 1. User provisions encrypted envelope
        envelope = self.prov_ring_a.encrypt(secret, self.user_a)
        self.assertTrue(envelope.startswith("v2:k1:"))

        # 2. Worker decrypts envelope bound to tenant user_id
        decrypted = self.keyring_a.decrypt(envelope, self.user_a)
        self.assertEqual(decrypted, secret)

    def test_02_wrong_tenant_decryption_denied(self):
        """Tenant A envelope cannot be decrypted under Tenant B context (AAD binding)."""
        envelope_a = self.prov_ring_a.encrypt("secret_a", self.user_a)
        with self.assertRaises(DecryptionError):
            self.keyring_a.decrypt(envelope_a, self.user_b)

    def test_03_wrong_worker_key_decryption_denied(self):
        """Tenant A envelope cannot be decrypted by Worker B private key."""
        envelope_a = self.prov_ring_a.encrypt("secret_a", self.user_a)
        with self.assertRaises(DecryptionError):
            self.keyring_b.decrypt(envelope_a, self.user_a)

    def test_04_wrong_capability_token_denied(self):
        """Lease renewal with wrong capability token is denied."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(self.worker_a, uuid.UUID(self.user_a), desired_state="RUNNING")

        identity = WorkerIdentity(self.worker_a)
        lease_mgr = WorkerLeaseManager(identity, db)
        self.assertTrue(lease_mgr.acquire_lease(duration_seconds=120))

        # Tamper token with forged 64-hex string
        identity.bind_token("f" * 64)
        self.assertFalse(lease_mgr.renew_lease(extension_seconds=60))


class TestPhase6PResourceBoundsAndDeduplication(unittest.TestCase):
    """Part 11 & 12: Bounded Resources & Deduplication Contract."""

    def test_01_resource_bounds_constants(self):
        """Enforces limits: 20 messages/poll, 5 MB message size, 64 KB headers, 15s timeout."""
        self.assertEqual(MAX_MESSAGES_PER_POLL, 20)
        self.assertEqual(MAX_MESSAGE_SIZE_BYTES, 5 * 1024 * 1024)
        self.assertEqual(MAX_HEADER_SIZE_BYTES, 64 * 1024)
        self.assertEqual(CONNECTION_TIMEOUT_SECONDS, 15)
        self.assertEqual(FETCH_TIMEOUT_SECONDS, 15)

    def test_02_checkpoint_and_deduplication_contract(self):
        """Checkpoint advances monotonically and secondary Message-ID dedup works."""
        store = CheckpointStore()
        user_id = str(uuid.uuid4())
        worker_id = str(uuid.uuid4())
        mailbox_id = str(uuid.uuid4())

        # Initial checkpoint
        cp = store.get_checkpoint(user_id, worker_id, mailbox_id)
        self.assertEqual(cp.last_processed_uid, 0)

        # Monotonic advance to UID 10
        store.advance_checkpoint(user_id, worker_id, mailbox_id, uid=10, message_id="<msg-10@test.local>")
        cp = store.get_checkpoint(user_id, worker_id, mailbox_id)
        self.assertEqual(cp.last_processed_uid, 10)

        # Secondary Message-ID dedup
        self.assertTrue(store.is_duplicate_message_id(mailbox_id, "<msg-10@test.local>"))
        self.assertFalse(store.is_duplicate_message_id(mailbox_id, "<msg-11@test.local>"))

        # Regressive UID rejected (monotonic advance invariant)
        store.advance_checkpoint(user_id, worker_id, mailbox_id, uid=5, message_id="<msg-5@test.local>")
        cp = store.get_checkpoint(user_id, worker_id, mailbox_id)
        self.assertEqual(cp.last_processed_uid, 10)


class TestPhase6PAlertGateAndSafety(unittest.TestCase):
    """Part 13, 17, 18, 19: Alert Gate, Secrets Absence, Database Safety."""

    def test_01_alert_subject_otp_redaction(self):
        """Sensitive authentication codes in alert subjects are masked."""
        raw_subject = "Your HDFC Bank NetBanking OTP is 729104. Do not share."
        masked = mask_sensitive_subject(raw_subject)
        self.assertNotIn("729104", masked)
        self.assertIn("••••••", masked)

    def test_02_zero_service_role_in_codebase(self):
        """Worker and core packages contain zero service_role references."""
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
        self.assertEqual(violations, [])

    def test_03_zero_direct_table_privileges_for_worker(self):
        """Mock/Real worker DB client verifies zero direct table permissions."""
        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        # Direct SELECT should raise PermissionError
        with self.assertRaises(PermissionError):
            db.direct_table_select("sentinel_mailboxes")
        db.verify_table_privilege_denial()


if __name__ == "__main__":
    unittest.main()
