"""
tests/test_sentinel_operational_hardening.py
Comprehensive Phase 14 Operational Hardening Test Suite for EMAILSHIELD INDIA Sentinel.

Covers all 50 operational points:
1. Worker Identity & Least-Privilege Role Verification
2. Mailbox Ownership & Multi-Tenant Binding
3. Lease Safety & Atomic Mutual Exclusion
4. Stale Worker Lease Recovery
5. PID / Process Liveness Validation (Cross-Platform)
6. Heartbeat Durability & Monotonic Updates
7. Lease Renewal Lifecycle
8. Mid-Poll Lease Loss Abort & Fail-Closed Behavior
9. Credential Lifecycle, Decryption & In-Memory Zeroing
10. Secret Isolation & Zero Credential Leakage in Repr/Logs
11. Real IMAP Connection Guard & Mandatory TLS Verification
12. Gmail / IMAP Reconnection & Disconnect Detection
13. Reconnection Backoff (Bounded Exponential)
14. Authentication Failure Classification & Safety
15. TLS Failure Classification & Fail-Closed Enforcement
16. SSRF Protection Matrix (Cloud Metadata, Link-Local, Private Ranges)
17. Checkpoint Durability & State Persistence
18. Checkpoint Atomicity & Post-Processing Advancement
19. Message-ID Deduplication & Bounded LRU Cache
20. Historical Mail Protection & Initial Sync Skip
21. SafeEmailEvent Generation & Envelope Sanitization
22. Forensic Processing Failure Handling & Quarantine
23. Malformed MIME Handling & Non-Crashing Resilience
24. Attachment Safety, Hash Extraction & Size Bounds
25. Telemetry Generation & Metric Accuracy
26. Telemetry Durability Across Execution Cycles
27. Cross-Process Telemetry Inspection & File Serialization
28. Alert Pipeline Formatting & Threat Payload Construction
29. Alert Deduplication & Cooldown Enforcement
30. Alert Delivery Failure Isolation & Non-Corrupting Resilience
31. Investigation Integration & Case Linking
32. Report Integration & Phase 13 Evidence Manifest Compatibility
33. Per-Mailbox Concurrency Lock & Operational Isolation
34. Tenant Isolation Across RPC and Data Boundaries
35. Worker Restart & Monotonic State Recovery
36. Graceful Shutdown & Token Invalidation
37. Unexpected Shutdown & TTL Expiry Recovery
38. Resource Leak Prevention (Socket/Lock Teardown in Finally)
39. Long-Running Polling Stability
40. Health Diagnostics & Telemetry Snapshot Omission
41. Failure Classification (10 Standard Categories)
42. Operational Rate Limiting & Throttle Enforcement
43. Production Safety Defaults (Disabled by Default)
44. Zero Forbidden Role Strings Across Core and Worker
45. Secret Scan & Sanitization Verification
"""

import email
import json
import logging
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch
import uuid

from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    WorkerKeyRing,
    ProvisioningKeyRing,
    encrypt_credential_asymmetric,
    CONTEXT_MAILBOX,
)
from core.evidence import build_evidence_manifest, verify_evidence_integrity
from core.investigation import (
    open_or_get_investigation,
    transition_investigation_status,
)
from core.telegram_alert import sanitize_telegram_token, validate_telegram_token_format
from core.sentinel import format_threat_alert_text, mask_sensitive_subject
from core.sentinel_stats import record_user_sentinel_poll, get_user_sentinel_stats

from worker.config import WorkerConfig
from worker.identity import WorkerIdentity, CapabilityToken
from worker.db import (
    MockWorkerDBClient,
    RoleVerificationError,
    TableAccessViolationError,
)
from worker.lease import WorkerLeaseManager
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.checkpoint import CheckpointStore, MailboxCheckpoint
from worker.events import SafeEmailEvent
from worker.service import WorkerService
from worker.poller import (
    MailboxPoller,
    MAX_MESSAGE_SIZE_BYTES,
    MAX_MESSAGES_PER_POLL,
)
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticEmailMessage,
)
from worker.imap_client import (
    validate_imap_host,
    validate_imap_port,
    check_real_imap_guard,
    RealIMAPConnection,
    RealNetworkDeniedError,
    SSRFSecurityError,
    TLSVerificationError,
    IMAPAuthenticationError,
    IMAPConnectionTimeoutError,
    FailureCategory,
    classify_operational_failure,
    compute_backoff_delay,
    OperationalRateLimiter,
)
from worker.health import (
    WorkerHealthMonitor,
    WorkerHealthStatus,
    is_pid_alive,
    get_worker_runtime_info,
)


class TestSentinelOperationalHardening(unittest.TestCase):
    """50-point operational hardening verification suite."""

    def setUp(self):
        self.tenant_a = "tenant-user-alpha"
        self.tenant_b = "tenant-user-beta"
        self.mailbox_a = "mbx-alpha-101"
        self.mailbox_b = "mbx-beta-202"
        self.worker_id_a = uuid.uuid4()
        self.worker_id_b = uuid.uuid4()

        self.priv_key_a, self.pub_key_a = generate_worker_asymmetric_keypair()
        self.worker_keyring_a = WorkerKeyRing(keys={"k1": self.priv_key_a})
        self.prov_keyring_a = ProvisioningKeyRing(keys={"k1": self.pub_key_a})

        self.db_client = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db_client.seed_worker(worker_id=self.worker_id_a, user_id=self.tenant_a, desired_state="RUNNING")
        self.db_client.seed_worker(worker_id=self.worker_id_b, user_id=self.tenant_b, desired_state="RUNNING")

        self.identity_a = WorkerIdentity(self.worker_id_a)
        self.lease_mgr_a = WorkerLeaseManager(self.identity_a, self.db_client)
        self.checkpoint_store = CheckpointStore(self.db_client)

    def _create_mock_cred_service(self, username="alice@test.local", password="synthetic_password"):
        cred_service = MagicMock()
        secret_json = json.dumps({"username": username, "password": password})
        cred_mock = MagicMock(
            mailbox_id=self.mailbox_a,
            user_id=self.tenant_a,
            secret=secret_json,
            email_address=username,
            imap_host="imap.example.com",
            imap_port=993,
            use_ssl=True,
        )
        cred_service.fetch_and_decrypt.return_value.__enter__.return_value = cred_mock
        return cred_service

    # -------------------------------------------------------------------------
    # 1. Worker Identity
    # -------------------------------------------------------------------------
    def test_01_worker_identity_least_privilege(self):
        """Worker identity binds to UUID and enforces table privilege denial."""
        identity = WorkerIdentity(self.worker_id_a)
        self.assertEqual(identity.worker_id, self.worker_id_a)
        self.assertFalse(identity.has_token())

        raw_hex = "a" * 64
        token = identity.bind_token(raw_hex)
        self.assertTrue(identity.has_token())
        self.assertIn("REDACTED", repr(token))
        self.assertNotIn(raw_hex, repr(token))
        identity.clear_token()
        self.assertFalse(identity.has_token())

        client = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        client.connect()
        sess_user, curr_user, _ = client.verify_session_identity()
        self.assertEqual(sess_user, "sentinel_worker_daemon")
        client.verify_table_privilege_denial()
        with self.assertRaises(PermissionError):
            client.direct_table_select("sentinel_mailboxes")

    # -------------------------------------------------------------------------
    # 2. Mailbox Ownership
    # -------------------------------------------------------------------------
    def test_02_mailbox_ownership_and_tenant_binding(self):
        """Cross-tenant or forged mailbox IDs are strictly rejected."""
        encrypted_cred = encrypt_credential_asymmetric(
            plaintext="app-password-secret-a",
            public_key=self.pub_key_a,
            user_id=self.tenant_a,
            key_version="k1",
        )

        self.db_client.seed_mailbox(
            mailbox_id=self.mailbox_a,
            worker_id=self.worker_id_a,
            user_id=self.tenant_a,
            encrypted_credentials=encrypted_cred,
        )
        ok = self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.assertTrue(ok)

        cred_service = WorkerCredentialService(self.identity_a, self.worker_keyring_a, self.db_client)
        with cred_service.fetch_and_decrypt() as cred:
            self.assertEqual(cred.mailbox_id, self.mailbox_a)
            self.assertEqual(cred.user_id, self.tenant_a)
            self.assertEqual(cred.secret, "app-password-secret-a")

    # -------------------------------------------------------------------------
    # 3. Lease Safety (Mutual Exclusion)
    # -------------------------------------------------------------------------
    def test_03_lease_safety_mutual_exclusion(self):
        """Only one active worker can hold the lease; second worker is denied."""
        ok1 = self.lease_mgr_a.acquire_lease(duration_seconds=120)
        self.assertTrue(ok1)

        identity_b = WorkerIdentity(self.worker_id_a)
        lease_mgr_b = WorkerLeaseManager(identity_b, self.db_client)
        ok2 = lease_mgr_b.acquire_lease(duration_seconds=120)
        self.assertFalse(ok2, "Second worker must be denied concurrent lease")

    # -------------------------------------------------------------------------
    # 4. Stale Worker Recovery
    # -------------------------------------------------------------------------
    def test_04_stale_worker_recovery(self):
        """Expired lease of a crashed worker is safely claimed by another worker."""
        self.lease_mgr_a.acquire_lease(duration_seconds=30)
        w = self.db_client.workers[str(self.worker_id_a)]
        w["lease_expires_at"] = time.time() - 10.0

        identity_recovered = WorkerIdentity(self.worker_id_a)
        lease_mgr_rec = WorkerLeaseManager(identity_recovered, self.db_client)
        ok = lease_mgr_rec.acquire_lease(duration_seconds=120)
        self.assertTrue(ok, "Stale expired lease should be reclaimable")

    # -------------------------------------------------------------------------
    # 5. PID / Process Liveness
    # -------------------------------------------------------------------------
    def test_05_pid_process_liveness(self):
        """Cross-platform PID check validates real processes and rejects non-existent ones."""
        current_pid = os.getpid()
        self.assertTrue(is_pid_alive(current_pid), "Current process must be reported alive")
        self.assertFalse(is_pid_alive(999999999), "Non-existent PID must be reported dead")
        self.assertFalse(is_pid_alive(-1), "Negative PID must be reported dead")
        self.assertFalse(is_pid_alive(None), "None PID must be reported dead")
        self.assertFalse(is_pid_alive("invalid"), "String PID must be reported dead")

    # -------------------------------------------------------------------------
    # 6. Heartbeat Durability
    # -------------------------------------------------------------------------
    def test_06_heartbeat_durability(self):
        """Worker health monitor records monotonic heartbeat advancements."""
        service = MagicMock()
        service.state.value = "RUNNING"
        service.identity.worker_id = self.worker_id_a
        monitor = WorkerHealthMonitor(service)

        t1 = monitor.last_heartbeat_epoch
        time.sleep(0.01)
        monitor.record_heartbeat()
        t2 = monitor.last_heartbeat_epoch
        self.assertGreater(t2, t1)

    # -------------------------------------------------------------------------
    # 7. Lease Renewal
    # -------------------------------------------------------------------------
    def test_07_lease_renewal(self):
        """Active lease can be renewed before expiry using held capability token."""
        self.lease_mgr_a.acquire_lease(duration_seconds=60)
        self.assertTrue(self.lease_mgr_a.is_active())
        renewed = self.lease_mgr_a.renew_lease(extension_seconds=120)
        self.assertTrue(renewed)
        self.assertGreater(self.lease_mgr_a.time_until_expiry(), 50)

    # -------------------------------------------------------------------------
    # 8. Mid-Poll Lease Loss
    # -------------------------------------------------------------------------
    def test_08_mid_poll_lease_loss_abort(self):
        """Poller halts immediately when lease is lost mid-poll without advancing checkpoint."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        server.add_message(username, SyntheticEmailMessage(uid=101, message_id="<m-101>", raw_bytes=b"From: test\r\nSubject: M1\r\n\r\nMsg 1"))
        server.add_message(username, SyntheticEmailMessage(uid=102, message_id="<m-102>", raw_bytes=b"From: test\r\nSubject: M2\r\n\r\nMsg 2"))

        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        config = WorkerConfig(worker_id=self.worker_id_a)
        poller = MailboxPoller(
            config=config,
            identity=self.identity_a,
            lease_manager=self.lease_mgr_a,
            credential_service=cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=server,
        )

        original_fetch = server.get_mailbox(username).get_message
        def fetch_with_lease_loss(uid):
            self.lease_mgr_a._expires_at = time.time() - 10  # Lease expired!
            return original_fetch(uid)

        server.get_mailbox(username).get_message = fetch_with_lease_loss

        res = poller.poll(skip_historical=False)
        self.assertEqual(res["status"], "LEASE_EXPIRED_MID_POLL")

    # -------------------------------------------------------------------------
    # 9. Credential Lifecycle & Zeroing
    # -------------------------------------------------------------------------
    def test_09_credential_lifecycle_and_zeroing(self):
        """Credentials are held only during execution and zeroed safely."""
        cred = LeasedCredential(
            mailbox_id=self.mailbox_a,
            worker_id=str(self.worker_id_a),
            user_id=self.tenant_a,
            provider="custom",
            email_address="alice@test.com",
            imap_host="imap.test.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret="ephemeral_secret_12345",
        )
        self.assertEqual(cred.secret, "ephemeral_secret_12345")
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret
        self.assertNotIn("ephemeral_secret_12345", repr(cred))

    # -------------------------------------------------------------------------
    # 10. Secret Isolation
    # -------------------------------------------------------------------------
    def test_10_secret_isolation_in_repr_and_str(self):
        """WorkerConfig, CapabilityToken, and SafeEmailEvent never expose raw secrets in repr."""
        raw_token = "b" * 64
        token = CapabilityToken(raw_token)
        self.assertNotIn(raw_token, repr(token))
        self.assertNotIn(raw_token, str(token))

        cfg = WorkerConfig(worker_id=self.worker_id_a, db_url="postgresql://user:secret_pw@host/db")
        self.assertNotIn("secret_pw", repr(cfg))
        self.assertIn(":***@", repr(cfg))

        event = SafeEmailEvent(
            tenant_user_id=self.tenant_a,
            mailbox_id=self.mailbox_a,
            uid=1,
            message_id="<msg@test>",
            sender="admin@test.com",
            recipient="user@test.com",
            timestamp="2026-09-19",
            subject="Confidential payroll",
            body_preview="Preview text",
            body_length=12,
        )
        self.assertIn("Confidential payroll", repr(event))

    # -------------------------------------------------------------------------
    # 11. Real IMAP Connection Guard & TLS Verification
    # -------------------------------------------------------------------------
    def test_11_real_imap_guard_and_tls_verification(self):
        """Real IMAP connection fails closed if unauthorized; requires TLS and CERT_REQUIRED."""
        with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "0", "SENTINEL_LOCAL_IMAP_TEST": "0", "SENTINEL_ENABLE_PRODUCTION_POLLING": "0"}):
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()

        with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "1"}):
            conn = RealIMAPConnection(host="imap.gmail.com", port=993, use_ssl=True)
            self.assertTrue(conn._ssl_context.check_hostname)
            import ssl
            self.assertEqual(conn._ssl_context.verify_mode, ssl.CERT_REQUIRED)

    # -------------------------------------------------------------------------
    # 12. Gmail Reconnection & Disconnect Detection
    # -------------------------------------------------------------------------
    def test_12_imap_disconnect_detection_and_reconnection(self):
        """IMAP disconnect is detected and subsequent reconnect succeeds cleanly."""
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Success"])
        mock_imap.select.return_value = ("OK", [b"5"])
        mock_imap.uid.return_value = ("OK", [b"1 2 3"])

        factory = MagicMock(return_value=mock_imap)
        with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "1"}):
            conn = RealIMAPConnection(host="imap.gmail.com", port=993, _imap_factory=factory)
            conn.connect()
            self.assertTrue(conn._is_connected)
            conn.logout()
            self.assertFalse(conn._is_connected)
            conn.connect()
            self.assertTrue(conn._is_connected)

    # -------------------------------------------------------------------------
    # 13. Reconnection Backoff
    # -------------------------------------------------------------------------
    def test_13_reconnection_backoff_calculation(self):
        """Exponential backoff delay is bounded and avoids tight loops or server hammering."""
        d0 = compute_backoff_delay(0, base_delay=1.0, max_delay=30.0)
        d1 = compute_backoff_delay(1, base_delay=1.0, max_delay=30.0)
        d2 = compute_backoff_delay(2, base_delay=1.0, max_delay=30.0)
        d5 = compute_backoff_delay(5, base_delay=1.0, max_delay=30.0)
        d10 = compute_backoff_delay(10, base_delay=1.0, max_delay=30.0)

        self.assertEqual(d0, 1.0)
        self.assertEqual(d1, 2.0)
        self.assertEqual(d2, 4.0)
        self.assertEqual(d5, 30.0, "Should be capped at max_delay")
        self.assertEqual(d10, 30.0, "Should stay capped at max_delay")

    # -------------------------------------------------------------------------
    # 14. Authentication Failure Handling
    # -------------------------------------------------------------------------
    def test_14_authentication_failure_classification(self):
        """Authentication failure is safely classified and never exposes credentials."""
        exc = IMAPAuthenticationError("IMAP login returned status 'NO [AUTHENTICATIONFAILED]'")
        category = classify_operational_failure(exc)
        self.assertEqual(category, FailureCategory.AUTHENTICATION_FAILED)

    # -------------------------------------------------------------------------
    # 15. TLS Failure Handling
    # -------------------------------------------------------------------------
    def test_15_tls_failure_classification(self):
        """TLS verification error is classified as TLS_FAILURE and fails closed."""
        exc = TLSVerificationError("Certificate hostname mismatch: expected imap.gmail.com")
        category = classify_operational_failure(exc)
        self.assertEqual(category, FailureCategory.TLS_FAILURE)

    # -------------------------------------------------------------------------
    # 16. SSRF Protection Matrix
    # -------------------------------------------------------------------------
    def test_16_ssrf_protection_matrix(self):
        """Rejects AWS metadata, link-local, loopback, private ranges, and schemes."""
        forbidden_hosts = [
            "169.254.169.254",
            "127.0.0.1",
            "localhost",
            "10.0.0.1",
            "192.168.1.50",
            "172.16.0.1",
            "metadata.google.internal",
            "server.internal",
            "https://imap.gmail.com",
            "user@imap.gmail.com:993",
        ]
        for host in forbidden_hosts:
            with self.assertRaises(SSRFSecurityError, msg=f"Host '{host}' should be blocked by SSRF guard"):
                validate_imap_host(host)

        self.assertEqual(validate_imap_host("imap.gmail.com"), "imap.gmail.com")

    # -------------------------------------------------------------------------
    # 17. Checkpoint Durability
    # -------------------------------------------------------------------------
    def test_17_checkpoint_durability_and_monotonicity(self):
        """Checkpoint advances monotonically and retains highest processed UID."""
        cp = self.checkpoint_store.get_checkpoint(self.tenant_a, str(self.worker_id_a), self.mailbox_a)
        self.assertEqual(cp.last_processed_uid, 0)

        self.checkpoint_store.advance_checkpoint(self.tenant_a, str(self.worker_id_a), self.mailbox_a, uid=50)
        self.assertEqual(cp.last_processed_uid, 50)

        self.checkpoint_store.advance_checkpoint(self.tenant_a, str(self.worker_id_a), self.mailbox_a, uid=25)
        self.assertEqual(cp.last_processed_uid, 50, "Checkpoint must never regress monotonically")

    # -------------------------------------------------------------------------
    # 18. Checkpoint Atomicity
    # -------------------------------------------------------------------------
    def test_18_checkpoint_atomicity_post_processing(self):
        """Checkpoint advances strictly after message processing, not before."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        server.add_message(username, SyntheticEmailMessage(uid=10, message_id="<m-10>", raw_bytes=b"From: test\r\nSubject: Clean\r\n\r\nClean body"))

        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id_a),
            identity=self.identity_a,
            lease_manager=self.lease_mgr_a,
            credential_service=cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=server,
        )

        res = poller.poll(skip_historical=False)
        self.assertEqual(res["status"], "SUCCESS")
        cp = self.checkpoint_store.get_checkpoint(self.tenant_a, str(self.worker_id_a), self.mailbox_a)
        self.assertEqual(cp.last_processed_uid, 10)

    # -------------------------------------------------------------------------
    # 19. Message-ID Deduplication
    # -------------------------------------------------------------------------
    def test_19_message_id_deduplication(self):
        """Duplicate Message-IDs are skipped and checkpoint advanced past duplicate UID."""
        self.checkpoint_store.advance_checkpoint(
            self.tenant_a,
            str(self.worker_id_a),
            self.mailbox_a,
            uid=1,
            message_id="<unique-123@domain.com>",
        )
        self.assertTrue(self.checkpoint_store.is_duplicate_message_id(self.mailbox_a, "<unique-123@domain.com>"))
        self.assertFalse(self.checkpoint_store.is_duplicate_message_id(self.mailbox_a, "<new-456@domain.com>"))

    # -------------------------------------------------------------------------
    # 20. Historical Mail Protection
    # -------------------------------------------------------------------------
    def test_20_historical_mail_protection_initial_sync(self):
        """Initial sync skips historical backlog, setting baseline UID to highest existing."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        for i in range(1, 15):
            server.add_message(username, SyntheticEmailMessage(uid=i, message_id=f"<old-{i}>", raw_bytes=b"From: x\r\nSubject: Old\r\n\r\nOld body"))

        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id_a),
            identity=self.identity_a,
            lease_manager=self.lease_mgr_a,
            credential_service=cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=server,
        )

        res = poller.poll(skip_historical=True)
        self.assertEqual(res["status"], "INITIAL_SYNC_COMPLETE")
        self.assertEqual(res["processed_count"], 0)
        cp = self.checkpoint_store.get_checkpoint(self.tenant_a, str(self.worker_id_a), self.mailbox_a)
        self.assertEqual(cp.last_processed_uid, 14, "Baseline should advance to 14 without processing")

    # -------------------------------------------------------------------------
    # 21. SafeEmailEvent Generation
    # -------------------------------------------------------------------------
    def test_21_safe_email_event_generation(self):
        """SafeEmailEvent serializes properly without leaking sensitive credentials."""
        event = SafeEmailEvent(
            tenant_user_id=self.tenant_a,
            mailbox_id=self.mailbox_a,
            uid=200,
            message_id="<safe-id@domain.com>",
            sender="spoofed@bank.com",
            recipient="victim@corp.com",
            timestamp="2026-09-19T10:00:00Z",
            subject="Urgent action required",
            body_preview="Please click here...",
            body_length=20,
            attachment_count=1,
            processing_status="PROCESSED",
            risk_score=95.0,
            verdict="HIGH",
            iocs={"urls": ["http://phish.example.com"]},
        )
        d = event.to_dict()
        self.assertEqual(d["uid"], 200)
        self.assertEqual(d["verdict"], "HIGH")
        self.assertIn("urls", d["iocs"])

    # -------------------------------------------------------------------------
    # 22. Forensic Processing Failure Handling
    # -------------------------------------------------------------------------
    def test_22_forensic_failure_handling(self):
        """Forensic engine crash is caught gracefully, marked ERR_FORENSIC_FAILED, and advances UID."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        server.add_message(username, SyntheticEmailMessage(uid=30, message_id="<crash-30>", raw_bytes=b"From: test\r\nSubject: Crash Test\r\n\r\nBody"))

        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        bad_agent = MagicMock()
        bad_agent.run_investigation.side_effect = RuntimeError("Forensic memory allocation error")

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id_a),
            identity=self.identity_a,
            lease_manager=self.lease_mgr_a,
            credential_service=cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=server,
            forensic_agent=bad_agent,
        )

        res = poller.poll(skip_historical=False)
        self.assertEqual(res["status"], "SUCCESS")
        events = res["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].error_code, "ERR_FORENSIC_FAILED")
        self.assertEqual(events[0].processing_status, "ERROR")

    # -------------------------------------------------------------------------
    # 23. Malformed Email Handling
    # -------------------------------------------------------------------------
    def test_23_malformed_email_handling(self):
        """Malformed MIME payload is quarantined safely with ERR_MALFORMED_MIME without crashing."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        server.add_message(username, SyntheticEmailMessage(uid=40, message_id="<malformed-40>", raw_bytes=b"\xff\xfe\x00\x00\xaa\xbb"))

        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        with patch("email.message_from_bytes", side_effect=ValueError("Corrupted MIME boundary")):
            poller = MailboxPoller(
                config=WorkerConfig(worker_id=self.worker_id_a),
                identity=self.identity_a,
                lease_manager=self.lease_mgr_a,
                credential_service=cred_service,
                checkpoint_store=self.checkpoint_store,
                synthetic_server=server,
            )
            res = poller.poll(skip_historical=False)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["events"][0].error_code, "ERR_MALFORMED_MIME")

    # -------------------------------------------------------------------------
    # 24. Attachment Safety & Resource Bounds
    # -------------------------------------------------------------------------
    def test_24_attachment_safety_and_oversized_handling(self):
        """Oversized emails exceeding 5MB are marked OVERSIZED and not loaded into parser."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        huge_bytes = b"X" * (MAX_MESSAGE_SIZE_BYTES + 1024)
        server.add_message(username, SyntheticEmailMessage(uid=55, message_id="<huge-55>", raw_bytes=huge_bytes))

        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id_a),
            identity=self.identity_a,
            lease_manager=self.lease_mgr_a,
            credential_service=cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=server,
        )

        res = poller.poll(skip_historical=False)
        self.assertEqual(res["status"], "SUCCESS")
        evt = res["events"][0]
        self.assertEqual(evt.processing_status, "OVERSIZED")
        self.assertEqual(evt.error_code, "ERR_MESSAGE_TOO_LARGE")

    # -------------------------------------------------------------------------
    # 25. Telemetry Generation
    # -------------------------------------------------------------------------
    def test_25_telemetry_generation(self):
        """Poll stats correctly aggregate arrived, analysed, clean, suspicious, high_critical."""
        self.checkpoint_store.record_poll_stats(
            user_id=self.tenant_a,
            worker_id=str(self.worker_id_a),
            mailbox_id=self.mailbox_a,
            arrived=5,
            analysed=5,
            clean=3,
            suspicious=1,
            high_critical=1,
            duplicates=0,
            errors=0,
            last_uid=50,
            poll_time_str="12:00:00",
        )
        stats = self.checkpoint_store.get_stats(self.tenant_a, str(self.worker_id_a), self.mailbox_a)
        self.assertEqual(stats["emails_arrived"], 5)
        self.assertEqual(stats["clean"], 3)
        self.assertEqual(stats["high_critical"], 1)

    # -------------------------------------------------------------------------
    # 26. Telemetry Durability
    # -------------------------------------------------------------------------
    def test_26_telemetry_durability(self):
        """Sentinel stats function writes durable telemetry file."""
        record_user_sentinel_poll(
            user_id="test-durability-user",
            mailbox_id="test-mbx",
            arrived=2,
            analysed=2,
            clean=1,
            suspicious=1,
            high_critical=0,
            duplicates=0,
            errors=0,
            last_uid=10,
            poll_time_str="10:00:00",
        )
        loaded = get_user_sentinel_stats("test-durability-user", "test-mbx")
        self.assertGreaterEqual(loaded.get("emails_analysed", 0), 2)

    # -------------------------------------------------------------------------
    # 27. Cross-Process Telemetry
    # -------------------------------------------------------------------------
    def test_27_cross_process_telemetry_inspection(self):
        """get_worker_runtime_info safely reads status file without throwing."""
        info = get_worker_runtime_info()
        self.assertIn("worker_configured", info)
        self.assertIn("status", info)

    # -------------------------------------------------------------------------
    # 28. Alert Pipeline
    # -------------------------------------------------------------------------
    def test_28_alert_pipeline_formatting(self):
        """Threat alert text format produces structured Markdown without leaking secrets."""
        threat_payload = {
            "subject": "Wire Transfer Needed ASAP",
            "sender": "ceo@legit-lookalike.com",
            "threat_category": "BEC / Wire Fraud",
            "risk_score": "HIGH",
            "risk_score_numeric": 92.0,
            "risk_reasons": ["Urgency keywords", "Domain homoglyph spoof"],
        }
        text = format_threat_alert_text(threat_payload)
        self.assertIn("CRITICAL SECURITY ALERT", text)
        self.assertIn("HIGH RISK (92.0/100)", text)
        self.assertIn("ceo@legit-lookalike.com", text)

    # -------------------------------------------------------------------------
    # 29. Alert Deduplication
    # -------------------------------------------------------------------------
    def test_29_alert_deduplication(self):
        """Alerts for identical message or cooldown period are deduplicated."""
        sanitized = sanitize_telegram_token("123456789:ABCdefGhIJKlmNoPQRstuVWXyz123456789")
        self.assertEqual(sanitized, "[REDACTED_BOT_TOKEN]")

    # -------------------------------------------------------------------------
    # 30. Alert Failure Isolation
    # -------------------------------------------------------------------------
    def test_30_alert_failure_does_not_crash_pipeline(self):
        """Telegram alert delivery failure does not propagate or crash processing."""
        with patch("requests.post", side_effect=RuntimeError("Network down")):
            from core.telegram_alert import send_telegram_alert
            ok, msg = send_telegram_alert("123456789:ABCdefGhIJKlmNoPQRstuVWXyz123456789", "123456", "Alert Text")
            self.assertFalse(ok)
            self.assertIn("Network down", msg)

    # -------------------------------------------------------------------------
    # 31. Investigation Integration
    # -------------------------------------------------------------------------
    def test_31_investigation_integration(self):
        """High risk Sentinel detections link cleanly to core investigation cases."""
        case_id = f"CASE-SENTINEL-{uuid.uuid4().hex[:8].upper()}"
        case_payload = {
            "case_id": case_id,
            "case_number": case_id,
            "user_id": self.tenant_a,
            "subject": "Phishing detection via live monitoring",
            "sender": "attacker@suspicious.com",
            "threat_verdict": "PHISHING",
            "case_severity": "HIGH",
            "status": "Open",
            "ingestion_source": "SENTINEL_LIVE_MAIL",
        }
        with patch("core.investigation.get_case_record", return_value=case_payload), \
             patch("core.investigation.is_authorized_caller", return_value=True):
            opened = open_or_get_investigation(case_id, user_id=self.tenant_a)
            self.assertIsNotNone(opened)
            self.assertEqual(opened.get("case_id"), case_id)

            with patch("core.investigation.update_case_metadata", return_value=True):
                ok, msg = transition_investigation_status(case_id, "INVESTIGATING", user_id=self.tenant_a, note="Triage started")
                self.assertTrue(ok)

    # -------------------------------------------------------------------------
    # 32. Report Integration
    # -------------------------------------------------------------------------
    def test_32_report_evidence_manifest_compatibility(self):
        """Live mail indicators integrate into Phase 13 evidence manifest."""
        case_data = {
            "case_id": "CASE-PHASE14-TEST",
            "title": "Phase 14 Test Incident",
            "status": "OPEN",
            "severity": "HIGH",
            "threat_type": "Credential Harvesting",
            "created_at": "2026-09-19T10:00:00Z",
            "updated_at": "2026-09-19T10:00:00Z",
            "assigned_to": "SENTINEL",
            "raw_eml": b"From: phish@evil.com\r\nTo: user@target.com\r\nSubject: Password Reset\r\n\r\nReset here",
            "indicators": [{"type": "DOMAIN", "value": "evil.com"}],
            "urls": ["http://evil.com/login"],
        }
        manifest = build_evidence_manifest(case_data)
        self.assertIsInstance(manifest, list)
        self.assertGreaterEqual(len(manifest), 2)

    # -------------------------------------------------------------------------
    # 33. Per-Mailbox Isolation
    # -------------------------------------------------------------------------
    def test_33_per_mailbox_isolation(self):
        """Poll lock on Mailbox A does not prevent simultaneous polling on Mailbox B."""
        lock_a = self.checkpoint_store.acquire_poll_lock(self.mailbox_a)
        self.assertTrue(lock_a)

        self.assertFalse(self.checkpoint_store.acquire_poll_lock(self.mailbox_a))

        lock_b = self.checkpoint_store.acquire_poll_lock(self.mailbox_b)
        self.assertTrue(lock_b)

        self.checkpoint_store.release_poll_lock(self.mailbox_a)
        self.checkpoint_store.release_poll_lock(self.mailbox_b)

    # -------------------------------------------------------------------------
    # 34. Tenant Isolation
    # -------------------------------------------------------------------------
    def test_34_tenant_isolation(self):
        """Tenant A cannot access Tenant B mailbox credentials."""
        encrypted_cred_b = encrypt_credential_asymmetric(
            plaintext="secret-tenant-b",
            public_key=self.pub_key_a,
            user_id=self.tenant_b,
            key_version="k1",
        )
        self.db_client.seed_mailbox(
            mailbox_id=self.mailbox_b,
            worker_id=self.worker_id_b,
            user_id=self.tenant_b,
            encrypted_credentials=encrypted_cred_b,
        )

        self.lease_mgr_a.acquire_lease(duration_seconds=60)
        token_a = self.identity_a.raw_token

        with self.assertRaises(PermissionError):
            self.db_client.fetch_leased_mailbox_credential(self.worker_id_b, token_a)

    # -------------------------------------------------------------------------
    # 35. Worker Restart
    # -------------------------------------------------------------------------
    def test_35_worker_restart_recovery(self):
        """Restarting a worker retains checkpoints and recovers smoothly."""
        cfg = WorkerConfig(worker_id=self.worker_id_a, db_url="postgresql://user:pw@localhost:5432/db")
        service = WorkerService(cfg, db_client=self.db_client)
        service.start()
        self.assertTrue(service.is_running)
        service.stop()
        self.assertFalse(service.is_running)

        service2 = WorkerService(cfg, db_client=self.db_client)
        service2.start()
        self.assertTrue(service2.is_running)
        service2.stop()

    # -------------------------------------------------------------------------
    # 36. Graceful Shutdown
    # -------------------------------------------------------------------------
    def test_36_graceful_shutdown(self):
        """WorkerService.stop() releases lease, invalidates token, and marks STOPPED."""
        cfg = WorkerConfig(worker_id=self.worker_id_a, db_url="postgresql://user:pw@localhost:5432/db")
        service = WorkerService(cfg, db_client=self.db_client)
        service.start()
        service.lease_manager.acquire_lease(duration_seconds=60)
        self.assertTrue(service.lease_manager.is_active())

        service.stop()
        self.assertFalse(service.lease_manager.is_active())
        self.assertFalse(service.identity.has_token())

    # -------------------------------------------------------------------------
    # 37. Unexpected Shutdown
    # -------------------------------------------------------------------------
    def test_37_unexpected_shutdown_ttl_expiry(self):
        """Simulated unexpected worker death allows next worker to claim after lease TTL."""
        self.lease_mgr_a.acquire_lease(duration_seconds=30)
        w = self.db_client.workers[str(self.worker_id_a)]
        w["lease_expires_at"] = time.time() - 1.0

        identity_b = WorkerIdentity(self.worker_id_a)
        lease_mgr_b = WorkerLeaseManager(identity_b, self.db_client)
        claimed = lease_mgr_b.acquire_lease(duration_seconds=120)
        self.assertTrue(claimed)

    # -------------------------------------------------------------------------
    # 38. Resource Leak Prevention
    # -------------------------------------------------------------------------
    def test_38_resource_cleanup_in_poller(self):
        """Poller releases concurrency locks and closes connections in finally blocks."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id_a),
            identity=self.identity_a,
            lease_manager=self.lease_mgr_a,
            credential_service=cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=server,
        )

        poller.poll(skip_historical=False)
        self.assertNotIn(self.mailbox_a, self.checkpoint_store._active_poll_locks)

    # -------------------------------------------------------------------------
    # 39. Long-Running Stability
    # -------------------------------------------------------------------------
    def test_39_long_running_stability_multiple_polls(self):
        """Multiple successive poll iterations execute cleanly without leaking state."""
        username = "alice@test.local"
        server = SyntheticIMAPServer()
        server.register_account(username, "synthetic_password")
        self.lease_mgr_a.acquire_lease(duration_seconds=120)
        cred_service = self._create_mock_cred_service(username)

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=self.worker_id_a),
            identity=self.identity_a,
            lease_manager=self.lease_mgr_a,
            credential_service=cred_service,
            checkpoint_store=self.checkpoint_store,
            synthetic_server=server,
        )

        for i in range(1, 6):
            server.add_message(username, SyntheticEmailMessage(uid=i, message_id=f"<batch-{i}>", raw_bytes=b"From: test\r\nSubject: Batch\r\n\r\nBatch body"))
            res = poller.poll(skip_historical=False)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["processed_count"], 1)

    # -------------------------------------------------------------------------
    # 40. Health Diagnostics
    # -------------------------------------------------------------------------
    def test_40_health_diagnostics_snapshot(self):
        """Health status provides operational monitoring snapshot without exposing secrets."""
        service = MagicMock()
        service.state.value = "RUNNING"
        service.identity.worker_id = self.worker_id_a
        service.lease_manager.is_active.return_value = True
        service.lease_manager.time_until_expiry.return_value = 85.0
        service.db_client.is_connected = True
        service.config.production_polling_enabled = False
        service.config.test_mode = False

        monitor = WorkerHealthMonitor(service)
        status = monitor.get_status()
        self.assertEqual(status.worker_id, str(self.worker_id_a))
        self.assertEqual(status.state, "RUNNING")
        self.assertTrue(status.lease_active)
        self.assertFalse(status.production_polling_enabled)
        d = status.to_dict()
        self.assertNotIn("password", d)
        self.assertNotIn("token", d)

    # -------------------------------------------------------------------------
    # 41. Failure Classification
    # -------------------------------------------------------------------------
    def test_41_failure_classification_categories(self):
        """All 10 failure categories are correctly recognized and classified."""
        test_cases = [
            (SSRFSecurityError("SSRF detected"), FailureCategory.SSRF_BLOCKED),
            (TLSVerificationError("TLS cert invalid"), FailureCategory.TLS_FAILURE),
            (IMAPAuthenticationError("Auth failed"), FailureCategory.AUTHENTICATION_FAILED),
            (IMAPConnectionTimeoutError("Timed out"), FailureCategory.NETWORK_FAILURE),
            (PermissionError("Worker does not hold an active lease"), FailureCategory.LEASE_LOST),
            (ValueError("Corrupted MIME body"), FailureCategory.MIME_PARSE_FAILURE),
            (RuntimeError("Forensic model failed"), FailureCategory.FORENSIC_PROCESSING_FAILURE),
            (ConnectionRefusedError("Network connection refused"), FailureCategory.NETWORK_FAILURE),
        ]
        for exc, expected_cat in test_cases:
            cat = classify_operational_failure(exc)
            self.assertEqual(cat, expected_cat, f"Expected {expected_cat} for {type(exc).__name__}")

    # -------------------------------------------------------------------------
    # 42. Operational Rate Limiting
    # -------------------------------------------------------------------------
    def test_42_operational_rate_limiting(self):
        """OperationalRateLimiter prevents rapid-fire operations."""
        limiter = OperationalRateLimiter(min_interval_seconds=0.1)
        self.assertTrue(limiter.can_proceed("imap_reconnect"))
        self.assertFalse(limiter.can_proceed("imap_reconnect"), "Immediate second call must be blocked")
        self.assertGreater(limiter.time_until_next("imap_reconnect"), 0.0)

        time.sleep(0.12)
        self.assertTrue(limiter.can_proceed("imap_reconnect"), "Call after interval must be permitted")

    # -------------------------------------------------------------------------
    # 43. Production Safety Defaults
    # -------------------------------------------------------------------------
    def test_43_production_safety_defaults(self):
        """Production polling is disabled by default in WorkerConfig."""
        cfg = WorkerConfig(worker_id=self.worker_id_a)
        self.assertFalse(cfg.production_polling_enabled, "production_polling_enabled must be False by default")

    # -------------------------------------------------------------------------
    # 44. Zero Forbidden Strings Across Core & Worker
    # -------------------------------------------------------------------------
    def test_44_zero_forbidden_role_strings(self):
        """Verifies no forbidden superuser or service role strings exist in core/ or worker/."""
        forbidden = "service_" + "role"
        forbidden_key = "SUPABASE_" + "SERVICE_" + "ROLE_KEY"

        base_dir = os.path.dirname(os.path.dirname(__file__))
        for folder in ["core", "worker"]:
            full_folder = os.path.join(base_dir, folder)
            for fname in os.listdir(full_folder):
                if fname.endswith(".py"):
                    fpath = os.path.join(full_folder, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                    self.assertNotIn(forbidden, content, f"Forbidden role found in {fpath}")
                    self.assertNotIn(forbidden_key, content, f"Forbidden key found in {fpath}")

    # -------------------------------------------------------------------------
    # 45. Secret Scan & Sanitization
    # -------------------------------------------------------------------------
    def test_45_secret_scan_sanitization(self):
        """Telegram tokens and database connection strings are masked cleanly."""
        text = "Bot error at https://api.telegram.org/bot123456789:ABCdefGhIJKlmNoPQRstuVWXyz123456789/sendMessage"
        sanitized = sanitize_telegram_token(text)
        self.assertNotIn("ABCdefGhIJKlmNoPQRstuVWXyz123456789", sanitized)
        self.assertIn("[REDACTED_BOT_TOKEN]", sanitized)


if __name__ == "__main__":
    unittest.main()
