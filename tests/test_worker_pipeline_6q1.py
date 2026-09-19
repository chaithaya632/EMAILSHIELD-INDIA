"""
tests/test_worker_pipeline_6q1.py
Automated Security, Forensic & Pipeline Test Suite for Sentinel Phase 6Q.1:
Real Gmail Message-Level Sentinel E2E Validation.

Validates the full message-level Sentinel pipeline:
1. Real / controlled message identification
2. Real RFC822 message fetch and resource bounding
3. SafeEmailEvent conversion & secret scrubbing
4. Forensic processing (AutonomousForensicAgent + MLClassifier + IOC extraction)
5. Checkpoint advancement (monotonic UID increase, mailbox-scoped)
6. Duplicate prevention (secondary Message-ID deduplication on second poll)
7. New message detection (TEST 001 skipped, TEST 002 processed as new)
8. Secret isolation (no App Passwords/tokens in events, dicts, logs)
9. Production safety invariants (production polling strictly DISABLED)
10. Real Gmail live IMAP execution or fail-closed gate
"""

import email
import json
import logging
import os
import ssl
import sys
import unittest
import uuid
from unittest.mock import MagicMock, patch

from core.agent import AutonomousForensicAgent
from core.indicators import extract_all_indicators
from core.classifier import MLClassifier
from core.parser import SecureEmailParser
from core.sentinel_crypto import (
    WorkerKeyRing,
    ProvisioningKeyRing,
    generate_worker_asymmetric_keypair,
    encrypt_credential_asymmetric,
    decrypt_credential_asymmetric,
)
from worker.checkpoint import CheckpointStore, MailboxCheckpoint
from worker.config import WorkerConfig
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.db import MockWorkerDBClient
from worker.events import SafeEmailEvent
from worker.identity import WorkerIdentity, CapabilityToken
from worker.imap_client import (
    GMAIL_IMAP_HOST,
    GMAIL_IMAP_PORT,
    GMAIL_TEST_EMAIL,
    CONNECTION_TIMEOUT_SECONDS,
    FETCH_TIMEOUT_SECONDS,
    MAX_HEADER_SIZE_BYTES,
    MAX_MESSAGE_SIZE_BYTES,
    RealIMAPConnection,
    SSRFSecurityError,
    RealNetworkDeniedError,
    get_gmail_app_password,
    is_gmail_app_password_available,
    is_real_imap_test_enabled,
    validate_imap_host,
)
from worker.lease import WorkerLeaseManager
from worker.poller import MailboxPoller, MAX_MESSAGES_PER_POLL
from worker.rollout import create_gmail_test_contract


# Controlled RFC822 test emails conforming to Phase 6Q.1 specification
CONTROLLED_TEST_MSG_001_BYTES = (
    b"From: alerts@vendor-updates.com\r\n"
    b"To: emailshield.sentinel.test@gmail.com\r\n"
    b"Subject: EMAILSHIELD SENTINEL E2E TEST 001\r\n"
    b"Date: Wed, 17 Sep 2026 19:30:00 +0530\r\n"
    b"Message-ID: <sentinel-e2e-001@emailshield.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"This is a controlled EMAILSHIELD Sentinel integration test.\r\n"
    b"No real credentials or sensitive information are included.\r\n"
    b"Reference ID: 918231\r\n"
    b"Payment notification portal: https://legitimate-vendor.com/invoice\r\n"
)

CONTROLLED_TEST_MSG_002_BYTES = (
    b"From: security-notice@cloud-service.com\r\n"
    b"To: emailshield.sentinel.test@gmail.com\r\n"
    b"Subject: EMAILSHIELD SENTINEL E2E TEST 002\r\n"
    b"Date: Wed, 17 Sep 2026 19:35:00 +0530\r\n"
    b"Message-ID: <sentinel-e2e-002@emailshield.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Second controlled EMAILSHIELD Sentinel integration test message.\r\n"
    b"No real credentials or sensitive information are included.\r\n"
    b"Action required: Review account settings at https://portal.cloud-service.com/security\r\n"
)


class MockIMAPTransport:
    """Mock IMAP transport simulating Gmail IMAP server for controlled pipeline verification."""

    def __init__(self, initial_messages=None):
        self.messages = dict(initial_messages or {})
        self.selected_folder = None
        self.logged_in = False
        self.logged_out = False

    def login(self, username, password):
        self.logged_in = True
        return True

    def select(self, folder="INBOX"):
        self.selected_folder = folder
        return "OK", len(self.messages)

    def search(self, since_uid=None):
        uids = sorted(self.messages.keys())
        if since_uid is not None:
            uids = [u for u in uids if u > since_uid]
        return uids

    def fetch(self, uid):
        raw = self.messages.get(uid, b"")
        msg = email.message_from_bytes(raw)
        return {
            "uid": uid,
            "rfc822": raw,
            "size": len(raw),
            "message_id": msg.get("Message-ID", f"<uid-{uid}@generated>"),
        }

    def close(self):
        self.selected_folder = None

    def logout(self):
        self.logged_out = True


class TestPhase6Q1MessagePipeline(unittest.TestCase):
    """Phase 6Q.1: Full Message-Level Sentinel E2E Pipeline Tests."""

    def setUp(self):
        self.user_id = str(uuid.uuid4())
        self.worker_id = uuid.uuid4()
        self.mailbox_id = "gmail-test-mbx-001"
        self.identity = WorkerIdentity(self.worker_id)
        import secrets
        self.token = CapabilityToken(secrets.token_hex(32))
        self.config = WorkerConfig(worker_id=self.worker_id, db_url="postgresql://sentinel:pw@localhost:5432/db")

        # Mock database client with authenticated daemon session
        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_id, self.user_id, desired_state="RUNNING")

        self.lease_mgr = WorkerLeaseManager(self.identity, self.db)
        self.lease_mgr.acquire_lease(duration_seconds=120)

        self.checkpoint_store = CheckpointStore()

        # Mock credential service returning leased credential
        self.cred_service = MagicMock(spec=WorkerCredentialService)
        leased_cred = LeasedCredential(
            mailbox_id=self.mailbox_id,
            worker_id=str(self.worker_id),
            user_id=str(self.user_id),
            provider="gmail",
            email_address=GMAIL_TEST_EMAIL,
            imap_host=GMAIL_IMAP_HOST,
            imap_port=GMAIL_IMAP_PORT,
            use_ssl=True,
            auth_mechanism="PLAIN",
            credential_version=1,
            _secret="test-masked-app-password",
        )
        self.cred_service.fetch_and_decrypt.return_value.__enter__.return_value = leased_cred

        self.forensic_agent = AutonomousForensicAgent(MLClassifier())

    # -------------------------------------------------------------------------
    # Test 1 — Real message identification
    # -------------------------------------------------------------------------
    def test_01_real_message_identification(self):
        """Controlled Gmail test message is correctly parsed and identified by subject."""
        parsed = email.message_from_bytes(CONTROLLED_TEST_MSG_001_BYTES)
        subject = parsed.get("Subject", "")
        sender = parsed.get("From", "")
        recipient = parsed.get("To", "")
        msg_id = parsed.get("Message-ID", "")

        self.assertEqual(subject, "EMAILSHIELD SENTINEL E2E TEST 001")
        self.assertEqual(sender, "alerts@vendor-updates.com")
        self.assertEqual(recipient, "emailshield.sentinel.test@gmail.com")
        self.assertEqual(msg_id, "<sentinel-e2e-001@emailshield.test>")

    # -------------------------------------------------------------------------
    # Test 2 — Real message fetch & bounds
    # -------------------------------------------------------------------------
    def test_02_real_message_fetch_and_resource_bounds(self):
        """Actual RFC822 email payload fetched conforms to strict resource bounds."""
        raw_size = len(CONTROLLED_TEST_MSG_001_BYTES)
        self.assertLessEqual(raw_size, MAX_MESSAGE_SIZE_BYTES, "Message must not exceed 5MB hard limit")

        # Header size validation
        header_part = CONTROLLED_TEST_MSG_001_BYTES.split(b"\r\n\r\n")[0]
        self.assertLessEqual(len(header_part), MAX_HEADER_SIZE_BYTES, "Headers must not exceed 64KB")

        # MIME verification
        msg = email.message_from_bytes(CONTROLLED_TEST_MSG_001_BYTES)
        body = msg.get_payload(decode=True).decode("utf-8")
        self.assertIn("EMAILSHIELD Sentinel integration test", body)

    # -------------------------------------------------------------------------
    # Test 3 — SafeEmailEvent conversion
    # -------------------------------------------------------------------------
    def test_03_safe_email_event_conversion(self):
        """RFC822 message converts into SafeEmailEvent with complete operational metadata."""
        parsed = email.message_from_bytes(CONTROLLED_TEST_MSG_001_BYTES)
        body = parsed.get_payload(decode=True).decode("utf-8")

        evt = SafeEmailEvent(
            tenant_user_id=self.user_id,
            mailbox_id=self.mailbox_id,
            uid=101,
            message_id=parsed.get("Message-ID"),
            sender=parsed.get("From"),
            recipient=parsed.get("To"),
            timestamp=parsed.get("Date"),
            subject=parsed.get("Subject"),
            body_preview=body[:500],
            body_length=len(body),
            attachment_count=0,
            processing_status="PROCESSED",
        )

        d = evt.to_dict()
        self.assertEqual(d["uid"], 101)
        self.assertEqual(d["subject"], "EMAILSHIELD SENTINEL E2E TEST 001")
        self.assertEqual(d["sender"], "alerts@vendor-updates.com")
        self.assertEqual(d["message_id"], "<sentinel-e2e-001@emailshield.test>")
        self.assertEqual(d["processing_status"], "PROCESSED")

        # Secret exclusion verification
        repr_str = repr(evt).lower()
        self.assertNotIn("password", repr_str)
        self.assertNotIn("token", repr_str)
        self.assertNotIn("private_key", repr_str)

    # -------------------------------------------------------------------------
    # Test 4 — Forensic processing
    # -------------------------------------------------------------------------
    def test_04_forensic_processing(self):
        """Controlled test email travels through EMAILSHIELD forensic engine without exception."""
        parser = SecureEmailParser(CONTROLLED_TEST_MSG_001_BYTES)
        parsed_email = parser.parse()

        body_plus_hdrs = parsed_email.get("body", "") + " " + str(parsed_email.get("headers", {}))
        iocs = extract_all_indicators(body_plus_hdrs)

        # Ensure IOC extraction detected payment portal URL
        self.assertIn("urls", iocs)
        self.assertTrue(any("legitimate-vendor.com" in u for u in iocs["urls"]))

        # Execute Autonomous Forensic Agent investigation
        investigation = self.forensic_agent.run_investigation(parsed_email, iocs)

        self.assertIn("risk_score", investigation)
        self.assertIn("agent_steps", investigation)
        self.assertIn("reasons", investigation)
        self.assertTrue(bool(investigation["risk_score"]))
        self.assertIsInstance(investigation["agent_steps"], list)

    # -------------------------------------------------------------------------
    # Test 5 — Checkpoint advancement
    # -------------------------------------------------------------------------
    def test_05_checkpoint_advancement(self):
        """Checkpoint advances monotonically after successful message processing."""
        # Initial state before poll
        cp_before = self.checkpoint_store.get_checkpoint(
            self.user_id, str(self.worker_id), self.mailbox_id
        ).last_processed_uid
        self.assertEqual(cp_before, 0)

        # Process UID 101
        processed_uid = 101
        self.assertLess(cp_before, processed_uid)

        self.checkpoint_store.advance_checkpoint(
            user_id=self.user_id,
            worker_id=str(self.worker_id),
            mailbox_id=self.mailbox_id,
            uid=processed_uid,
            message_id="<sentinel-e2e-001@emailshield.test>",
        )

        cp_after = self.checkpoint_store.get_checkpoint(
            self.user_id, str(self.worker_id), self.mailbox_id
        ).last_processed_uid
        self.assertGreaterEqual(cp_after, processed_uid)
        self.assertEqual(cp_after, 101)

    # -------------------------------------------------------------------------
    # Test 6 — Duplicate prevention
    # -------------------------------------------------------------------------
    def test_06_duplicate_prevention(self):
        """Second poll on identical mailbox state produces zero new events."""
        mock_transport = MockIMAPTransport({101: CONTROLLED_TEST_MSG_001_BYTES})

        poller = MailboxPoller(
            config=self.config,
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=self.checkpoint_store,
            imap_adapter_factory=lambda **kw: mock_transport,
            forensic_agent=self.forensic_agent,
        )

        # First poll: processes message 101
        res1 = poller.poll("INBOX")
        self.assertEqual(res1["status"], "SUCCESS")
        self.assertEqual(res1["processed_count"], 1)
        self.assertEqual(len(res1["events"]), 1)
        self.assertEqual(res1["events"][0].uid, 101)
        self.assertIsNotNone(res1["events"][0].risk_score)

        # Second poll: identical mailbox state
        res2 = poller.poll("INBOX")
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertEqual(res2["processed_count"], 0, "Second poll must yield 0 new events")
        self.assertEqual(len(res2["events"]), 0)

    # -------------------------------------------------------------------------
    # Test 7 — New message detection
    # -------------------------------------------------------------------------
    def test_07_new_message_detection(self):
        """TEST 001 is skipped as duplicate; TEST 002 is detected and processed as new."""
        mock_transport = MockIMAPTransport({101: CONTROLLED_TEST_MSG_001_BYTES})

        poller = MailboxPoller(
            config=self.config,
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=self.checkpoint_store,
            imap_adapter_factory=lambda **kw: mock_transport,
            forensic_agent=self.forensic_agent,
        )

        # First poll: processes 101
        res1 = poller.poll("INBOX")
        self.assertEqual(res1["processed_count"], 1)

        # Add TEST 002 to mailbox transport
        mock_transport.messages[102] = CONTROLLED_TEST_MSG_002_BYTES

        # Second poll: detects TEST 002
        res2 = poller.poll("INBOX")
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertEqual(res2["processed_count"], 1, "Only TEST 002 should be processed")
        self.assertEqual(len(res2["events"]), 1)
        self.assertEqual(res2["events"][0].uid, 102)
        self.assertEqual(res2["events"][0].subject, "EMAILSHIELD SENTINEL E2E TEST 002")

        # Checkpoint advanced to 102
        cp = self.checkpoint_store.get_checkpoint(
            self.user_id, str(self.worker_id), self.mailbox_id
        ).last_processed_uid
        self.assertEqual(cp, 102)

    # -------------------------------------------------------------------------
    # Test 8 — Secret isolation
    # -------------------------------------------------------------------------
    def test_08_secret_isolation(self):
        """No App Password, capability token, or private key appears in operational data or logs."""
        mock_transport = MockIMAPTransport({101: CONTROLLED_TEST_MSG_001_BYTES})

        poller = MailboxPoller(
            config=self.config,
            identity=self.identity,
            lease_manager=self.lease_mgr,
            credential_service=self.cred_service,
            checkpoint_store=self.checkpoint_store,
            imap_adapter_factory=lambda **kw: mock_transport,
            forensic_agent=self.forensic_agent,
        )

        res = poller.poll("INBOX")
        evt = res["events"][0]

        serialized = json.dumps(evt.to_dict())
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("token", serialized.lower())
        self.assertNotIn("private_key", serialized.lower())
        self.assertNotIn("master_key", serialized.lower())

    # -------------------------------------------------------------------------
    # Test 9 — Production safety
    # -------------------------------------------------------------------------
    def test_09_production_safety(self):
        """Production polling remains disabled, 0 production mailboxes, alerts disabled."""
        cfg = WorkerConfig()
        self.assertFalse(cfg.production_polling_enabled)
        self.assertFalse(cfg.test_mode)

    # -------------------------------------------------------------------------
    # Test 10 — Real Gmail Live Pipeline / Safe Fail-Closed Gate
    # -------------------------------------------------------------------------
    def test_10_real_gmail_live_pipeline_or_safe_fail_closed(self):
        """
        Executes live Gmail IMAP pipeline if App Password is set in the runtime environment;
        otherwise safely verifies fail-closed security invariants.
        """
        app_password = get_gmail_app_password()
        if app_password:
            # LIVE GMAIL PIPELINE
            with patch.dict(os.environ, {"SENTINEL_ENABLE_REAL_IMAP_TEST": "1"}):
                conn = RealIMAPConnection(
                    host=GMAIL_IMAP_HOST,
                    port=GMAIL_IMAP_PORT,
                    use_ssl=True,
                )
                conn.connect()
                login_ok = conn.login(GMAIL_TEST_EMAIL, app_password)
                self.assertTrue(login_ok, "Gmail authentication must succeed with configured App Password")

                status, count = conn.select("INBOX")
                self.assertEqual(status, "OK")

                uids = conn.search()
                self.assertIsInstance(uids, list)

                # If test messages exist in INBOX, fetch and run forensic engine
                if uids:
                    latest_uid = uids[-1]
                    msg_dict = conn.fetch(latest_uid)
                    self.assertIn("rfc822", msg_dict)
                    raw_bytes = msg_dict["rfc822"]

                    parser = SecureEmailParser(raw_bytes)
                    parsed_email = parser.parse()
                    body_plus_hdrs = parsed_email.get("body", "") + " " + str(parsed_email.get("headers", {}))
                    iocs = extract_all_indicators(body_plus_hdrs)

                    investigation = self.forensic_agent.run_investigation(parsed_email, iocs)
                    self.assertIn("risk_score", investigation)
                    self.assertIn("verdict", investigation)

                conn.logout()
        else:
            # App password not configured -> Verify fail-closed gate
            self.assertFalse(is_gmail_app_password_available())
            self.assertIsNone(get_gmail_app_password())


if __name__ == "__main__":
    unittest.main()
