"""
tests/test_real_imap_security.py
Comprehensive security verification for Real IMAP Poller Integration:
- Bounded UID discovery and fetch
- Monotonic checkpoint advancement
- Message-ID deduplication across polling runs
- Lease enforcement (unleased, expired, mid-poll loss)
- Oversized message (>5MB) handling
- Malformed MIME handling
- Tenant isolation (Worker A vs Worker B)
- Streamlit isolation (Streamlit does not import imap_client or imaplib)
- Safe logging (zero secrets, passwords, tokens, or private keys in logs)
"""

import io
import json
import logging
import os
import sys
import unittest
import uuid
from unittest.mock import MagicMock, patch

from core.sentinel_crypto import generate_worker_asymmetric_keypair, WorkerKeyRing, ProvisioningKeyRing
from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.db import MockWorkerDBClient
from worker.lease import WorkerLeaseManager
from worker.credentials import WorkerCredentialService
from worker.checkpoint import CheckpointStore
from worker.poller import MailboxPoller, MAX_MESSAGES_PER_POLL, MAX_MESSAGE_SIZE_BYTES
from worker.imap_client import RealIMAPConnection, GUARD_ENV_VAR
from worker.logging import SafeLoggingFilter


def make_raw_email(uid: int, message_id: str, subject: str = "Test Subject", body: str = "Test Body") -> bytes:
    """Helper to construct raw RFC822 bytes for testing."""
    return (
        f"From: sender-{uid}@example.com\r\n"
        f"To: recipient-{uid}@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: {message_id}\r\n"
        f"Date: Thu, 17 Sep 2026 12:00:00 +0000\r\n"
        f"\r\n"
        f"{body}"
    ).encode("utf-8")


class TestRealIMAPSecurity(unittest.TestCase):
    """Security verification for real IMAP poller operations and boundaries."""

    @classmethod
    def setUpClass(cls):
        cls.priv_a, cls.pub_a = generate_worker_asymmetric_keypair(2048)
        cls.priv_b, cls.pub_b = generate_worker_asymmetric_keypair(2048)

        cls.user_a = uuid.uuid4()
        cls.user_b = uuid.uuid4()
        cls.worker_a = uuid.uuid4()
        cls.worker_b = uuid.uuid4()
        cls.mailbox_a = uuid.uuid4()
        cls.mailbox_b = uuid.uuid4()

        cls.user_a_email = "user-a@example.com"
        cls.user_b_email = "user-b@example.com"
        cls.pw_a = "secret_pass_a"
        cls.pw_b = "secret_pass_b"

        # Encrypt envelopes for A and B
        cls.prov_a = ProvisioningKeyRing("k1", {"k1": cls.pub_a})
        cls.prov_b = ProvisioningKeyRing("k1", {"k1": cls.pub_b})

        cls.envelope_a = cls.prov_a.encrypt(
            json.dumps({"username": cls.user_a_email, "password": cls.pw_a, "imap_host": "imap.example.com", "imap_port": 993}),
            user_id=str(cls.user_a)
        )
        cls.envelope_b = cls.prov_b.encrypt(
            json.dumps({"username": cls.user_b_email, "password": cls.pw_b, "imap_host": "imap.example.com", "imap_port": 993}),
            user_id=str(cls.user_b)
        )

    def setUp(self):
        # Enable guard for tests with mocked sockets
        self._orig_guard = os.environ.get(GUARD_ENV_VAR)
        os.environ[GUARD_ENV_VAR] = "1"

        self.db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        self.db.seed_worker(self.worker_a, self.user_a, desired_state="RUNNING")
        self.db.seed_worker(self.worker_b, self.user_b, desired_state="RUNNING")

        self.db.seed_mailbox(self.mailbox_a, self.worker_a, self.user_a, encrypted_credentials=self.envelope_a, credential_version=1)
        self.db.seed_mailbox(self.mailbox_b, self.worker_b, self.user_b, encrypted_credentials=self.envelope_b, credential_version=1)

        self.identity_a = WorkerIdentity(self.worker_a)
        self.identity_b = WorkerIdentity(self.worker_b)

        self.lease_a = WorkerLeaseManager(self.identity_a, self.db)
        self.lease_b = WorkerLeaseManager(self.identity_b, self.db)

        self.keyring_a = WorkerKeyRing("k1", {"k1": self.priv_a})
        self.keyring_b = WorkerKeyRing("k1", {"k1": self.priv_b})

        self.cred_a = WorkerCredentialService(self.identity_a, self.keyring_a, self.db)
        self.cred_b = WorkerCredentialService(self.identity_b, self.keyring_b, self.db)

        self.checkpoint_store = CheckpointStore()

    def tearDown(self):
        if self._orig_guard is not None:
            os.environ[GUARD_ENV_VAR] = self._orig_guard
        else:
            os.environ.pop(GUARD_ENV_VAR, None)

    def _create_mock_imap(self, messages_dict):
        """Creates a mock IMAP server returning specified messages by UID."""
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"LOGIN completed"])
        mock_imap.select.return_value = ("OK", [str(len(messages_dict)).encode()])

        def mock_uid_cmd(cmd, *args):
            if cmd == "SEARCH":
                criteria = args[1] if len(args) > 1 else "ALL"
                if criteria == "ALL":
                    uids = sorted(messages_dict.keys())
                elif criteria.startswith("UID "):
                    since_val = int(criteria.split()[1].split(":")[0])
                    uids = sorted([u for u in messages_dict.keys() if u >= since_val])
                else:
                    uids = sorted(messages_dict.keys())
                raw_uids_str = " ".join(str(u) for u in uids).encode()
                return ("OK", [raw_uids_str])

            elif cmd == "FETCH":
                uid = int(args[0])
                raw = messages_dict.get(uid, b"")
                return ("OK", [(f"{uid} (BODY.PEEK[] {{{len(raw)}}}".encode(), raw)])
            return ("OK", [b""])

        mock_imap.uid.side_effect = mock_uid_cmd
        return mock_imap

    # =========================================================================
    # 1. BOUNDED DISCOVERY & CHECKPOINT ADVANCEMENT
    # =========================================================================

    def test_01_bounded_discovery_and_checkpoint_advancement(self):
        """Poller processes new messages in ascending UID order and advances checkpoint."""
        self.lease_a.acquire_lease(duration_seconds=120)

        # 3 test messages
        messages = {
            1: make_raw_email(1, "<msg-1@example.com>", "Subject 1"),
            2: make_raw_email(2, "<msg-2@example.com>", "Subject 2"),
            3: make_raw_email(3, "<msg-3@example.com>", "Subject 3"),
        }
        mock_imap = self._create_mock_imap(messages)

        def mock_adapter_factory(host, port, use_ssl):
            return RealIMAPConnection(
                host=host, port=port, use_ssl=use_ssl,
                _imap_factory=lambda *a, **kw: mock_imap
            )

        poller = MailboxPoller(
            WorkerConfig(worker_id=self.worker_a),
            self.identity_a,
            self.lease_a,
            self.cred_a,
            self.checkpoint_store,
            imap_adapter_factory=mock_adapter_factory
        )

        res = poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["processed_count"], 3)
        self.assertEqual([e.uid for e in res["events"]], [1, 2, 3])

        # Checkpoint should be at UID 3
        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_a), str(self.worker_a), str(self.mailbox_a)
        )
        self.assertEqual(cp.last_processed_uid, 3)

        # Second poll: no new messages
        res2 = poller.poll()
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertEqual(res2["processed_count"], 0)

    # =========================================================================
    # 2. MESSAGE-ID DEDUPLICATION
    # =========================================================================

    def test_02_message_id_deduplication(self):
        """Duplicate Message-ID under different UID is skipped without emitting duplicate event."""
        self.lease_a.acquire_lease(duration_seconds=120)

        # UID 1 and UID 2 share identical Message-ID
        shared_mid = "<duplicate-mid@example.com>"
        messages = {
            1: make_raw_email(1, shared_mid, "First Arrival"),
            2: make_raw_email(2, shared_mid, "Second Arrival with Same MID"),
        }
        mock_imap = self._create_mock_imap(messages)

        def mock_adapter_factory(host, port, use_ssl):
            return RealIMAPConnection(
                host=host, port=port, use_ssl=use_ssl,
                _imap_factory=lambda *a, **kw: mock_imap
            )

        poller = MailboxPoller(
            WorkerConfig(worker_id=self.worker_a),
            self.identity_a,
            self.lease_a,
            self.cred_a,
            self.checkpoint_store,
            imap_adapter_factory=mock_adapter_factory
        )

        res = poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        # Only 1 unique event generated, but checkpoint advances to UID 2
        self.assertEqual(res["processed_count"], 1)
        self.assertEqual(res["events"][0].uid, 1)

        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_a), str(self.worker_a), str(self.mailbox_a)
        )
        self.assertEqual(cp.last_processed_uid, 2)

    # =========================================================================
    # 3. LEASE ENFORCEMENT & MID-POLL LOSS
    # =========================================================================

    def test_03_lease_enforcement_and_mid_poll_expiry(self):
        """Unleased polling is denied; mid-poll lease loss halts checkpoint advancement."""
        messages = {
            1: make_raw_email(1, "<msg-1@example.com>"),
            2: make_raw_email(2, "<msg-2@example.com>"),
            3: make_raw_email(3, "<msg-3@example.com>"),
        }
        mock_imap = self._create_mock_imap(messages)

        def mock_adapter_factory(host, port, use_ssl):
            return RealIMAPConnection(
                host=host, port=port, use_ssl=use_ssl,
                _imap_factory=lambda *a, **kw: mock_imap
            )

        poller = MailboxPoller(
            WorkerConfig(worker_id=self.worker_a),
            self.identity_a,
            self.lease_a,
            self.cred_a,
            self.checkpoint_store,
            imap_adapter_factory=mock_adapter_factory
        )

        # Unleased poll rejected
        with self.assertRaises(PermissionError):
            poller.poll()

        # Acquire lease
        self.lease_a.acquire_lease(duration_seconds=120)

        # Expire lease when UID 2 is fetched
        orig_fetch = mock_imap.uid
        def expiring_fetch(cmd, *args):
            if cmd == "FETCH" and args[0] == "2":
                self.lease_a._expires_at = 0.0
            return orig_fetch(cmd, *args)

        mock_imap.uid = expiring_fetch

        res = poller.poll()
        self.assertEqual(res["status"], "LEASE_EXPIRED_MID_POLL")
        self.assertEqual(res["processed_count"], 1)

        # Checkpoint remains at 1; did NOT advance for UID 2 or 3
        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_a), str(self.worker_a), str(self.mailbox_a)
        )
        self.assertEqual(cp.last_processed_uid, 1)

    # =========================================================================
    # 4. OVERSIZED & MALFORMED MESSAGES
    # =========================================================================

    def test_04_oversized_and_malformed_messages(self):
        """Oversized (>5MB) and malformed MIME emails are handled safely without crashing."""
        self.lease_a.acquire_lease(duration_seconds=120)

        oversized_payload = b"X" * (MAX_MESSAGE_SIZE_BYTES + 1024)
        malformed_payload = b"Not a valid MIME email \xff\xfe\x00\x01 binary garbage"

        messages = {
            1: oversized_payload,
            2: malformed_payload,
            3: make_raw_email(3, "<msg-valid@example.com>", "Normal Email"),
        }
        mock_imap = self._create_mock_imap(messages)

        def mock_adapter_factory(host, port, use_ssl):
            return RealIMAPConnection(
                host=host, port=port, use_ssl=use_ssl,
                _imap_factory=lambda *a, **kw: mock_imap
            )

        poller = MailboxPoller(
            WorkerConfig(worker_id=self.worker_a),
            self.identity_a,
            self.lease_a,
            self.cred_a,
            self.checkpoint_store,
            imap_adapter_factory=mock_adapter_factory
        )

        res = poller.poll()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["processed_count"], 3)

        # Verify oversized event
        evt_over = res["events"][0]
        self.assertEqual(evt_over.processing_status, "OVERSIZED")
        self.assertEqual(evt_over.error_code, "ERR_MESSAGE_TOO_LARGE")

        # Verify malformed event safely handled
        evt_mal = res["events"][1]
        self.assertIn(evt_mal.processing_status, ("PROCESSED", "ERROR"))

        # Verify normal event
        evt_norm = res["events"][2]
        self.assertEqual(evt_norm.processing_status, "PROCESSED")

        # Checkpoint safely at UID 3
        cp = self.checkpoint_store.get_checkpoint(
            str(self.user_a), str(self.worker_a), str(self.mailbox_a)
        )
        self.assertEqual(cp.last_processed_uid, 3)

    # =========================================================================
    # 5. TENANT ISOLATION
    # =========================================================================

    def test_05_tenant_isolation_enforced(self):
        """Worker A cannot poll Mailbox B (RPC rejects credential fetch)."""
        self.lease_a.acquire_lease(duration_seconds=120)
        self.lease_b.acquire_lease(duration_seconds=120)

        # Worker A tries to poll forged Mailbox B
        self.db.mailboxes[str(self.mailbox_a)]["worker_id"] = None
        self.db.mailboxes[str(self.mailbox_b)]["worker_id"] = str(self.worker_a)

        mock_imap = MagicMock()
        def mock_adapter_factory(host, port, use_ssl):
            return RealIMAPConnection(
                host=host, port=port, use_ssl=use_ssl,
                _imap_factory=lambda *a, **kw: mock_imap
            )

        cross_poller = MailboxPoller(
            WorkerConfig(worker_id=self.worker_a),
            self.identity_a,
            self.lease_a,
            self.cred_a,
            self.checkpoint_store,
            imap_adapter_factory=mock_adapter_factory
        )

        with self.assertRaises(PermissionError):
            cross_poller.poll()

    # =========================================================================
    # 6. STREAMLIT ISOLATION
    # =========================================================================

    def test_06_streamlit_does_not_import_imap_client(self):
        """Verifies Streamlit app files do not import worker.imap_client or imaplib."""
        import glob
        app_files = glob.glob("app/**/*.py", recursive=True) + glob.glob("streamlit_app.py")
        for fpath in app_files:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.assertNotIn("worker.imap_client", content, f"{fpath} must not import worker.imap_client")
            self.assertNotIn("imaplib", content, f"{fpath} must not import imaplib")

    # =========================================================================
    # 7. LOGGING SECURITY
    # =========================================================================

    def test_07_safe_logging_zero_secrets(self):
        """Polling logs contain zero passwords, tokens, or private keys."""
        self.lease_a.acquire_lease(duration_seconds=120)

        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] [%(levelname)s] %(message)s"))
        handler.addFilter(SafeLoggingFilter())

        imap_logger = logging.getLogger("sentinel.worker.imap")
        poller_logger = logging.getLogger("sentinel.worker.poller")
        cred_logger = logging.getLogger("sentinel.worker.credentials")

        imap_logger.addHandler(handler)
        poller_logger.addHandler(handler)
        cred_logger.addHandler(handler)
        imap_logger.setLevel(logging.DEBUG)
        poller_logger.setLevel(logging.DEBUG)
        cred_logger.setLevel(logging.DEBUG)

        messages = {
            1: make_raw_email(1, "<msg-log@example.com>", "Subject Log", "Secret body text")
        }
        mock_imap = self._create_mock_imap(messages)

        def mock_adapter_factory(host, port, use_ssl):
            return RealIMAPConnection(
                host=host, port=port, use_ssl=use_ssl,
                _imap_factory=lambda *a, **kw: mock_imap
            )

        poller = MailboxPoller(
            WorkerConfig(worker_id=self.worker_a),
            self.identity_a,
            self.lease_a,
            self.cred_a,
            self.checkpoint_store,
            imap_adapter_factory=mock_adapter_factory
        )

        try:
            poller.poll()
            log_output = log_stream.getvalue()

            # Ensure secrets are never logged
            self.assertNotIn(self.pw_a, log_output)
            self.assertNotIn(self.identity_a.raw_token, log_output)
            self.assertNotIn("BEGIN" + " RSA PRIVATE KEY", log_output)
        finally:
            imap_logger.removeHandler(handler)
            poller_logger.removeHandler(handler)
            cred_logger.removeHandler(handler)
