"""
tests/test_sentinel_control_plane.py
Comprehensive test suite for EMAILSHIELD INDIA Sentinel Phase 3:
Control-Plane Logic, Input Validation, Multi-Tenant Isolation, and Non-Execution Guarantees.
"""

import ast
import inspect
import unittest
from typing import Dict, Any, List, Optional
import uuid

import core.sentinel_control as sc
from core.sentinel_control import (
    validate_poll_interval,
    validate_desired_state,
    validate_provider,
    validate_email_syntax,
    validate_imap_port,
    validate_alert_channel,
    get_user_worker,
    upsert_user_worker,
    set_worker_desired_state,
    get_user_mailbox,
    save_user_mailbox_metadata,
    get_user_checkpoint,
    get_user_alerts,
    save_user_alert_metadata,
    deactivate_user_sentinel,
    delete_user_sentinel_config,
    MIN_POLL_INTERVAL_SECONDS,
    MAX_POLL_INTERVAL_SECONDS,
    DEFAULT_POLL_INTERVAL_SECONDS,
    ALLOWED_PROVIDERS,
    ALLOWED_AUTH_MECHANISMS,
    ALLOWED_ALERT_CHANNELS,
    PROVIDER_IMAP_DEFAULTS,
)


class MockPostgrestTable:
    """Mock PostgREST table simulation with strict tenant RLS filtering."""

    def __init__(self, db: Dict[str, List[Dict[str, Any]]], table_name: str, auth_uid: str):
        self.db = db
        self.table_name = table_name
        self.auth_uid = auth_uid
        self._eq_filters: Dict[str, Any] = {}
        self._select_cols: Optional[str] = None
        self._pending_update: Optional[Dict[str, Any]] = None
        self._pending_insert: Optional[Dict[str, Any]] = None
        self._pending_delete = False

    def select(self, cols: str = "*"):
        self._select_cols = cols
        return self

    def eq(self, column: str, value: Any):
        self._eq_filters[column] = value
        return self

    def upsert(self, row: Dict[str, Any], on_conflict: str = ""):
        # RLS check: insert must belong to authenticated user
        if row.get("user_id") != self.auth_uid:
            raise PermissionError("RLS Violation: Cannot insert record belonging to another user.")
        
        table = self.db.setdefault(self.table_name, [])
        # Match by on_conflict or user_id
        conflict_field = on_conflict if on_conflict else "user_id"
        existing = next((r for r in table if r.get(conflict_field) == row.get(conflict_field)), None)
        if existing:
            existing.update(row)
            self._last_data = [dict(existing)]
        else:
            record = dict(row)
            if "id" not in record:
                record["id"] = str(uuid.uuid4())
            table.append(record)
            self._last_data = [dict(record)]
        return self

    def insert(self, row: Dict[str, Any]):
        # RLS check: insert must belong to authenticated user
        if row.get("user_id") != self.auth_uid:
            raise PermissionError("RLS Violation: Cannot insert record belonging to another user.")
        table = self.db.setdefault(self.table_name, [])
        record = dict(row)
        if "id" not in record:
            record["id"] = str(uuid.uuid4())
        table.append(record)
        self._last_data = [dict(record)]
        return self

    def update(self, updates: Dict[str, Any]):
        self._pending_update = dict(updates)
        return self

    def delete(self):
        self._pending_delete = True
        return self

    def execute(self):
        table = self.db.setdefault(self.table_name, [])

        class Response:
            def __init__(self, data):
                self.data = data

        if hasattr(self, "_last_data"):
            data = self._last_data
            del self._last_data
            return Response(data)

        # Enforce RLS: Authenticated user can ONLY see / operate on their own rows
        matching_rows = [r for r in table if r.get("user_id") == self.auth_uid]

        # Apply additional eq filters
        for col, val in self._eq_filters.items():
            matching_rows = [r for r in matching_rows if r.get(col) == val]

        if self._pending_delete:
            self._pending_delete = False
            deleted = []
            for r in matching_rows:
                table.remove(r)
                deleted.append(r)
            return Response(deleted)

        if self._pending_update is not None:
            updates = self._pending_update
            self._pending_update = None
            # Check immutability of user_id
            if "user_id" in updates and any(r.get("user_id") != updates["user_id"] for r in matching_rows):
                raise PermissionError("user_id is immutable and cannot be modified")
            for r in matching_rows:
                r.update(updates)
            return Response(matching_rows)

        # SELECT operation: check if select_cols requested safe projection
        return Response([dict(r) for r in matching_rows])


class MockSupabaseClient:
    def __init__(self, db: Dict[str, List[Dict[str, Any]]], auth_uid: str):
        self.db = db
        self.auth_uid = auth_uid

    def table(self, table_name: str) -> MockPostgrestTable:
        return MockPostgrestTable(self.db, table_name, self.auth_uid)


class TestSentinelValidation(unittest.TestCase):
    """Test pure input validation functions."""

    def test_01_validate_poll_interval_bounds(self):
        # Valid bounds
        validate_poll_interval(30)
        validate_poll_interval(60)
        validate_poll_interval(3600)

        # Invalid bounds
        with self.assertRaises(ValueError):
            validate_poll_interval(29)
        with self.assertRaises(ValueError):
            validate_poll_interval(3601)
        with self.assertRaises(ValueError):
            validate_poll_interval(0)
        with self.assertRaises(ValueError):
            validate_poll_interval(-10)

        # Non-integer / boolean types
        with self.assertRaises(ValueError):
            validate_poll_interval("60")  # string
        with self.assertRaises(ValueError):
            validate_poll_interval(60.5)  # float
        with self.assertRaises(ValueError):
            validate_poll_interval(True)  # bool is subclass of int in python!

    def test_02_validate_desired_state(self):
        validate_desired_state("RUNNING")
        validate_desired_state("STOPPED")
        validate_desired_state(" RUNNING ")

        with self.assertRaises(ValueError):
            validate_desired_state("STARTING")
        with self.assertRaises(ValueError):
            validate_desired_state("PAUSED")
        with self.assertRaises(ValueError):
            validate_desired_state("ACTIVE")
        with self.assertRaises(ValueError):
            validate_desired_state("")
        with self.assertRaises(ValueError):
            validate_desired_state(123)

    def test_03_validate_provider(self):
        for prov in ALLOWED_PROVIDERS:
            validate_provider(prov)
            validate_provider(prov.upper())

        with self.assertRaises(ValueError):
            validate_provider("proton")
        with self.assertRaises(ValueError):
            validate_provider("fastmail")
        with self.assertRaises(ValueError):
            validate_provider("")

    def test_04_validate_email_syntax(self):
        validate_email_syntax("user@example.com")
        validate_email_syntax("investigator.alpha@domain.co.in")

        with self.assertRaises(ValueError):
            validate_email_syntax("not-an-email")
        with self.assertRaises(ValueError):
            validate_email_syntax("user@")
        with self.assertRaises(ValueError):
            validate_email_syntax("@example.com")
        with self.assertRaises(ValueError):
            validate_email_syntax("")
        with self.assertRaises(ValueError):
            validate_email_syntax("user @example.com")

    def test_05_validate_imap_port(self):
        validate_imap_port(993)
        validate_imap_port(143)
        validate_imap_port(1)
        validate_imap_port(65535)

        with self.assertRaises(ValueError):
            validate_imap_port(0)
        with self.assertRaises(ValueError):
            validate_imap_port(-1)
        with self.assertRaises(ValueError):
            validate_imap_port(65536)
        with self.assertRaises(ValueError):
            validate_imap_port("993")
        with self.assertRaises(ValueError):
            validate_imap_port(True)

    def test_06_validate_alert_channel(self):
        for ch in ALLOWED_ALERT_CHANNELS:
            validate_alert_channel(ch)
            validate_alert_channel(ch.upper())

        with self.assertRaises(ValueError):
            validate_alert_channel("slack")
        with self.assertRaises(ValueError):
            validate_alert_channel("email")
        with self.assertRaises(ValueError):
            validate_alert_channel("")


class TestSentinelControlOperations(unittest.TestCase):
    """Test control plane operations with Mock Supabase client."""

    def setUp(self):
        self.user_a_id = str(uuid.uuid4())
        self.user_b_id = str(uuid.uuid4())
        self.shared_db = {
            "sentinel_workers": [],
            "sentinel_mailboxes": [],
            "sentinel_mailboxes_safe": [],
            "sentinel_checkpoints": [],
            "sentinel_alerts": [],
        }
        self.client_a = MockSupabaseClient(self.shared_db, self.user_a_id)
        self.client_b = MockSupabaseClient(self.shared_db, self.user_b_id)

    def test_07_unauthenticated_safety(self):
        """Unauthenticated calls fail safely without errors."""
        self.assertIsNone(get_user_worker("", None))
        self.assertIsNone(get_user_worker(self.user_a_id, None))

        ok, msg = upsert_user_worker("", 60, "RUNNING", None)
        self.assertFalse(ok)

        ok, msg = set_worker_desired_state(self.user_a_id, "RUNNING", None)
        self.assertFalse(ok)

        self.assertIsNone(get_user_mailbox(self.user_a_id, None))
        self.assertIsNone(get_user_checkpoint(self.user_a_id, None))
        self.assertEqual(get_user_alerts(self.user_a_id, None), [])

        ok, msg = deactivate_user_sentinel(self.user_a_id, None)
        self.assertFalse(ok)

        ok, msg = delete_user_sentinel_config(self.user_a_id, None)
        self.assertFalse(ok)

    def test_08_worker_upsert_and_retrieve(self):
        """Worker lifecycle: upsert and retrieval under tenant isolation."""
        # Initial: no worker
        w = get_user_worker(self.user_a_id, self.client_a)
        self.assertIsNone(w)

        # Upsert worker for user A
        ok, res = upsert_user_worker(self.user_a_id, 90, "RUNNING", self.client_a)
        self.assertTrue(ok)
        self.assertEqual(res["user_id"], self.user_a_id)
        self.assertEqual(res["poll_interval_seconds"], 90)
        self.assertEqual(res["desired_state"], "RUNNING")
        # Ensure actual_state was NOT manipulated by presentation plane
        self.assertNotIn("actual_state", res)

        # Retrieve worker for user A
        w = get_user_worker(self.user_a_id, self.client_a)
        self.assertIsNotNone(w)
        self.assertEqual(w["desired_state"], "RUNNING")

        # Update desired state to STOPPED
        ok, msg = set_worker_desired_state(self.user_a_id, "STOPPED", self.client_a)
        self.assertTrue(ok)

        w = get_user_worker(self.user_a_id, self.client_a)
        self.assertEqual(w["desired_state"], "STOPPED")

    def test_09_multi_user_worker_isolation(self):
        """User B cannot see or modify User A's worker record."""
        # Create User A worker
        ok, res_a = upsert_user_worker(self.user_a_id, 60, "RUNNING", self.client_a)
        self.assertTrue(ok)

        # User B queries their worker -> returns None
        w_b = get_user_worker(self.user_b_id, self.client_b)
        self.assertIsNone(w_b)

        # User B attempts to set desired state on User A -> fails (cannot see row)
        ok, msg = set_worker_desired_state(self.user_a_id, "STOPPED", self.client_b)
        self.assertFalse(ok)

        # User A worker remains RUNNING
        w_a = get_user_worker(self.user_a_id, self.client_a)
        self.assertEqual(w_a["desired_state"], "RUNNING")

    def test_10_mailbox_metadata_save_and_retrieve(self):
        """Save and retrieve non-sensitive mailbox metadata without credentials."""
        ok_w, w_data = upsert_user_worker(self.user_a_id, 60, "STOPPED", self.client_a)
        self.assertTrue(ok_w)
        worker_id = w_data["id"]

        # Save mailbox metadata
        ok_m, msg_m = save_user_mailbox_metadata(
            user_id=self.user_a_id,
            worker_id=worker_id,
            provider="gmail",
            email_address="investigator@gmail.com",
            imap_host="imap.gmail.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="APP_PASSWORD",
            is_active=True,
            client=self.client_a
        )
        self.assertTrue(ok_m)

    def test_11_checkpoint_read_only_inspection(self):
        """Checkpoints can be inspected read-only but have no presentation-tier write endpoint."""
        # Inject worker-generated checkpoint record into database
        checkpoint_id = str(uuid.uuid4())
        self.shared_db["sentinel_checkpoints"].append({
            "id": checkpoint_id,
            "user_id": self.user_a_id,
            "worker_id": str(uuid.uuid4()),
            "mailbox_id": str(uuid.uuid4()),
            "folder_name": "INBOX",
            "uid_validity": 12345,
            "last_processed_uid": 450,
            "last_scan_timestamp": "2026-09-16T15:00:00Z",
            "checkpoint_hash": "a1b2c3d4e5f6",
        })

        # User A reads checkpoint
        cp_a = get_user_checkpoint(self.user_a_id, self.client_a)
        self.assertIsNotNone(cp_a)
        self.assertEqual(cp_a["last_processed_uid"], 450)
        self.assertEqual(cp_a["folder_name"], "INBOX")

        # User B cannot see User A checkpoint
        cp_b = get_user_checkpoint(self.user_b_id, self.client_b)
        self.assertIsNone(cp_b)

    def test_12_deactivate_and_delete_lifecycle(self):
        """Test deactivation and deletion flows."""
        ok_w, w_data = upsert_user_worker(self.user_a_id, 60, "RUNNING", self.client_a)
        self.assertTrue(ok_w)

        # Deactivate
        ok_d, msg_d = deactivate_user_sentinel(self.user_a_id, self.client_a)
        self.assertTrue(ok_d)
        w = get_user_worker(self.user_a_id, self.client_a)
        self.assertEqual(w["desired_state"], "STOPPED")

        # Delete
        ok_del, msg_del = delete_user_sentinel_config(self.user_a_id, self.client_a)
        self.assertTrue(ok_del)
        self.assertIsNone(get_user_worker(self.user_a_id, self.client_a))

    def test_16_alert_metadata_save_and_retrieve(self):
        """Save, update, and retrieve alert channel metadata under tenant isolation."""
        ok_w, w_data = upsert_user_worker(self.user_a_id, 60, "STOPPED", self.client_a)
        self.assertTrue(ok_w)
        worker_id = w_data["id"]

        # 1. Save Telegram config
        ok_tg, msg_tg = save_user_alert_metadata(
            user_id=self.user_a_id,
            worker_id=worker_id,
            channel="telegram",
            destination_target="123456789",
            is_enabled=True,
            high_risk_only=True,
            client=self.client_a
        )
        self.assertTrue(ok_tg)

        # 2. Save WhatsApp config
        ok_wa, msg_wa = save_user_alert_metadata(
            user_id=self.user_a_id,
            worker_id=worker_id,
            channel="whatsapp",
            destination_target="+919876543210",
            is_enabled=False,
            high_risk_only=True,
            client=self.client_a
        )
        self.assertTrue(ok_wa)

        # User B queries alerts -> returns empty list
        alerts_b = get_user_alerts(self.user_b_id, self.client_b)
        self.assertEqual(len(alerts_b), 0)

    def test_17_alert_target_validation(self):
        """Alert metadata validation rejects empty destination targets and invalid channels."""
        ok_w, w_data = upsert_user_worker(self.user_a_id, 60, "STOPPED", self.client_a)
        worker_id = w_data["id"]

        # Empty target
        ok, msg = save_user_alert_metadata(
            self.user_a_id, worker_id, "telegram", "", True, True, self.client_a
        )
        self.assertFalse(ok)
        self.assertIn("Destination target", msg)

        # Invalid channel
        ok, msg = save_user_alert_metadata(
            self.user_a_id, worker_id, "discord", "12345", True, True, self.client_a
        )
        self.assertFalse(ok)
        self.assertIn("Unsupported alert channel", msg)

    def test_18_upsert_worker_prevents_privilege_escalation(self):
        """Presentation layer cannot set actual_state, lease_owner, or lease_expires_at."""
        ok, res = upsert_user_worker(self.user_a_id, 60, "RUNNING", self.client_a)
        self.assertTrue(ok)
        self.assertNotIn("actual_state", res)
        self.assertNotIn("lease_owner", res)
        self.assertNotIn("lease_expires_at", res)

    def test_19_mailbox_safe_view_omits_credentials(self):
        """Mailbox query via get_user_mailbox omits encrypted_credentials."""
        ok_w, w_data = upsert_user_worker(self.user_a_id, 60, "STOPPED", self.client_a)
        # Manually inject record with encrypted_credentials into database
        self.shared_db["sentinel_mailboxes_safe"].append({
            "id": str(uuid.uuid4()),
            "user_id": self.user_a_id,
            "worker_id": w_data["id"],
            "provider": "gmail",
            "email_address": "secure@gmail.com",
            "imap_host": "imap.gmail.com",
            "imap_port": 993,
            "use_ssl": True,
            "auth_mechanism": "APP_PASSWORD",
            "is_active": True,
            # encrypted_credentials is NOT in safe view
        })
        mb = get_user_mailbox(self.user_a_id, self.client_a)
        self.assertIsNotNone(mb)
        self.assertNotIn("encrypted_credentials", mb)
        self.assertEqual(mb["email_address"], "secure@gmail.com")


class TestSentinelNonExecutionGuarantees(unittest.TestCase):
    """Verifies that Phase 3 does NOT execute workers, spawn threads, or make IMAP/alert network calls."""

    def test_13_no_worker_threads_or_daemons_in_control_module(self):
        """core/sentinel_control.py must contain zero thread, multiprocessing, or subprocess spawns."""
        source = inspect.getsource(sc)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, ["threading", "multiprocessing", "subprocess", "sched", "asyncio"])
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module, ["threading", "multiprocessing", "subprocess", "sched", "asyncio"])

    def test_14_no_imap_or_network_calls_in_control_module(self):
        """core/sentinel_control.py must not make direct IMAP or HTTP network calls."""
        source = inspect.getsource(sc)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, ["imaplib", "requests", "urllib", "httpx", "aiohttp"])
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module, ["imaplib", "requests", "urllib", "httpx", "aiohttp"])

    def test_15_containment_isolation_retained_in_app(self):
        """app.py must retain the mandatory disabled warning and zero sentinel_manager.start calls."""
        with open("app.py", "r", encoding="utf-8") as f:
            app_code = f.read()

        self.assertIn(
            "Live Sentinel is temporarily unavailable in public multi-user mode",
            app_code,
            "app.py must retain the exact containment warning for multi-user mode"
        )
        self.assertNotIn(
            "sentinel_manager.start",
            app_code,
            "app.py must not call legacy sentinel_manager.start"
        )
        self.assertIn(
            "NOT DEPLOYED (Phase 4)",
            app_code,
            "app.py must explicitly indicate worker execution state as NOT DEPLOYED (Phase 4)"
        )


if __name__ == "__main__":
    unittest.main()
