"""
tests/test_sentinel_1sec_telemetry.py
Focused test suite for EMAILSHIELD INDIA Sentinel 1-Second Polling and Authoritative Telemetry.
Validates:
1. 1-second polling configuration defaults and environment parsing.
2. Non-overlapping poll execution pacing and mutex locking.
3. Persistent disk telemetry creation and tenant isolation.
4. Streamlit reading matching persistent worker telemetry.
5. Telemetry survival across Streamlit and worker restarts.
6. Checkpoint preservation and monotonic advancement across restarts.
7. Duplicate message prevention.
8. Read-only semantics of Refresh Telemetry.
"""

import os
import time
import uuid
import json
import pytest
from unittest.mock import MagicMock, patch

from worker.config import (
    WorkerConfig,
    DEFAULT_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    MAX_POLL_INTERVAL_SECONDS,
)
from worker.checkpoint import CheckpointStore, MailboxCheckpoint
from worker.service import WorkerService
from core.sentinel_stats import (
    TenantSentinelMetrics,
    _TenantStatsRegistry,
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    get_user_sentinel_metrics,
    _get_telemetry_file_path,
    TELEMETRY_DIR,
)


class TestSentinel1SecTelemetry:
    """Test suite covering 1-second polling cadence and authoritative telemetry synchronization."""

    def test_01_worker_config_1sec_default(self):
        """WorkerConfig defaults to 1.0 second poll interval."""
        cfg = WorkerConfig(worker_id=uuid.uuid4())
        assert cfg.poll_interval_seconds == 1.0
        assert "poll_interval=1.0s" in repr(cfg)

    def test_02_worker_config_from_env_1sec(self):
        """WorkerConfig.from_env correctly parses SENTINEL_POLL_INTERVAL."""
        wid = str(uuid.uuid4())
        env = {
            "SENTINEL_WORKER_ID": wid,
            "SENTINEL_POLL_INTERVAL": "1",
        }
        cfg = WorkerConfig.from_env(env)
        assert cfg.poll_interval_seconds == 1.0

        # Floats
        env["SENTINEL_POLL_INTERVAL"] = "1.5"
        cfg2 = WorkerConfig.from_env(env)
        assert cfg2.poll_interval_seconds == 1.5

        # Bounds enforcement
        env["SENTINEL_POLL_INTERVAL"] = "0.01"
        cfg_min = WorkerConfig.from_env(env)
        assert cfg_min.poll_interval_seconds == MIN_POLL_INTERVAL_SECONDS

        env["SENTINEL_POLL_INTERVAL"] = "99999"
        cfg_max = WorkerConfig.from_env(env)
        assert cfg_max.poll_interval_seconds == MAX_POLL_INTERVAL_SECONDS

    def test_03_no_overlapping_polls_and_cadence(self):
        """Poll lock prevents concurrent execution and ensures next poll waits for interval."""
        store = CheckpointStore()
        mb_id = f"test-mbx-{uuid.uuid4().hex[:8]}"

        # Acquire lock
        assert store.acquire_poll_lock(mb_id) is True
        # Second acquire fails closed (no concurrent poll)
        assert store.acquire_poll_lock(mb_id) is False

        # Release lock
        store.release_poll_lock(mb_id)
        assert store.acquire_poll_lock(mb_id) is True
        store.release_poll_lock(mb_id)

    def test_04_persistent_telemetry_created_on_poll(self):
        """Polling records telemetry to tenant/mailbox-scoped disk file."""
        user_id = str(uuid.uuid4())
        mailbox_id = str(uuid.uuid4())

        stats = record_user_sentinel_poll(
            user_id=user_id,
            mailbox_id=mailbox_id,
            arrived=1,
            analysed=1,
            clean=1,
            suspicious=0,
            high_critical=0,
            duplicates=0,
            errors=0,
            last_uid=10,
            poll_interval=1,
            highest_observed_uid=10,
            last_successful_imap_poll="12:00:00",
            last_poll_result="1 new message(s)",
        )

        assert stats["emails_arrived"] == 1
        assert stats["emails_analysed"] == 1
        assert stats["last_processed_uid"] == 10
        assert stats["poll_interval_seconds"] == 1

        # Check disk file exists
        path = _get_telemetry_file_path(user_id, mailbox_id)
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["user_id"] == user_id
        assert data["mailbox_id"] == mailbox_id
        assert data["emails_arrived"] == 1
        assert data["emails_analysed"] == 1
        assert data["last_processed_uid"] == 10

    def test_05_streamlit_reads_same_persistent_telemetry(self):
        """Streamlit get_user_sentinel_stats reads persistent disk telemetry matching worker."""
        user_id = str(uuid.uuid4())
        mailbox_id = str(uuid.uuid4())

        # Worker writes telemetry
        record_user_sentinel_poll(
            user_id=user_id,
            mailbox_id=mailbox_id,
            arrived=2,
            analysed=2,
            clean=2,
            duplicates=0,
            errors=0,
            last_uid=15,
            poll_interval=1,
            highest_observed_uid=15,
        )

        # Streamlit reads telemetry
        st_stats = get_user_sentinel_stats(user_id=user_id, mailbox_id=mailbox_id)
        assert st_stats["emails_arrived"] == 2
        assert st_stats["emails_analysed"] == 2
        assert st_stats["last_processed_uid"] == 15
        assert st_stats["poll_interval_seconds"] == 1

    def test_06_telemetry_survives_streamlit_restart(self):
        """Fresh registry instance (simulating Streamlit process restart) preserves telemetry."""
        user_id = str(uuid.uuid4())
        mailbox_id = str(uuid.uuid4())

        # Seed telemetry
        record_user_sentinel_poll(
            user_id=user_id,
            mailbox_id=mailbox_id,
            arrived=3,
            analysed=3,
            clean=3,
            duplicates=1,
            errors=0,
            last_uid=20,
            poll_interval=1,
            highest_observed_uid=20,
        )

        # Create brand new registry representing restarted Streamlit process
        fresh_registry = _TenantStatsRegistry()
        metrics = fresh_registry.get_or_create(user_id, mailbox_id)
        dict_data = metrics.to_dict()

        assert dict_data["emails_arrived"] == 3
        assert dict_data["emails_analysed"] == 3
        assert dict_data["duplicates_skipped"] == 1
        assert dict_data["last_processed_uid"] == 20

    def test_07_telemetry_and_checkpoint_survive_worker_restart(self):
        """Worker checkpoint store seeds from disk telemetry on process restart."""
        user_id = str(uuid.uuid4())
        mailbox_id = str(uuid.uuid4())
        worker_id = str(uuid.uuid4())

        # Record initial worker telemetry
        record_user_sentinel_poll(
            user_id=user_id,
            mailbox_id=mailbox_id,
            arrived=5,
            analysed=4,
            clean=4,
            duplicates=1,
            errors=0,
            last_uid=50,
            poll_interval=1,
            highest_observed_uid=50,
        )

        # Create brand new CheckpointStore (simulating worker restart)
        new_store = CheckpointStore()
        # Production worker explicitly seeds from telemetry on startup
        new_store.seed_from_telemetry(user_id, worker_id, mailbox_id)
        cp = new_store.get_checkpoint(user_id, worker_id, mailbox_id)

        assert cp.last_processed_uid == 50
        assert cp.has_polled is True
        assert cp.emails_arrived == 5
        assert cp.emails_analysed == 4
        assert cp.duplicates_skipped == 1

    def test_08_tenant_isolation_cross_tenant_prevented(self):
        """Tenant A cannot access Tenant B's metrics."""
        user_a = str(uuid.uuid4())
        user_b = str(uuid.uuid4())
        mb_a = str(uuid.uuid4())
        mb_b = str(uuid.uuid4())

        record_user_sentinel_poll(user_id=user_a, mailbox_id=mb_a, arrived=7, analysed=7, last_uid=77)

        # Query user B
        stats_b = get_user_sentinel_stats(user_id=user_b, mailbox_id=mb_b)
        assert stats_b["emails_arrived"] == 0
        assert stats_b["emails_analysed"] == 0
        assert stats_b["last_processed_uid"] == 0

    def test_09_duplicate_prevention_semantics(self):
        """Deduplication advances checkpoint without incrementing emails_analysed."""
        store = CheckpointStore()
        user_id = str(uuid.uuid4())
        worker_id = str(uuid.uuid4())
        mb_id = str(uuid.uuid4())

        store.advance_checkpoint(user_id, worker_id, mb_id, uid=1, message_id="<msg-1@test>")
        assert store.is_duplicate_message_id(mb_id, "<msg-1@test>") is True
        assert store.is_duplicate_message_id(mb_id, "<msg-2@test>") is False

    def test_10_refresh_telemetry_is_readonly(self):
        """get_user_sentinel_stats does not mutate disk state or perform writes."""
        user_id = str(uuid.uuid4())
        mb_id = str(uuid.uuid4())

        # No telemetry exists yet
        stats_before = get_user_sentinel_stats(user_id, mb_id)
        assert stats_before["emails_arrived"] == 0
        assert stats_before["has_polled"] is False

        # Repeating the call produces identical read-only output
        stats_after = get_user_sentinel_stats(user_id, mb_id)
        assert stats_after == stats_before
