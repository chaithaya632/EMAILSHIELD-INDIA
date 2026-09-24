"""
worker/checkpoint.py
Mailbox checkpoint management and Message-ID deduplication for EMAILSHIELD INDIA Sentinel.
Enforces incremental UID progress, monotonic checkpoint advancement, secondary Message-ID
deduplication, and concurrent poll locking.
"""

import time
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional, Dict, Tuple, Set


@dataclass
class MailboxCheckpoint:
    """Represents the incremental synchronization state for a single mailbox folder."""
    user_id: str
    worker_id: str
    mailbox_id: str
    folder_name: str = "INBOX"
    uid_validity: int = 1
    last_processed_uid: int = 0
    last_processed_msg_id: Optional[str] = None
    last_processed_date: Optional[str] = None
    last_scan_timestamp: float = 0.0
    emails_arrived: int = 0
    emails_analysed: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    high_critical_count: int = 0
    duplicates_skipped: int = 0
    processing_errors: int = 0
    this_poll_arrived: int = 0
    this_poll_analysed: int = 0
    this_poll_clean: int = 0
    this_poll_suspicious: int = 0
    this_poll_high_critical: int = 0
    this_poll_duplicates: int = 0
    this_poll_errors: int = 0
    has_polled: bool = False
    last_poll_time_str: Optional[str] = None


class CheckpointStore:
    """
    In-memory and thread-safe checkpoint and deduplication state manager.
    
    Security & Reliability Properties:
    - Atomic checkpoint updates strictly after message processing.
    - Secondary Message-ID deduplication with bounded memory (LRU capacity).
    - Mailbox concurrency mutual exclusion preventing concurrent polling of the same mailbox.
    """
    MAX_SEEN_MSG_IDS_PER_MAILBOX = 10000

    def __init__(self, db_client: any = None):
        self.db_client = db_client
        self._checkpoints: Dict[Tuple[str, str, str], MailboxCheckpoint] = {}
        # Bounded LRU OrderedDict for secondary Message-ID deduplication
        self._seen_msg_ids: Dict[str, OrderedDict] = {}
        # Concurrency locks per mailbox_id
        self._active_poll_locks: Set[str] = set()
        self._lock = threading.RLock()

    def get_checkpoint(
        self,
        user_id: str,
        worker_id: str,
        mailbox_id: str,
        folder_name: str = "INBOX"
    ) -> MailboxCheckpoint:
        """Retrieves or initializes a mailbox checkpoint."""
        key = (user_id.strip(), mailbox_id.strip(), folder_name.strip())
        with self._lock:
            if key not in self._checkpoints:
                cp = MailboxCheckpoint(
                    user_id=user_id.strip(),
                    worker_id=worker_id.strip(),
                    mailbox_id=mailbox_id.strip(),
                    folder_name=folder_name.strip(),
                )
                self._checkpoints[key] = cp
            return self._checkpoints[key]

    def seed_from_telemetry(
        self,
        user_id: str,
        worker_id: str,
        mailbox_id: str,
        folder_name: str = "INBOX"
    ) -> None:
        """Seeds a checkpoint from persistent telemetry if available.
        
        Called explicitly by the worker service during startup to recover
        counters and checkpoint state across worker restarts.
        Must NOT be called automatically — tests rely on fresh checkpoints.
        """
        key = (user_id.strip(), mailbox_id.strip(), folder_name.strip())
        with self._lock:
            cp = self._checkpoints.get(key)
            if cp is None:
                cp = self.get_checkpoint(user_id, worker_id, mailbox_id, folder_name)
            if cp.has_polled:
                return  # Already has data, don't overwrite
            try:
                from core.sentinel_stats import get_user_sentinel_metrics
                saved_m = get_user_sentinel_metrics(user_id.strip(), mailbox_id.strip())
                if saved_m and saved_m.has_polled:
                    cp.last_processed_uid = saved_m.last_processed_uid
                    cp.has_polled = saved_m.has_polled
                    cp.last_poll_time_str = saved_m.last_poll_time_str
                    cp.emails_arrived = saved_m.emails_arrived
                    cp.emails_analysed = saved_m.emails_analysed
                    cp.clean_count = saved_m.clean_count
                    cp.suspicious_count = saved_m.suspicious_count
                    cp.high_critical_count = saved_m.high_critical_count
                    cp.duplicates_skipped = saved_m.duplicates_skipped
                    cp.processing_errors = saved_m.processing_errors
            except Exception:
                pass

    def advance_checkpoint(
        self,
        user_id: str,
        worker_id: str,
        mailbox_id: str,
        uid: int,
        message_id: Optional[str] = None,
        date_str: Optional[str] = None,
        folder_name: str = "INBOX"
    ) -> None:
        """
        Atomically advances the checkpoint UID and records the processed Message-ID.
        Must only be invoked after a message is successfully processed.
        """
        key = (user_id.strip(), mailbox_id.strip(), folder_name.strip())
        with self._lock:
            cp = self.get_checkpoint(user_id, worker_id, mailbox_id, folder_name)
            # Enforce monotonic increase of UID
            if uid > cp.last_processed_uid:
                cp.last_processed_uid = uid
                cp.last_processed_msg_id = message_id
                cp.last_processed_date = date_str
                cp.last_scan_timestamp = time.time()

            # Record in secondary deduplication index
            if message_id:
                clean_msg_id = message_id.strip()
                mb_seen = self._seen_msg_ids.setdefault(mailbox_id.strip(), OrderedDict())
                mb_seen[clean_msg_id] = True
                if len(mb_seen) > self.MAX_SEEN_MSG_IDS_PER_MAILBOX:
                    mb_seen.popitem(last=False)  # Evict oldest entry

    def is_duplicate_message_id(self, mailbox_id: str, message_id: Optional[str]) -> bool:
        """Checks if a Message-ID has already been processed for this mailbox."""
        if not message_id or not message_id.strip():
            return False
        with self._lock:
            mb_seen = self._seen_msg_ids.get(mailbox_id.strip())
            return clean_msg_id in mb_seen if mb_seen and (clean_msg_id := message_id.strip()) in mb_seen else False

    def acquire_poll_lock(self, mailbox_id: str) -> bool:
        """
        Attempts to acquire a mutually exclusive polling lock for a mailbox.
        Returns False (POLL_ALREADY_RUNNING) if a poll is already in progress.
        """
        with self._lock:
            clean_id = mailbox_id.strip()
            if clean_id in self._active_poll_locks:
                return False
            self._active_poll_locks.add(clean_id)
            return True

    def release_poll_lock(self, mailbox_id: str) -> None:
        """Releases the mailbox polling lock."""
        with self._lock:
            self._active_poll_locks.discard(mailbox_id.strip())

    def record_poll_stats(
        self,
        user_id: str,
        worker_id: str,
        mailbox_id: str,
        arrived: int = 0,
        analysed: int = 0,
        clean: int = 0,
        suspicious: int = 0,
        high_critical: int = 0,
        duplicates: int = 0,
        errors: int = 0,
        last_uid: Optional[int] = None,
        poll_time_str: Optional[str] = None,
        folder_name: str = "INBOX"
    ) -> MailboxCheckpoint:
        """Atomically records poll cycle statistics onto the tenant's MailboxCheckpoint."""
        with self._lock:
            cp = self.get_checkpoint(user_id, worker_id, mailbox_id, folder_name)
            cp.has_polled = True
            cp.last_poll_time_str = poll_time_str or time.strftime("%H:%M:%S")
            cp.last_scan_timestamp = time.time()
            if last_uid is not None and last_uid > cp.last_processed_uid:
                cp.last_processed_uid = last_uid

            # Record this poll
            cp.this_poll_arrived = arrived
            cp.this_poll_analysed = analysed
            cp.this_poll_clean = clean
            cp.this_poll_suspicious = suspicious
            cp.this_poll_high_critical = high_critical
            cp.this_poll_duplicates = duplicates
            cp.this_poll_errors = errors

            # Accumulate session totals
            cp.emails_arrived += arrived
            cp.emails_analysed += analysed
            cp.clean_count += clean
            cp.suspicious_count += suspicious
            cp.high_critical_count += high_critical
            cp.duplicates_skipped += duplicates
            cp.processing_errors += errors
            return cp

    def get_stats(
        self,
        user_id: str,
        worker_id: str,
        mailbox_id: str,
        folder_name: str = "INBOX"
    ) -> Dict[str, Any]:
        """Returns tenant-isolated processing statistics for presentation."""
        with self._lock:
            cp = self.get_checkpoint(user_id, worker_id, mailbox_id, folder_name)
            return {
                "user_id": cp.user_id,
                "mailbox_id": cp.mailbox_id,
                "has_polled": cp.has_polled,
                "last_poll_time": cp.last_poll_time_str if cp.has_polled else "Waiting for first poll...",
                "last_processed_uid": cp.last_processed_uid,
                "emails_arrived": cp.emails_arrived,
                "emails_analysed": cp.emails_analysed,
                "clean": cp.clean_count,
                "suspicious": cp.suspicious_count,
                "high_critical": cp.high_critical_count,
                "duplicates_skipped": cp.duplicates_skipped,
                "processing_errors": cp.processing_errors,
                "this_poll_arrived": cp.this_poll_arrived,
                "this_poll_analysed": cp.this_poll_analysed,
                "this_poll_clean": cp.this_poll_clean,
                "this_poll_suspicious": cp.this_poll_suspicious,
                "this_poll_high_critical": cp.this_poll_high_critical,
                "this_poll_duplicates": cp.this_poll_duplicates,
                "this_poll_errors": cp.this_poll_errors,
            }
