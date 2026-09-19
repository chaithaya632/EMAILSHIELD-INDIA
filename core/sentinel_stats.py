"""
core/sentinel_stats.py
Tenant-Isolated Sentinel Mail Processing Statistics & Telemetry.

Security & Architectural Guarantees:
1. Strict Multi-Tenant Isolation: Statistics are strictly scoped per (user_id, mailbox_id).
   User A can NEVER inspect or access User B's processing metrics or counters.
2. Counter Semantics (EMAILSHIELD Specification Section 6):
   - Emails Arrived: Number of NEW email messages discovered during polling.
   - Emails Analysed: Number of newly discovered messages that entered forensic analysis.
   - Clean: Newly analysed emails classified LOW/Clean.
   - Suspicious: Newly analysed emails classified SUSPICIOUS/Medium.
   - High/Critical: Newly analysed emails classified HIGH or CRITICAL.
   - Duplicates Skipped: Deduplicated messages intentionally not analysed again.
   - Processing Errors: Messages that could not be safely processed due to malformed/oversized payloads.
3. Alert Independence: Test Alert invocations NEVER alter email processing counters.
4. Zero Database Schema Alteration: Operates in coordination with existing checkpoints and RLS.
"""

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, List

TELEMETRY_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local", "sentinel_telemetry")


def _get_telemetry_file_path(user_id: str, mailbox_id: str) -> str:
    """Generates tenant-isolated, deterministic file path for telemetry persistence."""
    h_u = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:16]
    h_m = hashlib.sha256(mailbox_id.encode("utf-8")).hexdigest()[:16]
    return os.path.join(TELEMETRY_DIR, f"telemetry_{h_u}_{h_m}.json")


@dataclass
class TenantSentinelMetrics:
    """Telemetry counters for a specific tenant user and mailbox."""
    user_id: str
    mailbox_id: str
    folder_name: str = "INBOX"
    has_polled: bool = False
    last_poll_time_str: Optional[str] = None
    last_processed_uid: int = 0
    poll_interval_seconds: int = 1

    # Cumulative / Session Total Counters
    emails_arrived: int = 0
    emails_analysed: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    high_critical_count: int = 0
    duplicates_skipped: int = 0
    processing_errors: int = 0

    # Last-Poll ("This Poll") Counters
    this_poll_arrived: int = 0
    this_poll_analysed: int = 0
    this_poll_clean: int = 0
    this_poll_suspicious: int = 0
    this_poll_high_critical: int = 0
    this_poll_duplicates: int = 0
    this_poll_errors: int = 0

    # Section 16 Diagnostic Fields
    highest_observed_uid: int = 0
    last_successful_imap_poll_str: Optional[str] = None
    last_poll_result: str = "0 new messages"
    # Recent Events for Live Activity View
    recent_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Returns safe dictionary format for presentation tier."""
        return {
            "user_id": self.user_id,
            "mailbox_id": self.mailbox_id,
            "folder_name": self.folder_name,
            "has_polled": self.has_polled,
            "last_poll_time": self.last_poll_time_str if self.has_polled else "Waiting for first poll...",
            "poll_interval_seconds": self.poll_interval_seconds,
            "last_processed_uid": self.last_processed_uid,
            # Cumulative Totals
            "emails_arrived": self.emails_arrived,
            "emails_analysed": self.emails_analysed,
            "clean": self.clean_count,
            "suspicious": self.suspicious_count,
            "high_critical": self.high_critical_count,
            "duplicates_skipped": self.duplicates_skipped,
            "processing_errors": self.processing_errors,
            # Per-Poll Activity
            "this_poll_arrived": self.this_poll_arrived,
            "this_poll_analysed": self.this_poll_analysed,
            "this_poll_clean": self.this_poll_clean,
            "this_poll_suspicious": self.this_poll_suspicious,
            "this_poll_high_critical": self.this_poll_high_critical,
            "this_poll_duplicates": self.this_poll_duplicates,
            "this_poll_errors": self.this_poll_errors,
            # Section 16 Diagnostics
            "highest_observed_uid": self.highest_observed_uid,
            "last_successful_imap_poll": self.last_successful_imap_poll_str or ("Never" if not self.has_polled else (self.last_poll_time_str or "Never")),
            "last_poll_result": self.last_poll_result,
            "recent_events": list(self.recent_events),
        }


class _TenantStatsRegistry:
    """Thread-safe and process-resilient tenant-scoped metrics registry."""
    def __init__(self):
        self._metrics: Dict[Tuple[str, str], TenantSentinelMetrics] = {}
        self._lock = threading.RLock()

    def _make_key(self, user_id: str, mailbox_id: Optional[str]) -> Tuple[str, str]:
        u_key = str(user_id).strip() if user_id else "anonymous"
        m_key = str(mailbox_id).strip() if mailbox_id else "default_mailbox"
        return (u_key, m_key)

    def _save_to_disk(self, m: TenantSentinelMetrics) -> None:
        """Persists tenant telemetry to disk atomically for cross-process synchronization."""
        try:
            os.makedirs(TELEMETRY_DIR, exist_ok=True)
            path = _get_telemetry_file_path(m.user_id, m.mailbox_id)
            tmp_path = path + ".tmp"
            data = {
                "user_id": m.user_id,
                "mailbox_id": m.mailbox_id,
                "folder_name": m.folder_name,
                "has_polled": m.has_polled,
                "last_poll_time_str": m.last_poll_time_str,
                "last_processed_uid": m.last_processed_uid,
                "poll_interval_seconds": m.poll_interval_seconds,
                "emails_arrived": m.emails_arrived,
                "emails_analysed": m.emails_analysed,
                "clean_count": m.clean_count,
                "suspicious_count": m.suspicious_count,
                "high_critical_count": m.high_critical_count,
                "duplicates_skipped": m.duplicates_skipped,
                "processing_errors": m.processing_errors,
                "this_poll_arrived": m.this_poll_arrived,
                "this_poll_analysed": m.this_poll_analysed,
                "this_poll_clean": m.this_poll_clean,
                "this_poll_suspicious": m.this_poll_suspicious,
                "this_poll_high_critical": m.this_poll_high_critical,
                "this_poll_duplicates": m.this_poll_duplicates,
                "this_poll_errors": m.this_poll_errors,
                "highest_observed_uid": m.highest_observed_uid,
                "last_successful_imap_poll_str": m.last_successful_imap_poll_str,
                "last_poll_result": m.last_poll_result,
                "recent_events": m.recent_events,
            }
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            if os.path.exists(path):
                os.replace(tmp_path, path)
            else:
                os.rename(tmp_path, path)
        except Exception:
            pass

    def _load_from_disk(self, user_id: str, mailbox_id: str) -> Optional[TenantSentinelMetrics]:
        """Loads persisted tenant telemetry from disk if present."""
        try:
            path = _get_telemetry_file_path(user_id, mailbox_id)
            if not os.path.exists(path) and os.path.isdir(TELEMETRY_DIR) and user_id:
                h_u = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:16]
                candidates = [
                    os.path.join(TELEMETRY_DIR, f)
                    for f in os.listdir(TELEMETRY_DIR)
                    if f.startswith(f"telemetry_{h_u}_") and f.endswith(".json")
                ]
                if candidates:
                    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
                    path = candidates[0]

            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return TenantSentinelMetrics(
                    user_id=data.get("user_id", user_id),
                    mailbox_id=data.get("mailbox_id", mailbox_id),
                    folder_name=data.get("folder_name", "INBOX"),
                    has_polled=data.get("has_polled", False),
                    last_poll_time_str=data.get("last_poll_time_str"),
                    last_processed_uid=data.get("last_processed_uid", 0),
                    poll_interval_seconds=data.get("poll_interval_seconds", 1),
                    emails_arrived=data.get("emails_arrived", 0),
                    emails_analysed=data.get("emails_analysed", 0),
                    clean_count=data.get("clean_count", 0),
                    suspicious_count=data.get("suspicious_count", 0),
                    high_critical_count=data.get("high_critical_count", 0),
                    duplicates_skipped=data.get("duplicates_skipped", 0),
                    processing_errors=data.get("processing_errors", 0),
                    this_poll_arrived=data.get("this_poll_arrived", 0),
                    this_poll_analysed=data.get("this_poll_analysed", 0),
                    this_poll_clean=data.get("this_poll_clean", 0),
                    this_poll_suspicious=data.get("this_poll_suspicious", 0),
                    this_poll_high_critical=data.get("this_poll_high_critical", 0),
                    this_poll_duplicates=data.get("this_poll_duplicates", 0),
                    this_poll_errors=data.get("this_poll_errors", 0),
                    highest_observed_uid=data.get("highest_observed_uid", 0),
                    last_successful_imap_poll_str=data.get("last_successful_imap_poll_str"),
                    last_poll_result=data.get("last_poll_result", "0 new messages"),
                    recent_events=data.get("recent_events", []),
                )
        except Exception:
            pass
        return None

    def get_or_create(self, user_id: str, mailbox_id: Optional[str] = None) -> TenantSentinelMetrics:
        key = self._make_key(user_id, mailbox_id)
        with self._lock:
            disk_m = self._load_from_disk(key[0], key[1])
            if disk_m:
                self._metrics[key] = disk_m
            elif key not in self._metrics:
                self._metrics[key] = TenantSentinelMetrics(
                    user_id=key[0],
                    mailbox_id=key[1]
                )
            return self._metrics[key]

    def record_poll(
        self,
        user_id: str,
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
        poll_interval: int = 1,
        highest_observed_uid: Optional[int] = None,
        last_successful_imap_poll: Optional[str] = None,
        last_poll_result: Optional[str] = None,
        recent_events: Optional[List[Dict[str, Any]]] = None,
    ) -> TenantSentinelMetrics:
        """Atomically updates tenant-isolated metrics for a poll cycle."""
        key = self._make_key(user_id, mailbox_id)
        with self._lock:
            m = self.get_or_create(user_id, mailbox_id)
            m.has_polled = True
            m.last_poll_time_str = poll_time_str or time.strftime("%H:%M:%S")
            m.poll_interval_seconds = poll_interval
            if last_uid is not None and last_uid > m.last_processed_uid:
                m.last_processed_uid = last_uid

            if highest_observed_uid is not None and highest_observed_uid > m.highest_observed_uid:
                m.highest_observed_uid = highest_observed_uid
            elif last_uid is not None and last_uid > m.highest_observed_uid:
                m.highest_observed_uid = last_uid

            if last_successful_imap_poll:
                m.last_successful_imap_poll_str = last_successful_imap_poll
            elif poll_time_str:
                m.last_successful_imap_poll_str = poll_time_str

            if last_poll_result:
                m.last_poll_result = last_poll_result

            if recent_events:
                m.recent_events = (list(recent_events) + list(m.recent_events))[:10]

            # Update this poll counters
            m.this_poll_arrived = arrived
            m.this_poll_analysed = analysed
            m.this_poll_clean = clean
            m.this_poll_suspicious = suspicious
            m.this_poll_high_critical = high_critical
            m.this_poll_duplicates = duplicates
            m.this_poll_errors = errors

            # Accumulate cumulative counters
            m.emails_arrived += arrived
            m.emails_analysed += analysed
            m.clean_count += clean
            m.suspicious_count += suspicious
            m.high_critical_count += high_critical
            m.duplicates_skipped += duplicates
            m.processing_errors += errors

            # Persist for multi-process coordination
            self._save_to_disk(m)
            return m

    def reset(self, user_id: str, mailbox_id: Optional[str] = None) -> None:
        """Cleanses tenant metrics on mailbox disconnect or session termination."""
        key = self._make_key(user_id, mailbox_id)
        with self._lock:
            self._metrics.pop(key, None)
            try:
                path = _get_telemetry_file_path(key[0], key[1])
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass


# Module-level tenant-scoped registry
_REGISTRY = _TenantStatsRegistry()


def get_user_sentinel_stats(
    user_id: str,
    mailbox_id: Optional[str] = None,
    client: Any = None,
    checkpoint_rec: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Retrieves tenant-isolated Sentinel metrics strictly scoped to user_id.
    Cross-tenant queries are structurally prevented.
    """
    if not user_id:
        return TenantSentinelMetrics(user_id="anonymous", mailbox_id="none").to_dict()

    m = _REGISTRY.get_or_create(user_id, mailbox_id)
    stats_dict = m.to_dict()

    # If in-memory poll has not occurred yet, seed UID & Last Scan from checkpoint if available
    if not m.has_polled and checkpoint_rec:
        if checkpoint_rec.get("last_processed_uid"):
            stats_dict["last_processed_uid"] = int(checkpoint_rec["last_processed_uid"])
            if stats_dict.get("highest_observed_uid", 0) < stats_dict["last_processed_uid"]:
                stats_dict["highest_observed_uid"] = stats_dict["last_processed_uid"]
        if checkpoint_rec.get("last_scan_timestamp"):
            stats_dict["last_poll_time"] = str(checkpoint_rec["last_scan_timestamp"])

    import logging
    stats_logger = logging.getLogger("sentinel.stats")
    stats_logger.info(
        "SAFE_DIAG_BOUNDARY_3: read telemetry user_hash=%s, arrived=%d, analysed=%d, uid=%d",
        hashlib.sha256(user_id.encode()).hexdigest()[:8],
        stats_dict.get("emails_arrived", 0),
        stats_dict.get("emails_analysed", 0),
        stats_dict.get("last_processed_uid", 0)
    )

    return stats_dict


def record_user_sentinel_poll(
    user_id: str,
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
    poll_interval: int = 1,
    highest_observed_uid: Optional[int] = None,
    last_successful_imap_poll: Optional[str] = None,
    last_poll_result: Optional[str] = None,
    recent_events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Records a single poll cycle's results for a given tenant user and mailbox."""
    m = _REGISTRY.record_poll(
        user_id=user_id,
        mailbox_id=mailbox_id,
        arrived=arrived,
        analysed=analysed,
        clean=clean,
        suspicious=suspicious,
        high_critical=high_critical,
        duplicates=duplicates,
        errors=errors,
        last_uid=last_uid,
        poll_time_str=poll_time_str,
        poll_interval=poll_interval,
        highest_observed_uid=highest_observed_uid,
        last_successful_imap_poll=last_successful_imap_poll,
        last_poll_result=last_poll_result,
        recent_events=recent_events,
    )
    return m.to_dict()


def get_user_sentinel_metrics(user_id: str, mailbox_id: Optional[str] = None) -> Optional[TenantSentinelMetrics]:
    """Returns the TenantSentinelMetrics instance for a user/mailbox, loading from disk if needed."""
    if not user_id:
        return None
    return _REGISTRY.get_or_create(user_id, mailbox_id)


def reset_user_sentinel_stats(user_id: str, mailbox_id: Optional[str] = None) -> None:
    """Purges tenant statistics for user_id."""
    _REGISTRY.reset(user_id, mailbox_id)


def is_pid_alive(pid: Optional[int]) -> bool:
    """Checks if a process ID is currently running in the OS."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    import sys
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            try:
                exit_code = wintypes.DWORD()
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == STILL_ACTIVE
                return False
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def get_sentinel_worker_runtime() -> Dict[str, Any]:
    """
    Checks the real runtime state of the external Sentinel worker process.
    Never fakes RUNNING status unless a real OS worker process is verified alive.
    """
    runtime_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data", "local", "sentinel_worker_runtime.json"
    )
    if not os.path.exists(runtime_path):
        return {
            "worker_configured": False,
            "worker_started": False,
            "worker_process_alive": False,
            "worker_poll_loop_active": False,
            "worker_last_heartbeat": "Never",
            "pid": None,
            "status": "STOPPED",
        }

    try:
        with open(runtime_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_pid = data.get("pid")
        pid = int(raw_pid) if raw_pid else None
        alive = is_pid_alive(pid) if pid else False
        last_hb = float(data.get("last_heartbeat", 0))
        hb_fresh = (time.time() - last_hb) < 120.0 if last_hb > 0 else False
        configured = bool(data.get("worker_id"))
        started = bool(data.get("started_at"))
        loop_active = alive and hb_fresh and data.get("status") == "RUNNING"
        effective_status = "RUNNING" if loop_active else "STOPPED"

        return {
            "worker_configured": configured,
            "worker_started": started,
            "worker_process_alive": alive,
            "worker_poll_loop_active": loop_active,
            "worker_last_heartbeat": data.get("last_heartbeat_str", "Never") if last_hb > 0 else "Never",
            "pid": pid if alive else None,
            "status": effective_status,
        }
    except Exception:
        return {
            "worker_configured": False,
            "worker_started": False,
            "worker_process_alive": False,
            "worker_poll_loop_active": False,
            "worker_last_heartbeat": "Never",
            "pid": None,
            "status": "STOPPED",
        }


def start_sentinel_worker_daemon() -> Tuple[bool, str, Optional[int]]:
    """
    Ensures the independent Sentinel worker process is running.
    Launches python -m worker as an independent detached OS process.
    """
    import subprocess
    import sys

    proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(proj_root, "data", "local")
    os.makedirs(log_dir, exist_ok=True)
    worker_log_file = os.path.join(log_dir, "worker.log")

    # Ensure production polling flag is set
    prod_flag_path = os.path.join(log_dir, "sentinel_production_polling.txt")
    try:
        with open(prod_flag_path, "w", encoding="utf-8") as f:
            f.write("1")
    except Exception:
        pass

    # Determine target worker ID
    wid_file = os.path.join(log_dir, "sentinel_worker_id.txt")
    target_wid = None
    if os.path.exists(wid_file):
        try:
            with open(wid_file, "r", encoding="utf-8") as f:
                target_wid = f.read().strip()
        except Exception:
            pass

    if not target_wid:
        try:
            from worker.db import LocalWorkerDBClient
            loc_client = LocalWorkerDBClient()
            for mb in loc_client.mailboxes.values():
                if mb.get("is_active") and mb.get("assigned_worker_id"):
                    target_wid = mb["assigned_worker_id"]
                    try:
                        with open(wid_file, "w", encoding="utf-8") as f:
                            f.write(target_wid)
                    except Exception:
                        pass
                    break
        except Exception:
            pass

    info = get_sentinel_worker_runtime()
    if info.get("worker_process_alive"):
        pid = info.get("pid")
        runtime_path = os.path.join(log_dir, "sentinel_worker_runtime.json")
        running_wid = None
        if os.path.exists(runtime_path):
            try:
                with open(runtime_path, "r", encoding="utf-8") as f:
                    running_wid = json.load(f).get("worker_id")
            except Exception:
                pass
        if target_wid and running_wid and target_wid != running_wid:
            stop_sentinel_worker_daemon()
        else:
            return True, f"Worker already running (PID: {pid})", pid

    if target_wid:
        try:
            from worker.db import LocalWorkerDBClient
            loc_client = LocalWorkerDBClient()
            loc_client._load_from_disk()
            with loc_client._lock:
                for wid, w in loc_client.workers.items():
                    if wid == str(target_wid):
                        w["desired_state"] = "RUNNING"
                        w["lease_owner"] = None
                        w["lease_expires_at"] = None
                        w["lease_token_hash"] = None
                        w["actual_state"] = "STOPPED"
                loc_client._save_to_disk()
        except Exception:
            pass

    cmd = [sys.executable, "-u", "-m", "worker"]
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP

    env = os.environ.copy()
    env["SENTINEL_ENABLE_PRODUCTION_POLLING"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    if target_wid:
        env["SENTINEL_WORKER_ID"] = target_wid

    try:
        log_f = open(worker_log_file, "a", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=proj_root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags
        )
        pid = proc.pid

        # Wait up to 3 seconds for worker to report running status
        start_time = time.time()
        while time.time() - start_time < 3.0:
            time.sleep(0.3)
            info = get_sentinel_worker_runtime()
            if info.get("worker_process_alive"):
                return True, f"Worker started successfully (PID: {info.get('pid', pid)})", info.get("pid", pid)

        if is_pid_alive(pid):
            return True, f"Worker process alive (PID: {pid})", pid
        return False, "Worker process exited immediately. Check data/local/worker.log for details.", None
    except Exception as e:
        return False, f"Failed to start worker process: {str(e)}", None


def stop_sentinel_worker_daemon() -> Tuple[bool, str]:
    """Gracefully halts the independent Sentinel worker process."""
    import signal
    import subprocess

    try:
        from worker.db import LocalWorkerDBClient
        LocalWorkerDBClient.force_release_worker_lease()
    except Exception:
        pass

    info = get_sentinel_worker_runtime()
    pid = info.get("pid")
    if not pid or not info.get("worker_process_alive"):
        return True, "Worker process is not running."

    try:
        if sys.platform == "win32":
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
            time.sleep(0.5)
            if is_pid_alive(pid):
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        else:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            if is_pid_alive(pid):
                os.kill(pid, signal.SIGKILL)

        runtime_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "local", "sentinel_worker_runtime.json"
        )
        if os.path.exists(runtime_path):
            try:
                with open(runtime_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["status"] = "STOPPED"
                data["pid"] = None
                with open(runtime_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass

        return True, f"Worker process (PID {pid}) stopped."
    except Exception as e:
        return False, f"Error stopping worker: {str(e)}"
