"""
worker/health.py
Worker Health and Telemetry Monitoring for EMAILSHIELD INDIA Sentinel.

Provides operational telemetry while strictly prohibiting the exposure of:
- Passwords, OAuth tokens, or app passwords
- Capability tokens
- Private keys
- SENTINEL_MASTER_KEY
- Encrypted or decrypted credentials
- Email messages or user content
"""

import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, Optional

WORKER_RUNTIME_VERSION = "1.0.0"


@dataclass
class WorkerHealthStatus:
    """Operational health telemetry snapshot for Sentinel worker runtime."""
    worker_id: str
    runtime_version: str
    state: str
    started_at: str
    uptime_seconds: float
    last_heartbeat: str
    lease_active: bool
    lease_expires_in_seconds: float
    db_connected: bool
    production_polling_enabled: bool
    test_mode: bool

    def to_dict(self) -> Dict[str, Any]:
        """Converts health status to dictionary, strictly enforcing secret omission."""
        return asdict(self)

    def __repr__(self) -> str:
        return (
            f"<WorkerHealthStatus id={self.worker_id} state={self.state} "
            f"lease_active={self.lease_active} db_connected={self.db_connected} "
            f"uptime={self.uptime_seconds:.1f}s prod_polling={self.production_polling_enabled}>"
        )


class WorkerHealthMonitor:
    """
    Collects runtime operational telemetry without exposing sensitive credentials or keys.
    """

    def __init__(self, service: Any):
        self.service = service
        self.started_at_epoch = time.time()
        self.started_at_iso = datetime.now(timezone.utc).isoformat()
        self.last_heartbeat_epoch = self.started_at_epoch
        self.last_heartbeat_iso = self.started_at_iso

    def record_heartbeat(self) -> None:
        """Records a successful worker heartbeat timestamp."""
        now = time.time()
        self.last_heartbeat_epoch = now
        self.last_heartbeat_iso = datetime.now(timezone.utc).isoformat()

    def get_status(self) -> WorkerHealthStatus:
        """Collects current operational health status."""
        now = time.time()
        uptime = max(0.0, now - self.started_at_epoch)

        state_str = str(getattr(self.service, "state", "UNKNOWN"))
        if hasattr(self.service, "state") and hasattr(self.service.state, "value"):
            state_str = self.service.state.value

        worker_id_str = str(getattr(self.service.identity, "worker_id", "unconfigured"))

        # Lease telemetry
        lease_mgr = getattr(self.service, "lease_manager", None)
        lease_active = lease_mgr.is_active() if lease_mgr else False
        lease_remaining = lease_mgr.time_until_expiry() if lease_mgr else 0.0

        # Database telemetry
        db_client = getattr(self.service, "db_client", None)
        if hasattr(db_client, "_conn") and db_client._conn:
            db_connected = not getattr(db_client._conn, "closed", True)
        elif hasattr(db_client, "is_connected"):
            db_connected = bool(db_client.is_connected)
        else:
            db_connected = bool(db_client)

        # Configuration flags
        config = getattr(self.service, "config", None)
        prod_polling = getattr(config, "production_polling_enabled", False) if config else False
        test_mode = getattr(config, "test_mode", False) if config else False

        return WorkerHealthStatus(
            worker_id=worker_id_str,
            runtime_version=WORKER_RUNTIME_VERSION,
            state=state_str,
            started_at=self.started_at_iso,
            uptime_seconds=uptime,
            last_heartbeat=self.last_heartbeat_iso,
            lease_active=lease_active,
            lease_expires_in_seconds=max(0.0, lease_remaining),
            db_connected=db_connected,
            production_polling_enabled=prod_polling,
            test_mode=test_mode
        )

    def is_healthy(self) -> bool:
        """Returns True if the worker runtime is in a healthy operational state."""
        status = self.get_status()
        # A healthy worker is in RUNNING state with active DB connection
        return status.state == "RUNNING" and status.db_connected


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
        import os
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def get_worker_runtime_info() -> Dict[str, Any]:
    """
    Checks the real runtime state of the external Sentinel worker.
    Distinguishes:
    - Worker Configured
    - Worker Started
    - Worker Process Alive
    - Worker Poll Loop Active
    - Worker Last Heartbeat
    Never fakes RUNNING status unless a real OS worker process is verified alive.
    """
    import os
    import json
    runtime_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data",
        "local",
        "sentinel_worker_runtime.json"
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


class FailureCategory:
    """Standardized operational failure categories for Sentinel worker and IMAP engine."""
    NETWORK_FAILURE = "NETWORK_FAILURE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    TLS_FAILURE = "TLS_FAILURE"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    LEASE_LOST = "LEASE_LOST"
    CHECKPOINT_FAILURE = "CHECKPOINT_FAILURE"
    MIME_PARSE_FAILURE = "MIME_PARSE_FAILURE"
    FORENSIC_PROCESSING_FAILURE = "FORENSIC_PROCESSING_FAILURE"
    ALERT_DELIVERY_FAILURE = "ALERT_DELIVERY_FAILURE"
    CREDENTIAL_RETRIEVAL_FAILURE = "CREDENTIAL_RETRIEVAL_FAILURE"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"


def classify_operational_failure(exc: Optional[Exception]) -> str:
    """
    Classifies operational exceptions into standard fail-closed categories.
    Never exposes internal tokens, passwords, or raw credential strings.
    """
    if exc is None:
        return "NONE"

    type_name = type(exc).__name__.lower()
    msg = str(exc).lower()

    if "ssrf" in type_name or "ssrf" in msg:
        return FailureCategory.SSRF_BLOCKED

    if "tls" in type_name or "ssl" in type_name or "certificate" in type_name or "cert" in msg:
        return FailureCategory.TLS_FAILURE

    if "auth" in type_name or "credential" in type_name or "login" in msg or "unauthorized" in msg:
        if "retriev" in msg or "fetch" in msg or "keyring" in msg or "decrypt" in msg:
            return FailureCategory.CREDENTIAL_RETRIEVAL_FAILURE
        return FailureCategory.AUTHENTICATION_FAILED

    if "lease" in type_name or "lease" in msg:
        return FailureCategory.LEASE_LOST

    if "checkpoint" in type_name or "checkpoint" in msg:
        return FailureCategory.CHECKPOINT_FAILURE

    if "mime" in type_name or "mime" in msg or "parse" in type_name or "parse" in msg or "malformed" in msg:
        return FailureCategory.MIME_PARSE_FAILURE


    if "forensic" in type_name or "forensic" in msg:
        return FailureCategory.FORENSIC_PROCESSING_FAILURE

    if "alert" in type_name or "telegram" in type_name or "whatsapp" in type_name or "alert" in msg:
        return FailureCategory.ALERT_DELIVERY_FAILURE

    if (
        "timeout" in type_name
        or "timeout" in msg
        or "connection" in type_name
        or "socket" in type_name
        or "network" in type_name
        or "refused" in msg
        or "reset" in msg
        or "brokenpipe" in type_name
    ):
        return FailureCategory.NETWORK_FAILURE

    return FailureCategory.UNKNOWN_FAILURE


def compute_backoff_delay(
    attempt: int,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
) -> float:
    """
    Calculates bounded exponential backoff delay to avoid tight retry loops and server hammering.
    Formula: min(max_delay, base_delay * (backoff_factor ** max(0, attempt)))
    """
    safe_attempt = max(0, int(attempt))
    delay = base_delay * (backoff_factor ** safe_attempt)
    return min(float(max_delay), max(float(base_delay), float(delay)))


class OperationalRateLimiter:
    """
    Thread-safe operational rate limiter enforcing minimum time intervals between operations.
    Prevents tight polling loops, retry storms, and downstream service denial.
    """
    def __init__(self, min_interval_seconds: float = 1.0):
        self.min_interval = max(0.01, float(min_interval_seconds))
        self._last_time: Dict[str, float] = {}
        import threading
        self._lock = threading.Lock()

    def can_proceed(self, key: str = "default") -> bool:
        """Returns True if the minimum interval has elapsed since last operation."""
        now = time.time()
        with self._lock:
            last = self._last_time.get(key, 0.0)
            if now - last >= self.min_interval:
                self._last_time[key] = now
                return True
            return False

    def time_until_next(self, key: str = "default") -> float:
        """Returns remaining seconds before the operation can proceed."""
        now = time.time()
        with self._lock:
            last = self._last_time.get(key, 0.0)
            elapsed = now - last
            if elapsed >= self.min_interval:
                return 0.0
            return max(0.0, self.min_interval - elapsed)


