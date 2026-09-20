"""
worker/db.py
Database connection and RPC execution client for EMAILSHIELD INDIA Sentinel External Worker.
Enforces session role verification (sentinel_worker_daemon), least-privilege boundary checks
(direct table access denial), and interaction strictly via the 4 hardened PostgreSQL RPCs.
Supports both live PostgreSQL (via psycopg v3) and in-memory mock testing for isolation.
"""

import os
import time
import uuid
import hashlib
import threading
import json
from typing import Optional, Dict, Any, Tuple

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.errors import InsufficientPrivilege
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False
    InsufficientPrivilege = Exception  # Fallback

from worker.config import WorkerConfig, mask_db_url
from worker.logging import get_worker_logger

logger = get_worker_logger("sentinel.worker.db")


class WorkerDBError(Exception):
    """Base exception for worker database operations."""
    pass


class RoleVerificationError(WorkerDBError):
    """Raised when worker session identity does not match required role."""
    pass


class TableAccessViolationError(WorkerDBError):
    """Raised if direct table access is unexpectedly granted to worker."""
    pass


class WorkerDBClient:
    """
    Live PostgreSQL database client for the external Sentinel worker using psycopg v3.
    Operates strictly under sentinel_worker_daemon login role.
    """
    def __init__(self, config: WorkerConfig):
        if not PSYCOPG_AVAILABLE:
            raise WorkerDBError("psycopg library is not installed or available.")
        if not config.db_url:
            raise ValueError("Database URL is not configured in WorkerConfig.")
        self.config = config
        self._conn: Optional[psycopg.Connection] = None
        self._lock = threading.Lock()

    def connect(self) -> None:
        """Establishes a connection and verifies session_user identity and privileges."""
        with self._lock:
            if self._conn and not self._conn.closed:
                return

            retries = self.config.max_retries
            last_err = None
            for attempt in range(1, retries + 1):
                try:
                    logger.info("Connecting to PostgreSQL worker endpoint (attempt %d/%d)...", attempt, retries)
                    # psycopg v3 connection
                    self._conn = psycopg.connect(
                        self.config.db_url,
                        row_factory=dict_row,
                        autocommit=True,
                        connect_timeout=int(self.config.query_timeout_seconds),
                    )
                    # Set bounded statement timeout
                    with self._conn.cursor() as cur:
                        timeout_ms = int(self.config.query_timeout_seconds * 1000)
                        cur.execute(f"SET statement_timeout = {timeout_ms};")
                    break
                except Exception as e:
                    last_err = e
                    logger.warning("Worker connection attempt %d failed: %s", attempt, type(e).__name__)
                    time.sleep(self.config.retry_delay_seconds * attempt)

            if not self._conn or self._conn.closed:
                raise WorkerDBError(f"Failed to connect to worker database: {last_err}")

        # Verify session identity and privileges
        self.verify_session_identity()
        self.verify_table_privilege_denial()

    def close(self) -> None:
        """Closes the active database connection."""
        with self._lock:
            if self._conn and not self._conn.closed:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    def verify_session_identity(self) -> Tuple[str, str, str]:
        """
        Executes SELECT session_user, current_user, current_setting('role', true);
        and verifies identity conforms to sentinel_worker_daemon / sentinel_worker_role.
        """
        with self._lock:
            if not self._conn or self._conn.closed:
                raise WorkerDBError("Connection is closed.")
            with self._conn.cursor() as cur:
                cur.execute("SELECT session_user, current_user, current_setting('role', true) AS role_setting;")
                row = cur.fetchone()
                if not row:
                    raise RoleVerificationError("Failed to fetch session identity.")

                sess_user = row.get("session_user", "")
                curr_user = row.get("current_user", "")
                role_setting = row.get("role_setting", "")

                logger.info("Verified worker DB session: session_user=%s, current_user=%s", sess_user, curr_user)

                # Must be sentinel_worker_daemon or member of sentinel_worker_role
                allowed = ("sentinel_worker_daemon", "sentinel_worker_role")
                if sess_user not in allowed and curr_user not in allowed:
                    # Also check pg_has_role if running under custom pooler mapping
                    cur.execute("SELECT pg_has_role(session_user, 'sentinel_worker_role', 'MEMBER') AS is_member;")
                    has_role = cur.fetchone()
                    if not (has_role and has_role.get("is_member")):
                        raise RoleVerificationError(
                            f"Worker session_user '{sess_user}' is not authorized for sentinel_worker_role."
                        )

                return sess_user, curr_user, role_setting

    def verify_table_privilege_denial(self) -> None:
        """
        Confirms least-privilege boundary: direct table access must be DENIED.
        Attempts SELECT on sentinel_mailboxes and sentinel_workers.
        Must raise InsufficientPrivilege (42501).
        """
        with self._lock:
            if not self._conn or self._conn.closed:
                raise WorkerDBError("Connection is closed.")
            with self._conn.cursor() as cur:
                for table in ("sentinel_mailboxes", "sentinel_workers", "sentinel_checkpoints"):
                    try:
                        cur.execute(f"SELECT 1 FROM public.{table} LIMIT 1;")
                        # If query succeeded, worker has unauthorized table access!
                        raise TableAccessViolationError(
                            f"SECURITY VIOLATION: Worker has unauthorized direct SELECT access on public.{table}!"
                        )
                    except (InsufficientPrivilege, Exception) as err:
                        if isinstance(err, TableAccessViolationError):
                            raise
                        # Expected: permission denied for table
                        err_str = str(err).lower()
                        if "permission denied" in err_str or "insufficient_privilege" in err_str or "42501" in err_str:
                            logger.debug("Confirmed direct table access DENIED for public.%s", table)
                        else:
                            # Re-raise unexpected error
                            raise

    # -----------------------------------------------------------------
    # RPC 1: rpc_claim_worker_lease
    # -----------------------------------------------------------------
    def claim_worker_lease(self, worker_id: uuid.UUID, duration_seconds: int = 120) -> Dict[str, Any]:
        """Calls public.rpc_claim_worker_lease(p_worker_id, p_lease_duration_seconds)."""
        with self._lock:
            if not self._conn or self._conn.closed:
                self.connect()
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT public.rpc_claim_worker_lease(%s, %s) AS result;",
                    (str(worker_id), int(duration_seconds))
                )
                row = cur.fetchone()
                return row["result"] if row and row.get("result") else {"success": False, "reason": "empty_result"}

    # -----------------------------------------------------------------
    # RPC 2: rpc_renew_worker_lease
    # -----------------------------------------------------------------
    def renew_worker_lease(self, worker_id: uuid.UUID, lease_token: str, extension_seconds: int = 120) -> bool:
        """Calls public.rpc_renew_worker_lease(p_worker_id, p_lease_token, p_extension_seconds)."""
        with self._lock:
            if not self._conn or self._conn.closed:
                self.connect()
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT public.rpc_renew_worker_lease(%s, %s, %s) AS renewed;",
                    (str(worker_id), str(lease_token), int(extension_seconds))
                )
                row = cur.fetchone()
                return bool(row["renewed"]) if row else False

    # -----------------------------------------------------------------
    # RPC 3: rpc_release_worker_lease
    # -----------------------------------------------------------------
    def release_worker_lease(self, worker_id: uuid.UUID, lease_token: str) -> bool:
        """Calls public.rpc_release_worker_lease(p_worker_id, p_lease_token)."""
        with self._lock:
            if not self._conn or self._conn.closed:
                self.connect()
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT public.rpc_release_worker_lease(%s, %s) AS released;",
                    (str(worker_id), str(lease_token))
                )
                row = cur.fetchone()
                return bool(row["released"]) if row else False

    # -----------------------------------------------------------------
    # RPC 4: rpc_fetch_leased_mailbox_credential
    # -----------------------------------------------------------------
    def fetch_leased_mailbox_credential(self, worker_id: uuid.UUID, lease_token: str) -> Dict[str, Any]:
        """Calls public.rpc_fetch_leased_mailbox_credential(p_worker_id, p_lease_token)."""
        with self._lock:
            if not self._conn or self._conn.closed:
                self.connect()
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT public.rpc_fetch_leased_mailbox_credential(%s, %s) AS result;",
                    (str(worker_id), str(lease_token))
                )
                row = cur.fetchone()
                return row["result"] if row and row.get("result") else {"success": False, "reason": "empty_result"}


class MockWorkerDBClient:
    """
    High-fidelity in-memory database simulation conforming strictly to
    the Phase 4/5 SQL RPC contracts, table privilege denials, CAS versioning,
    and PostgreSQL concurrency semantics. Used for unit and concurrency tests.
    """
    def __init__(self, session_user: str = "sentinel_worker_daemon"):
        self.session_user = session_user
        self.current_user = session_user
        self.role_setting = "sentinel_worker_daemon"
        self._lock = threading.RLock()

        # Tables
        self.workers: Dict[str, Dict[str, Any]] = {}
        self.mailboxes: Dict[str, Dict[str, Any]] = {}
        self.checkpoints: Dict[str, Dict[str, Any]] = {}
        self.is_connected = False
        self.has_direct_table_access = False

    def connect(self) -> None:
        self.verify_session_identity()
        self.verify_table_privilege_denial()
        self.is_connected = True

    def close(self) -> None:
        self.is_connected = False

    def verify_session_identity(self) -> Tuple[str, str, str]:
        allowed = ("sentinel_worker_daemon", "sentinel_worker_role")
        if self.session_user not in allowed:
            raise RoleVerificationError(f"Session user '{self.session_user}' is not authorized.")
        return self.session_user, self.current_user, self.role_setting

    def verify_table_privilege_denial(self) -> None:
        # In mock, calling select_table directly will fail closed
        if self.has_direct_table_access:
            raise TableAccessViolationError("SECURITY VIOLATION: Worker has unauthorized direct SELECT access on public tables!")

    def direct_table_select(self, table_name: str) -> None:
        """Simulates direct table query attempt to confirm denial."""
        raise PermissionError(f"permission denied for table {table_name} (insufficient_privilege)")

    # -----------------------------------------------------------------
    # In-memory Helper: Seed worker & mailbox records
    # -----------------------------------------------------------------
    def seed_worker(
        self,
        worker_id: uuid.UUID,
        user_id: uuid.UUID,
        desired_state: str = "RUNNING",
        actual_state: str = "STOPPED",
        lease_owner: Optional[str] = None,
        lease_expires_at: Optional[float] = None,
        lease_token_hash: Optional[str] = None,
    ) -> None:
        with self._lock:
            self.workers[str(worker_id)] = {
                "id": str(worker_id),
                "user_id": str(user_id),
                "desired_state": desired_state,
                "actual_state": actual_state,
                "lease_owner": lease_owner,
                "lease_expires_at": lease_expires_at,
                "lease_token_hash": lease_token_hash,
                "poll_interval_seconds": 60,
                "last_heartbeat": time.time(),
                "updated_at": time.time(),
            }

    def seed_mailbox(
        self,
        mailbox_id: uuid.UUID,
        worker_id: uuid.UUID,
        user_id: uuid.UUID,
        encrypted_credentials: str,
        credential_version: int = 1,
        is_active: bool = True,
    ) -> None:
        with self._lock:
            self.mailboxes[str(mailbox_id)] = {
                "id": str(mailbox_id),
                "worker_id": str(worker_id),
                "user_id": str(user_id),
                "provider": "custom",
                "email_address": "synthetic@test.local",
                "imap_host": "imap.test.local",
                "imap_port": 993,
                "use_ssl": True,
                "auth_mechanism": "APP_PASSWORD",
                "encrypted_credentials": encrypted_credentials,
                "credential_version": credential_version,
                "credential_status": "ACTIVE",
                "is_active": is_active,
            }

    # -----------------------------------------------------------------
    # Simulation: rpc_claim_worker_lease
    # -----------------------------------------------------------------
    def claim_worker_lease(self, worker_id: uuid.UUID, duration_seconds: int = 120) -> Dict[str, Any]:
        with self._lock:
            # Step 1: Worker role authorization guard
            if self.session_user not in ("sentinel_worker_daemon", "sentinel_worker_role"):
                raise PermissionError("Access denied: caller is not a member of sentinel_worker_role")

            w_id = str(worker_id)
            if w_id not in self.workers:
                return {"success": False, "reason": "worker_unavailable_or_locked", "worker_id": w_id}

            worker = self.workers[w_id]
            now = time.time()

            # Step 2: Bound lease duration between 30 and 600 seconds
            clamped_duration = max(30, min(duration_seconds, 600))

            # Step 3: Concurrency check: worker must be in RUNNING state and unleased or expired
            is_expired = worker.get("lease_expires_at") is None or worker.get("lease_expires_at") < now
            is_unleased = worker.get("lease_owner") is None
            is_available = is_unleased or is_expired

            if worker.get("desired_state") != "RUNNING" or not is_available:
                return {"success": False, "reason": "worker_unavailable_or_locked", "worker_id": w_id}

            # Step 4: Generate 256-bit CSPRNG capability token
            raw_token_bytes = os.urandom(32)
            raw_token_hex = raw_token_bytes.hex()
            token_hash = hashlib.sha256(raw_token_bytes).hexdigest()

            # Step 5: Acquire lease and bind to session_user
            worker["lease_owner"] = self.session_user
            worker["lease_expires_at"] = now + clamped_duration
            worker["lease_token_hash"] = token_hash
            worker["actual_state"] = "RUNNING"
            worker["last_heartbeat"] = now
            worker["updated_at"] = now

            return {
                "success": True,
                "worker_id": w_id,
                "user_id": worker["user_id"],
                "lease_owner": self.session_user,
                "lease_token": raw_token_hex,
                "lease_expires_at": worker["lease_expires_at"],
                "lease_duration_seconds": clamped_duration,
            }

    # -----------------------------------------------------------------
    # Simulation: rpc_renew_worker_lease
    # -----------------------------------------------------------------
    def renew_worker_lease(self, worker_id: uuid.UUID, lease_token: str, extension_seconds: int = 120) -> bool:
        with self._lock:
            if self.session_user not in ("sentinel_worker_daemon", "sentinel_worker_role"):
                raise PermissionError("Access denied: caller is not a member of sentinel_worker_role")

            if not worker_id or not lease_token:
                return False

            try:
                raw_bytes = bytes.fromhex(lease_token)
                provided_hash = hashlib.sha256(raw_bytes).hexdigest()
            except Exception:
                return False

            w_id = str(worker_id)
            if w_id not in self.workers:
                return False

            worker = self.workers[w_id]
            now = time.time()
            clamped_seconds = max(30, min(extension_seconds, 300))

            if (
                worker.get("lease_owner") == self.session_user
                and worker.get("lease_token_hash") == provided_hash
                and worker.get("lease_expires_at", 0) > now
                and worker.get("desired_state") == "RUNNING"
            ):
                worker["lease_expires_at"] = now + clamped_seconds
                worker["last_heartbeat"] = now
                worker["updated_at"] = now
                return True

            return False

    # -----------------------------------------------------------------
    # Simulation: rpc_release_worker_lease
    # -----------------------------------------------------------------
    def release_worker_lease(self, worker_id: uuid.UUID, lease_token: str) -> bool:
        with self._lock:
            if self.session_user not in ("sentinel_worker_daemon", "sentinel_worker_role"):
                raise PermissionError("Access denied: caller is not a member of sentinel_worker_role")

            if not worker_id or not lease_token:
                return False

            try:
                raw_bytes = bytes.fromhex(lease_token)
                provided_hash = hashlib.sha256(raw_bytes).hexdigest()
            except Exception:
                return False

            w_id = str(worker_id)
            if w_id not in self.workers:
                return False

            worker = self.workers[w_id]

            if (
                worker.get("lease_owner") == self.session_user
                and worker.get("lease_token_hash") == provided_hash
            ):
                worker["lease_owner"] = None
                worker["lease_expires_at"] = None
                worker["lease_token_hash"] = None
                if worker.get("desired_state") == "RUNNING":
                    worker["actual_state"] = "STOPPED"
                worker["updated_at"] = time.time()
                return True

            return False

    # -----------------------------------------------------------------
    # Simulation: rpc_fetch_leased_mailbox_credential
    # -----------------------------------------------------------------
    def fetch_leased_mailbox_credential(self, worker_id: uuid.UUID, lease_token: str) -> Dict[str, Any]:
        with self._lock:
            if self.session_user not in ("sentinel_worker_daemon", "sentinel_worker_role"):
                raise PermissionError("Access denied: caller is not a member of sentinel_worker_role")

            if not worker_id or not lease_token:
                raise ValueError("p_worker_id and p_lease_token cannot be null")

            try:
                raw_bytes = bytes.fromhex(lease_token)
                provided_hash = hashlib.sha256(raw_bytes).hexdigest()
            except Exception:
                raise ValueError("Invalid capability token encoding")

            w_id = str(worker_id)
            if w_id not in self.workers:
                raise PermissionError(f"Worker {w_id} not found")

            worker = self.workers[w_id]
            now = time.time()

            if worker.get("lease_owner") != self.session_user:
                raise PermissionError(f"Lease violation: worker {w_id} is not leased by caller {self.session_user}")

            if worker.get("lease_expires_at", 0) <= now:
                raise PermissionError(f"Lease expired for worker {w_id}")

            if worker.get("desired_state") != "RUNNING":
                raise PermissionError(f"Worker {w_id} desired_state is not RUNNING")

            if worker.get("lease_token_hash") != provided_hash:
                raise PermissionError(f"Capability token verification failed for worker {w_id}")

            # Find mailbox for this worker and tenant user_id
            user_id = worker["user_id"]
            mailbox = next(
                (m for m in self.mailboxes.values() if m["worker_id"] == w_id and m["user_id"] == user_id),
                None
            )
            if not mailbox:
                return {"success": False, "reason": "mailbox_not_configured", "worker_id": w_id}

            if not mailbox.get("is_active"):
                return {"success": False, "reason": "mailbox_inactive", "worker_id": w_id}

            return {
                "success": True,
                "mailbox_id": mailbox["id"],
                "worker_id": mailbox["worker_id"],
                "user_id": mailbox["user_id"],
                "provider": mailbox["provider"],
                "email_address": mailbox["email_address"],
                "imap_host": mailbox["imap_host"],
                "imap_port": mailbox["imap_port"],
                "use_ssl": mailbox["use_ssl"],
                "auth_mechanism": mailbox["auth_mechanism"],
                "encrypted_credentials": mailbox["encrypted_credentials"],
                "credential_version": mailbox["credential_version"],
                "credential_status": mailbox["credential_status"],
            }


class LocalWorkerDBClient(MockWorkerDBClient):
    """
    Process-resilient, file-persisted local database client conforming strictly
    to the Phase 4/5 SQL RPC contracts, table privilege denials, CAS versioning,
    and least-privilege role verification (sentinel_worker_daemon).
    Used for external Sentinel worker processes in local execution environments.
    """
    LOCAL_DB_FILE = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data",
        "local",
        "sentinel_local_db.json"
    )

    def __init__(self, session_user: str = "sentinel_worker_daemon", db_path: Optional[str] = None):
        super().__init__(session_user=session_user)
        self.db_path = db_path or self.LOCAL_DB_FILE
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Loads state from local JSON storage atomically."""
        if not os.path.exists(self.db_path):
            return
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                if isinstance(data.get("workers"), dict):
                    self.workers.update(data["workers"])
                if isinstance(data.get("mailboxes"), dict):
                    self.mailboxes.update(data["mailboxes"])
                if isinstance(data.get("checkpoints"), dict):
                    self.checkpoints.update(data["checkpoints"])
        except Exception as e:
            logger.debug("Failed loading local worker DB state from %s: %s", self.db_path, e)

    def _save_to_disk(self) -> None:
        """Atomically persists state to disk."""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            tmp_path = self.db_path + ".tmp"
            with self._lock:
                payload = {
                    "workers": self.workers,
                    "mailboxes": self.mailboxes,
                    "checkpoints": self.checkpoints,
                    "updated_at": time.time(),
                }
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, self.db_path)
        except Exception as e:
            logger.warning("Failed persisting local worker DB state to %s: %s", self.db_path, e)

    def connect(self) -> None:
        self._load_from_disk()
        super().connect()

    def claim_worker_lease(self, worker_id: uuid.UUID, duration_seconds: int = 120) -> Dict[str, Any]:
        self._load_from_disk()
        w_id = str(worker_id)
        with self._lock:
            worker = self.workers.get(w_id)
            if worker and worker.get("lease_expires_at") and worker.get("lease_expires_at") >= time.time():
                if self.db_path == self.LOCAL_DB_FILE:
                    # Check if the process that previously held or registered the worker is dead
                    runtime_path = os.path.join(
                        os.path.dirname(os.path.dirname(__file__)),
                        "data", "local", "sentinel_worker_runtime.json"
                    )
                    if os.path.exists(runtime_path):
                        try:
                            with open(runtime_path, "r", encoding="utf-8") as rf:
                                rdata = json.load(rf)
                            rpid = rdata.get("pid")
                            from worker.health import is_pid_alive
                            if rpid and not is_pid_alive(rpid):
                                worker["lease_owner"] = None
                                worker["lease_expires_at"] = None
                                worker["lease_token_hash"] = None
                        except Exception:
                            pass
        result = super().claim_worker_lease(worker_id, duration_seconds)
        if result and result.get("success"):
            self._save_to_disk()
        return result

    def renew_worker_lease(self, worker_id: uuid.UUID, lease_token: str, extension_seconds: int = 120) -> bool:
        self._load_from_disk()
        result = super().renew_worker_lease(worker_id, lease_token, extension_seconds)
        if result:
            self._save_to_disk()
        return result

    def release_worker_lease(self, worker_id: uuid.UUID, lease_token: str) -> bool:
        self._load_from_disk()
        result = super().release_worker_lease(worker_id, lease_token)
        if result:
            self._save_to_disk()
        return result

    def fetch_leased_mailbox_credential(self, worker_id: uuid.UUID, lease_token: str) -> Dict[str, Any]:
        self._load_from_disk()
        return super().fetch_leased_mailbox_credential(worker_id, lease_token)

    @classmethod
    def sync_mailbox_and_worker(
        cls,
        worker_id: str,
        user_id: str,
        email_address: str,
        encrypted_credentials: str,
        imap_host: str = "imap.gmail.com",
        imap_port: int = 993,
        use_ssl: bool = True,
        provider: str = "gmail",
        desired_state: str = "RUNNING",
        db_path: Optional[str] = None,
        mailbox_id: Optional[str] = None,
    ) -> str:
        """Class helper to synchronize worker and mailbox records from control plane."""
        client = cls(db_path=db_path)
        client._load_from_disk()
        if not mailbox_id:
            # Check if mailbox for this user already exists
            for m_id, m in client.mailboxes.items():
                if m.get("user_id") == str(user_id) and m.get("worker_id") == str(worker_id):
                    mailbox_id = m_id
                    break
            if not mailbox_id:
                # Also check by (user_id, email_address)
                for m_id, m in client.mailboxes.items():
                    if m.get("user_id") == str(user_id) and m.get("email_address") == email_address:
                        mailbox_id = m_id
                        break
            if not mailbox_id:
                mailbox_id = str(uuid.uuid4())

        now = time.time()
        client.seed_worker(
            worker_id=uuid.UUID(str(worker_id)),
            user_id=uuid.UUID(str(user_id)),
            desired_state=desired_state,
            actual_state="STOPPED"
        )
        with client._lock:
            # Deactivate any previous mailboxes for this user to maintain single active mailbox invariant
            for m_id, m in client.mailboxes.items():
                if m.get("user_id") == str(user_id) and m_id != mailbox_id:
                    m["is_active"] = False
                    m["updated_at"] = now
            client.mailboxes[mailbox_id] = {
                "id": mailbox_id,
                "worker_id": str(worker_id),
                "user_id": str(user_id),
                "provider": provider,
                "email_address": email_address,
                "imap_host": imap_host,
                "imap_port": int(imap_port),
                "use_ssl": bool(use_ssl),
                "auth_mechanism": "APP_PASSWORD",
                "encrypted_credentials": encrypted_credentials,
                "credential_version": 1,
                "credential_status": "ACTIVE",
                "is_active": True,
                "updated_at": now,
            }
        client._save_to_disk()
        return mailbox_id

    @classmethod
    def set_desired_state(cls, user_id: str, desired_state: str, db_path: Optional[str] = None) -> bool:
        """Class helper to update desired state of worker."""
        client = cls(db_path=db_path)
        client._load_from_disk()
        updated = False
        with client._lock:
            for w in client.workers.values():
                if w.get("user_id") == str(user_id):
                    w["desired_state"] = desired_state
                    w["updated_at"] = time.time()
                    updated = True
        if updated:
            client._save_to_disk()
        return updated

    @classmethod
    def deactivate_mailbox(cls, user_id: str, db_path: Optional[str] = None) -> bool:
        """Class helper to deactivate mailbox and set desired_state STOPPED."""
        client = cls(db_path=db_path)
        client._load_from_disk()
        updated = False
        with client._lock:
            for w in client.workers.values():
                if w.get("user_id") == str(user_id):
                    w["desired_state"] = "STOPPED"
                    w["lease_owner"] = None
                    w["lease_expires_at"] = None
                    w["lease_token_hash"] = None
                    w["actual_state"] = "STOPPED"
                    w["updated_at"] = time.time()
                    updated = True
            for m in client.mailboxes.values():
                if m.get("user_id") == str(user_id):
                    m["is_active"] = False
                    m["encrypted_credentials"] = "REVOKED"
                    m["updated_at"] = time.time()
                    updated = True
        if updated:
            client._save_to_disk()
        return updated

    @classmethod
    def force_release_worker_lease(cls, worker_id: Optional[str] = None, db_path: Optional[str] = None) -> bool:
        """Class helper to immediately clear held lease on worker shutdown or restart."""
        client = cls(db_path=db_path)
        client._load_from_disk()
        updated = False
        with client._lock:
            for wid, w in client.workers.items():
                if worker_id is None or wid == str(worker_id):
                    w["lease_owner"] = None
                    w["lease_expires_at"] = None
                    w["lease_token_hash"] = None
                    w["actual_state"] = "STOPPED"
                    w["updated_at"] = time.time()
                    updated = True
        if updated:
            client._save_to_disk()
        return updated

    @classmethod
    def has_other_active_mailboxes(cls, exclude_user_id: Optional[str] = None, db_path: Optional[str] = None) -> bool:
        """Checks if any active mailboxes exist, optionally excluding a specific user."""
        client = cls(db_path=db_path)
        client._load_from_disk()
        with client._lock:
            for m in client.mailboxes.values():
                if m.get("is_active"):
                    if exclude_user_id is None or m.get("user_id") != str(exclude_user_id):
                        return True
        return False

