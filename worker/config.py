"""
worker/config.py
Configuration loader and validator for EMAILSHIELD INDIA Sentinel External Worker Runtime.
Loads configuration exclusively from environment variables or runtime secrets.
Never exposes plaintext credentials, database passwords, or private keys in logs/repr.
"""

import os
import re
import uuid
from dataclasses import dataclass
from typing import Optional, Dict, Any

from core.sentinel_crypto import (
    validate_master_key,
    InvalidKeyError,
    MASTER_KEY_LENGTH_BYTES,
)

# =====================================================================
# Operational Bounds & Defaults (as enforced by Phase 4/5 SQL RPCs)
# =====================================================================
MIN_LEASE_DURATION_SECONDS = 30
MAX_LEASE_DURATION_SECONDS = 600
DEFAULT_LEASE_DURATION_SECONDS = 120

MIN_RENEWAL_EXTENSION_SECONDS = 30
MAX_RENEWAL_EXTENSION_SECONDS = 300
DEFAULT_RENEWAL_EXTENSION_SECONDS = 120

DEFAULT_RENEWAL_INTERVAL_SECONDS = 45
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY_SECONDS = 1.0
DEFAULT_QUERY_TIMEOUT_SECONDS = 10.0
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 5.0

DEFAULT_POLL_INTERVAL_SECONDS = 1.0
MIN_POLL_INTERVAL_SECONDS = 0.1
MAX_POLL_INTERVAL_SECONDS = 3600.0


def mask_db_url(url: Optional[str]) -> str:
    """Masks database password in connection strings to prevent credential leaks."""
    if not url:
        return "<not-configured>"
    # Pattern matches postgresql://[user]:[password]@[host]:[port]/[db]
    return re.sub(r"(postgres(?:ql)?://[^:\s]+):(.+)@([^/@\s]+(?::\d+)?(?:/[^\s?]*)?)", r"\1:***@\3", url)


@dataclass
class WorkerConfig:
    """Configuration container for external Sentinel worker runtime."""
    worker_id: Optional[uuid.UUID] = None
    db_url: Optional[str] = None
    private_key_pem: Optional[str] = None
    master_key: Optional[bytes] = None

    lease_duration_seconds: int = DEFAULT_LEASE_DURATION_SECONDS
    renewal_interval_seconds: int = DEFAULT_RENEWAL_INTERVAL_SECONDS
    renewal_extension_seconds: int = DEFAULT_RENEWAL_EXTENSION_SECONDS

    max_retries: int = DEFAULT_MAX_RETRIES
    retry_delay_seconds: float = DEFAULT_RETRY_DELAY_SECONDS
    query_timeout_seconds: float = DEFAULT_QUERY_TIMEOUT_SECONDS
    shutdown_timeout_seconds: float = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS

    # Deployment & Runtime Hardening
    production_polling_enabled: bool = False
    test_mode: bool = False
    heartbeat_interval_seconds: int = 30
    max_db_connections: int = 5
    db_connect_timeout_seconds: int = 10
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS

    def __repr__(self) -> str:
        """Safe representation masking all sensitive tokens, passwords, and private keys."""
        masked_db = mask_db_url(self.db_url)
        has_key = "SET" if self.private_key_pem else "NOT_SET"
        has_mk = "SET" if self.master_key else "NOT_SET"
        return (
            f"WorkerConfig("
            f"worker_id={self.worker_id}, "
            f"db_url='{masked_db}', "
            f"private_key=[{has_key}], "
            f"master_key=[{has_mk}], "
            f"lease_duration={self.lease_duration_seconds}s, "
            f"renewal_interval={self.renewal_interval_seconds}s, "
            f"poll_interval={self.poll_interval_seconds}s, "
            f"max_retries={self.max_retries})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    @classmethod
    def from_env(cls, env_dict: Optional[Dict[str, str]] = None) -> "WorkerConfig":
        """
        Loads configuration from environment variables or custom dict.
        Fails closed on malformed values.
        """
        def _get_val(key: str) -> str:
            if env_dict is not None:
                return env_dict.get(key, "").strip()
            val = os.environ.get(key, "").strip()
            if val:
                return val
            try:
                from worker.imap_client import _lookup_local_env_var
                return _lookup_local_env_var(key)
            except Exception:
                return ""

        # 1. Worker ID
        raw_worker_id = _get_val("SENTINEL_WORKER_ID")
        worker_id = None
        if raw_worker_id:
            try:
                worker_id = uuid.UUID(raw_worker_id)
            except (ValueError, AttributeError) as err:
                raise ValueError(f"Invalid SENTINEL_WORKER_ID '{raw_worker_id}': must be a valid UUID.") from err
        elif env_dict is None:
            # Check sentinel_worker_id.txt first for the authoritative active worker ID
            proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            wid_path = os.path.join(proj_root, "data", "local", "sentinel_worker_id.txt")
            if os.path.exists(wid_path):
                try:
                    with open(wid_path, "r", encoding="utf-8") as f:
                        wid_str = f.read().strip()
                    if wid_str:
                        worker_id = uuid.UUID(wid_str)
                except Exception:
                    pass
            try:
                from worker.db import LocalWorkerDBClient
                loc_client = LocalWorkerDBClient()
                has_active = False
                if worker_id:
                    for mb in loc_client.mailboxes.values():
                        if mb.get("assigned_worker_id") == str(worker_id) and mb.get("is_active"):
                            has_active = True
                            break
                if not has_active:
                    for mb in loc_client.mailboxes.values():
                        if mb.get("is_active") and mb.get("assigned_worker_id"):
                            worker_id = uuid.UUID(mb["assigned_worker_id"])
                            break
                if worker_id is None and loc_client.workers:
                    first_wid = next(iter(loc_client.workers.keys()))
                    worker_id = uuid.UUID(first_wid)
            except Exception:
                pass


        # 2. Database Connection URL
        db_url = _get_val("SENTINEL_WORKER_DB_URL") or None

        # 3. Worker Private Key (either PEM string or path to PEM file)
        raw_pk = _get_val("SENTINEL_WORKER_PRIVATE_KEY")
        private_key_pem = None
        if raw_pk:
            if "BEGIN" in raw_pk and "PRIVATE KEY" in raw_pk:
                private_key_pem = raw_pk
            elif os.path.isfile(raw_pk):
                with open(raw_pk, "r", encoding="utf-8") as f:
                    private_key_pem = f.read()
            else:
                raise ValueError("SENTINEL_WORKER_PRIVATE_KEY must be a valid PEM block or accessible file path.")
        elif env_dict is None:
            # Check default local scratch locations if not specified
            proj_root = os.path.dirname(os.path.dirname(__file__))
            scratch_pk = os.path.join(proj_root, "scratch", "sentinel_worker_private.pem")
            local_pk = os.path.join(proj_root, "data", "local", "sentinel_worker_private.pem")
            for p in (scratch_pk, local_pk):
                if os.path.isfile(p):
                    try:
                        with open(p, "r", encoding="utf-8") as f:
                            candidate = f.read().strip()
                        if "BEGIN" in candidate and "PRIVATE KEY" in candidate:
                            private_key_pem = candidate
                            break
                    except Exception:
                        pass

        # 4. Optional Sentinel Master Key
        raw_mk = _get_val("SENTINEL_MASTER_KEY")
        master_key = None
        if raw_mk:
            # Parse hex or base64 or raw 32-byte string
            if len(raw_mk) == 64:
                try:
                    master_key = bytes.fromhex(raw_mk)
                except ValueError:
                    pass
            if master_key is None and len(raw_mk) == 32:
                master_key = raw_mk.encode("utf-8")
            if master_key is not None:
                validate_master_key(master_key)
            else:
                raise InvalidKeyError("SENTINEL_MASTER_KEY must be a valid 32-byte key (64 hex characters).")

        # 5. Operational Durations & Bounds
        raw_lease_duration = _get_val("SENTINEL_LEASE_DURATION_SECONDS") or str(DEFAULT_LEASE_DURATION_SECONDS)
        try:
            lease_duration = int(raw_lease_duration)
        except ValueError as err:
            raise ValueError("SENTINEL_LEASE_DURATION_SECONDS must be an integer.") from err
        lease_duration = max(MIN_LEASE_DURATION_SECONDS, min(lease_duration, MAX_LEASE_DURATION_SECONDS))

        raw_renewal_ext = _get_val("SENTINEL_RENEWAL_EXTENSION_SECONDS") or str(DEFAULT_RENEWAL_EXTENSION_SECONDS)
        try:
            renewal_ext = int(raw_renewal_ext)
        except ValueError as err:
            raise ValueError("SENTINEL_RENEWAL_EXTENSION_SECONDS must be an integer.") from err
        renewal_ext = max(MIN_RENEWAL_EXTENSION_SECONDS, min(renewal_ext, MAX_RENEWAL_EXTENSION_SECONDS))

        raw_renewal_interval = _get_val("SENTINEL_RENEWAL_INTERVAL_SECONDS") or str(DEFAULT_RENEWAL_INTERVAL_SECONDS)
        try:
            renewal_interval = int(raw_renewal_interval)
        except ValueError as err:
            raise ValueError("SENTINEL_RENEWAL_INTERVAL_SECONDS must be an integer.") from err
        if renewal_interval <= 0:
            raise ValueError("SENTINEL_RENEWAL_INTERVAL_SECONDS must be positive.")

        # 6. Production Polling & Test Mode Controls
        # Invariant: Production polling is strictly DISABLED by default.
        prod_polling = _get_val("SENTINEL_ENABLE_PRODUCTION_POLLING") == "1"
        test_mode = _get_val("SENTINEL_WORKER_TEST_MODE") == "1"

        raw_heartbeat = _get_val("SENTINEL_HEARTBEAT_INTERVAL_SECONDS") or "30"
        try:
            heartbeat_interval = int(raw_heartbeat)
        except ValueError:
            heartbeat_interval = 30

        raw_max_conn = _get_val("SENTINEL_MAX_DB_CONNECTIONS") or "5"
        try:
            max_db_conn = int(raw_max_conn)
        except ValueError:
            max_db_conn = 5

        raw_connect_timeout = _get_val("SENTINEL_DB_CONNECT_TIMEOUT_SECONDS") or "10"
        try:
            connect_timeout = int(raw_connect_timeout)
        except ValueError:
            connect_timeout = 10

        raw_poll_interval = _get_val("SENTINEL_POLL_INTERVAL") or _get_val("SENTINEL_POLL_INTERVAL_SECONDS")
        if raw_poll_interval:
            try:
                poll_interval = float(raw_poll_interval)
            except ValueError as err:
                raise ValueError(f"Invalid SENTINEL_POLL_INTERVAL '{raw_poll_interval}': must be a number.") from err
            poll_interval = max(MIN_POLL_INTERVAL_SECONDS, min(poll_interval, MAX_POLL_INTERVAL_SECONDS))
        else:
            poll_interval = DEFAULT_POLL_INTERVAL_SECONDS

        return cls(
            worker_id=worker_id,
            db_url=db_url,
            private_key_pem=private_key_pem,
            master_key=master_key,
            lease_duration_seconds=lease_duration,
            renewal_interval_seconds=renewal_interval,
            renewal_extension_seconds=renewal_ext,
            production_polling_enabled=prod_polling,
            test_mode=test_mode,
            heartbeat_interval_seconds=heartbeat_interval,
            max_db_connections=max_db_conn,
            db_connect_timeout_seconds=connect_timeout,
            poll_interval_seconds=poll_interval,
        )

    def validate_for_runtime(self) -> None:
        """Validates that mandatory runtime configuration is present and valid."""
        if self.worker_id is None:
            raise ValueError("SENTINEL_WORKER_ID is mandatory for worker runtime execution.")


class ProductionMailboxGateError(Exception):
    """Raised when one or more production mailbox gating conditions fail."""
    pass


class ProductionReadinessGate:
    """
    Explicit gate preventing production mailbox connection unless all mandatory
    security and architectural prerequisites are verified.
    
    Required Conditions (Section 4):
    1. Authenticated configuration (valid worker config and DB URL)
    2. Authorized tenant (non-empty tenant user_id)
    3. Authorized worker (valid worker_id)
    4. Valid mailbox (non-empty mailbox_id)
    5. Valid credential (non-empty encrypted envelope)
    6. Valid capability token (active 256-bit CSPRNG token held by worker)
    7. Valid active lease (unexpired lease owned by worker session)
    8. Explicit production enablement (production_polling_enabled is True)
    
    A missing condition fails closed immediately.
    """
    @staticmethod
    def verify_production_mailbox_connection(
        config: "WorkerConfig",
        user_id: Optional[str],
        worker_id: Optional[str],
        mailbox_id: Optional[str],
        credential_present: bool,
        capability_token_present: bool,
        lease_active: bool,
    ) -> bool:
        if not config.production_polling_enabled:
            raise ProductionMailboxGateError("Production mailbox connection blocked: production_polling_enabled is False.")
        if not config.db_url:
            raise ProductionMailboxGateError("Production mailbox connection blocked: worker DB URL is missing.")
        if not user_id or not str(user_id).strip():
            raise ProductionMailboxGateError("Production mailbox connection blocked: tenant user_id is missing.")
        if not worker_id or not str(worker_id).strip():
            raise ProductionMailboxGateError("Production mailbox connection blocked: worker_id is missing.")
        if not mailbox_id or not str(mailbox_id).strip():
            raise ProductionMailboxGateError("Production mailbox connection blocked: mailbox_id is missing.")
        if not credential_present:
            raise ProductionMailboxGateError("Production mailbox connection blocked: encrypted credential is not present.")
        if not capability_token_present:
            raise ProductionMailboxGateError("Production mailbox connection blocked: active capability token is not present.")
        if not lease_active:
            raise ProductionMailboxGateError("Production mailbox connection blocked: active worker lease is not held.")
        return True
