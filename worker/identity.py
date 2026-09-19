"""
worker/identity.py
Worker Identity and Capability-Token Management for EMAILSHIELD INDIA Sentinel.
Enforces strict worker identity binding, in-memory capability-token isolation,
constant-time hash comparison, memory wiping, and zero leakage in __repr__/__str__.
"""

import hmac
import hashlib
import uuid
import re
from typing import Optional


class CapabilityToken:
    """
    Encapsulates an ephemeral 256-bit capability token granted by PostgreSQL
    during lease acquisition (rpc_claim_worker_lease).
    
    Security Properties:
    - Raw token is held in-memory only.
    - Never prints raw token in __repr__ or __str__ (fail-safe redaction).
    - Computes SHA-256 hash matching PostgreSQL encode(sha256(decode(token, 'hex')), 'hex').
    - Provides constant-time verification via hmac.compare_digest.
    - Explicit wipe via clear() removes the token from memory.
    """
    def __init__(self, raw_token_hex: str):
        if not isinstance(raw_token_hex, str) or not raw_token_hex.strip():
            raise ValueError("Capability token must be a non-empty string.")
        
        cleaned = raw_token_hex.strip()
        if not re.match(r"^[0-9a-fA-F]{64}$", cleaned):
            raise ValueError(f"Invalid capability token format: expected 64 hex characters (256 bits), got {len(cleaned)} chars.")
        
        self._raw_token: Optional[str] = cleaned
        # Hash matches PostgreSQL: sha256 of the 32 raw bytes
        raw_bytes = bytes.fromhex(self._raw_token)
        self._token_hash: Optional[str] = hashlib.sha256(raw_bytes).hexdigest()

    @property
    def raw_token(self) -> str:
        """Access the raw token for RPC authentication only."""
        if self._raw_token is None:
            raise ValueError("Capability token has been wiped or is invalid.")
        return self._raw_token

    @property
    def token_hash(self) -> str:
        """The SHA-256 hex digest of the 32 raw token bytes."""
        if self._token_hash is None:
            raise ValueError("Capability token has been wiped or is invalid.")
        return self._token_hash

    def verify_hash(self, candidate_hash: str) -> bool:
        """Constant-time verification against a candidate SHA-256 hex string."""
        if self._token_hash is None or not candidate_hash:
            return False
        return hmac.compare_digest(self._token_hash.lower(), candidate_hash.strip().lower())

    def clear(self) -> None:
        """Explicitly wipes the capability token from memory."""
        self._raw_token = None
        self._token_hash = None

    def is_active(self) -> bool:
        return self._raw_token is not None

    def __repr__(self) -> str:
        status = "ACTIVE" if self._raw_token is not None else "WIPED"
        return f"<CapabilityToken: [REDACTED_{status}]>"

    def __str__(self) -> str:
        return self.__repr__()


class WorkerIdentity:
    """
    Manages the authoritative identity of the running Sentinel worker.
    
    Security Properties:
    - Worker identity is strictly bound to its configured worker_id (UUID).
    - Prohibits accepting caller-supplied tenant IDs or mailbox IDs.
    - Tenant ownership is resolved authoritatively by the database kernel.
    - Binds and lifecycle-manages the worker's active CapabilityToken.
    """
    def __init__(self, worker_id: uuid.UUID):
        if not isinstance(worker_id, uuid.UUID):
            raise ValueError("WorkerIdentity requires a valid uuid.UUID instance.")
        self._worker_id: uuid.UUID = worker_id
        self._token: Optional[CapabilityToken] = None

    @property
    def worker_id(self) -> uuid.UUID:
        return self._worker_id

    @property
    def worker_id_str(self) -> str:
        return str(self._worker_id)

    def bind_token(self, raw_token_hex: str) -> CapabilityToken:
        """Binds a fresh capability token received from rpc_claim_worker_lease."""
        if self._token is not None:
            self._token.clear()
        self._token = CapabilityToken(raw_token_hex)
        return self._token

    def clear_token(self) -> None:
        """Invalidates and clears the current capability token."""
        if self._token is not None:
            self._token.clear()
            self._token = None

    def clear(self) -> None:
        """Best-effort cleanup: invalidates and clears the current capability token."""
        self.clear_token()

    def has_token(self) -> bool:
        return self._token is not None and self._token.is_active()

    @property
    def token(self) -> Optional[CapabilityToken]:
        return self._token

    @property
    def raw_token(self) -> Optional[str]:
        return self._token.raw_token if self._token and self._token.is_active() else None

    @property
    def token_hash(self) -> Optional[str]:
        return self._token.token_hash if self._token and self._token.is_active() else None

    def __setattr__(self, name: str, value: object) -> None:
        if name in ("user_id", "tenant_id", "mailbox_id"):
            raise AttributeError(f"Worker cannot be configured with arbitrary '{name}'. Identity is bound strictly to worker_id.")
        super().__setattr__(name, value)

    def __repr__(self) -> str:
        has_tok = "YES" if self.has_token() else "NO"
        return f"WorkerIdentity(worker_id={self._worker_id}, has_active_token={has_tok})"

    def __str__(self) -> str:
        return self.__repr__()
