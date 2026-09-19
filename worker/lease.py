"""
worker/lease.py
Worker Lease Lifecycle Manager for EMAILSHIELD INDIA Sentinel External Worker.
Coordinates lease acquisition, renewal, release, and capability-token lifecycle
strictly via the database RPC boundary and WorkerIdentity.
"""

import time
import uuid
from typing import Optional, Dict, Any, Union

from worker.identity import WorkerIdentity
from worker.db import WorkerDBClient, MockWorkerDBClient
from worker.logging import get_worker_logger

logger = get_worker_logger("sentinel.worker.lease")


class WorkerLeaseManager:
    """
    Manages the lifecycle of a worker lease:
    - Atomic claim via rpc_claim_worker_lease
    - In-memory capability token binding
    - Heartbeat / periodic renewal via rpc_renew_worker_lease
    - Clean release and memory wipe via rpc_release_worker_lease
    """
    def __init__(
        self,
        identity: WorkerIdentity,
        db_client: Union[WorkerDBClient, MockWorkerDBClient]
    ):
        self.identity = identity
        self.db_client = db_client
        self._expires_at: Optional[float] = None
        self._duration_seconds: int = 120
        self._tenant_user_id: Optional[str] = None

    @property
    def worker_id(self) -> uuid.UUID:
        return self.identity.worker_id

    @property
    def tenant_user_id(self) -> Optional[str]:
        return self._tenant_user_id

    def is_active(self) -> bool:
        """Returns True if the worker currently holds an unexpired lease with active capability token."""
        if not self.identity.has_token():
            return False
        if self._expires_at is None:
            return False
        return time.time() < self._expires_at

    def time_until_expiry(self) -> float:
        """Returns remaining seconds on active lease, or 0.0 if not active."""
        if not self.is_active() or self._expires_at is None:
            return 0.0
        return max(0.0, self._expires_at - time.time())

    def acquire_lease(self, duration_seconds: int = 120) -> bool:
        """
        Attempts to atomically claim the worker lease.
        If successful, binds the received capability token to WorkerIdentity.
        """
        logger.info("Attempting to acquire lease for worker %s (duration=%ds)...", self.identity.worker_id, duration_seconds)
        try:
            result = self.db_client.claim_worker_lease(self.identity.worker_id, duration_seconds)
            if not result or not result.get("success"):
                reason = result.get("reason", "unknown") if result else "null_response"
                logger.warning("Lease claim denied for worker %s: %s", self.identity.worker_id, reason)
                return False

            raw_token = result.get("lease_token")
            if not raw_token:
                logger.error("Database returned lease claim success but omitted capability token!")
                return False

            # Bind token securely in memory
            self.identity.bind_token(raw_token)
            
            # Record expiry timestamp (handle either float seconds or ISO string)
            expires_val = result.get("lease_expires_at")
            if isinstance(expires_val, (int, float)):
                self._expires_at = float(expires_val)
            else:
                # Fallback to local time offset if string/datetime returned
                dur = int(result.get("lease_duration_seconds", duration_seconds))
                self._expires_at = time.time() + dur

            self._duration_seconds = int(result.get("lease_duration_seconds", duration_seconds))
            self._tenant_user_id = str(result.get("user_id")) if result.get("user_id") else None

            logger.info("Successfully acquired lease for worker %s (duration=%ds)", self.identity.worker_id, self._duration_seconds)
            return True
        except Exception as e:
            logger.error("Exception during lease claim: %s", type(e).__name__)
            return False

    def renew_lease(self, extension_seconds: int = 120) -> bool:
        """
        Renews active lease using the held capability token.
        Fails if no lease is active or if token is invalid.
        """
        if not self.identity.has_token():
            logger.warning("Cannot renew lease: worker %s holds no capability token.", self.identity.worker_id)
            return False

        raw_token = self.identity.raw_token
        if not raw_token:
            return False

        logger.info("Attempting to renew lease for worker %s (extension=%ds)...", self.identity.worker_id, extension_seconds)
        try:
            success = self.db_client.renew_worker_lease(self.identity.worker_id, raw_token, extension_seconds)
            if success:
                self._expires_at = time.time() + extension_seconds
                logger.info("Lease renewed successfully for worker %s.", self.identity.worker_id)
                return True
            else:
                logger.warning("Lease renewal denied or failed for worker %s.", self.identity.worker_id)
                return False
        except Exception as e:
            logger.error("Exception during lease renewal: %s", type(e).__name__)
            return False

    def release_lease(self) -> bool:
        """
        Releases the active lease and wipes capability token from memory.
        Guarantees that token is wiped even if RPC call raises an exception.
        """
        if not self.identity.has_token():
            self._expires_at = None
            return True

        raw_token = self.identity.raw_token
        success = False
        try:
            if raw_token:
                logger.info("Releasing lease for worker %s...", self.identity.worker_id)
                success = self.db_client.release_worker_lease(self.identity.worker_id, raw_token)
        except Exception as e:
            logger.error("Exception during lease release RPC: %s", type(e).__name__)
        finally:
            # Absolute invariant: wipe in-memory token on release
            self.identity.clear_token()
            self._expires_at = None
            logger.info("Capability token invalidated and cleared from memory.")

        return success

    def get_status(self) -> Dict[str, Any]:
        """Returns safe operational status without exposing capability tokens or credentials."""
        return {
            "worker_id": str(self.identity.worker_id),
            "is_active": self.is_active(),
            "expires_at": self._expires_at,
            "seconds_remaining": self.time_until_expiry(),
            "has_token": self.identity.has_token(),
        }
