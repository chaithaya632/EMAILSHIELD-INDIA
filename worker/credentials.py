"""
worker/credentials.py
Leased credential container and worker-only decryption service for EMAILSHIELD INDIA Sentinel.
Enforces best-effort in-memory secret scrubbing, strict redaction in logs/repr,
and private-key decryption bound to authoritative tenant AAD context.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, Union

from core.sentinel_crypto import (
    WorkerKeyRing,
    CONTEXT_MAILBOX,
    DecryptionError,
    UnknownKeyVersionError,
    PayloadFormatError,
)
from worker.identity import WorkerIdentity
from worker.db import WorkerDBClient, MockWorkerDBClient
from worker.logging import get_worker_logger

logger = get_worker_logger("sentinel.worker.credentials")


@dataclass
class LeasedCredential:
    """
    In-memory container for a leased mailbox credential retrieved via
    rpc_fetch_leased_mailbox_credential and decrypted inside worker memory.
    
    Security Properties:
    - Never prints secret password in __repr__ or __str__.
    - Provides explicit clear() for best-effort memory cleanup.
    - Supports context management (with credential: ...) for automatic scrubbing.
    """
    mailbox_id: str
    worker_id: str
    user_id: str
    provider: str
    email_address: str
    imap_host: str
    imap_port: int
    use_ssl: bool
    auth_mechanism: str
    credential_version: int
    _secret: Optional[str] = None

    @property
    def secret(self) -> str:
        """Returns the decrypted plaintext secret for operational worker use only."""
        if self._secret is None:
            raise ValueError("Credential secret has been wiped or is unavailable.")
        return self._secret

    def clear(self) -> None:
        """Best-effort memory cleanup: wipes secret from memory."""
        self._secret = None

    def __enter__(self) -> "LeasedCredential":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.clear()

    def __repr__(self) -> str:
        status = "ACTIVE" if self._secret is not None else "WIPED"
        return (
            f"LeasedCredential("
            f"mailbox_id='{self.mailbox_id}', "
            f"worker_id='{self.worker_id}', "
            f"user_id='{self.user_id}', "
            f"provider='{self.provider}', "
            f"email='{self.email_address}', "
            f"secret=[REDACTED_{status}])"
        )

    def __str__(self) -> str:
        return self.__repr__()


class WorkerCredentialService:
    """
    Coordinates RPC credential retrieval and worker-only asymmetric decryption.
    """
    def __init__(
        self,
        identity: WorkerIdentity,
        keyring: WorkerKeyRing,
        db_client: Union[WorkerDBClient, MockWorkerDBClient]
    ):
        self.identity = identity
        self.keyring = keyring
        self.db_client = db_client

    def fetch_and_decrypt(self) -> LeasedCredential:
        """
        Retrieves the encrypted credential envelope via rpc_fetch_leased_mailbox_credential
        using the held capability token, and decrypts the payload inside worker runtime.
        
        Fails closed if:
        - Worker does not hold an active capability token.
        - Database returns failure or inactive mailbox.
        - Ciphertext or AAD has been tampered with.
        - Private key does not match envelope key version.
        - Tenant context (user_id) does not match envelope AAD.
        """
        if not self.identity.has_token():
            raise PermissionError("Worker does not hold an active capability token.")

        raw_token = self.identity.raw_token
        if not raw_token:
            raise PermissionError("Capability token is invalid or cleared.")

        logger.info("Fetching encrypted mailbox credential for worker %s...", self.identity.worker_id)
        result = self.db_client.fetch_leased_mailbox_credential(self.identity.worker_id, raw_token)

        if not result or not result.get("success"):
            reason = result.get("reason", "unknown") if result else "null_response"
            logger.warning("Credential fetch denied for worker %s: %s", self.identity.worker_id, reason)
            raise PermissionError(f"Database denied credential fetch: {reason}")

        envelope = result.get("encrypted_credentials")
        if not envelope:
            raise ValueError("Database returned success but omitted encrypted_credentials.")

        tenant_user_id = str(result.get("user_id", "")).strip()
        if not tenant_user_id:
            raise ValueError("Database response omitted mandatory user_id for AAD verification.")

        # Decrypt payload strictly inside worker runtime memory using WorkerKeyRing
        logger.info("Decrypting credential envelope inside worker runtime using WorkerKeyRing...")
        decrypted_secret = self.keyring.decrypt(
            envelope,
            user_id=tenant_user_id,
            purpose=CONTEXT_MAILBOX
        )

        return LeasedCredential(
            mailbox_id=str(result.get("mailbox_id")),
            worker_id=str(result.get("worker_id")),
            user_id=tenant_user_id,
            provider=str(result.get("provider")),
            email_address=str(result.get("email_address")),
            imap_host=str(result.get("imap_host")),
            imap_port=int(result.get("imap_port", 993)),
            use_ssl=bool(result.get("use_ssl", True)),
            auth_mechanism=str(result.get("auth_mechanism", "APP_PASSWORD")),
            credential_version=int(result.get("credential_version", 1)),
            _secret=decrypted_secret,
        )
