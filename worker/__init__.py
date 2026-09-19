"""
worker/
EMAILSHIELD INDIA Sentinel External Worker Runtime Package.
Phase 6A: External Worker Runtime Foundation & Lease Verification.

Components:
- config: Environment configuration and secret parsing
- identity: Worker identity binding and in-memory capability token management
- logging: Redacted safe logging filter
- db: PostgreSQL client and mock database client for testing
- lease: Lease acquisition, renewal, and release lifecycle
- runtime: Daemon process with signal handling and bounded execution
"""

from worker.config import (
    WorkerConfig,
    mask_db_url,
    ProductionMailboxGateError,
    ProductionReadinessGate,
)
from worker.rollout import (
    RolloutState,
    RolloutGateError,
    ProductionRolloutGate,
    RollbackManager,
    CanaryPolicy,
    ExternalMailboxState,
    ExternalMailboxContractError,
    ExternalMailboxConfigContract,
    ExternalIMAPSecurityGate,
    create_gmail_test_contract,
)
from worker.identity import WorkerIdentity, CapabilityToken
from worker.logging import SafeLoggingFilter, get_worker_logger
from worker.db import (
    WorkerDBClient,
    MockWorkerDBClient,
    WorkerDBError,
    RoleVerificationError,
    TableAccessViolationError,
)
from worker.lease import WorkerLeaseManager
from worker.runtime import SentinelWorkerDaemon, DaemonState
from worker.credentials import LeasedCredential, WorkerCredentialService
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticEmailMessage,
    SyntheticIMAPError,
    SyntheticAuthError,
    SyntheticConnectionError,
)
from worker.events import SafeEmailEvent
from worker.checkpoint import CheckpointStore, MailboxCheckpoint
from worker.poller import MailboxPoller
from worker.service import WorkerService
from worker.health import WorkerHealthMonitor, WorkerHealthStatus

from worker.imap_client import (
    RealIMAPConnection,
    IMAPConnectionProtocol,
    IMAPClientError,
    RealNetworkDeniedError,
    SSRFSecurityError,
    TLSVerificationError,
    UnsupportedAuthMechanismError,
    IMAPAuthenticationError,
    IMAPConnectionTimeoutError,
    validate_imap_host,
    validate_imap_port,
    validate_auth_mechanism,
    is_real_imap_test_enabled,
    check_real_imap_guard,
    GMAIL_TEST_EMAIL,
    GMAIL_IMAP_HOST,
    GMAIL_IMAP_PORT,
    GMAIL_APP_PASSWORD_ENV_VAR,
    get_gmail_app_password,
    is_gmail_app_password_available,
)

__all__ = [
    "WorkerConfig",
    "mask_db_url",
    "ProductionMailboxGateError",
    "ProductionReadinessGate",
    "RolloutState",
    "RolloutGateError",
    "ProductionRolloutGate",
    "RollbackManager",
    "CanaryPolicy",
    "ExternalMailboxState",
    "ExternalMailboxContractError",
    "ExternalMailboxConfigContract",
    "ExternalIMAPSecurityGate",
    "WorkerIdentity",
    "CapabilityToken",
    "SafeLoggingFilter",
    "get_worker_logger",
    "WorkerDBClient",
    "MockWorkerDBClient",
    "WorkerDBError",
    "RoleVerificationError",
    "TableAccessViolationError",
    "WorkerLeaseManager",
    "SentinelWorkerDaemon",
    "DaemonState",
    "LeasedCredential",
    "WorkerCredentialService",
    "SyntheticIMAPServer",
    "SyntheticIMAPConnection",
    "SyntheticEmailMessage",
    "SyntheticIMAPError",
    "SyntheticAuthError",
    "SyntheticConnectionError",
    "SafeEmailEvent",
    "CheckpointStore",
    "MailboxCheckpoint",
    "MailboxPoller",
    "RealIMAPConnection",
    "IMAPConnectionProtocol",
    "IMAPClientError",
    "RealNetworkDeniedError",
    "SSRFSecurityError",
    "TLSVerificationError",
    "UnsupportedAuthMechanismError",
    "IMAPAuthenticationError",
    "IMAPConnectionTimeoutError",
    "validate_imap_host",
    "validate_imap_port",
    "validate_auth_mechanism",
    "is_real_imap_test_enabled",
    "check_real_imap_guard",
    "WorkerService",
    "WorkerHealthMonitor",
    "WorkerHealthStatus",
    "create_gmail_test_contract",
    "GMAIL_TEST_EMAIL",
    "GMAIL_IMAP_HOST",
    "GMAIL_IMAP_PORT",
    "GMAIL_APP_PASSWORD_ENV_VAR",
    "get_gmail_app_password",
    "is_gmail_app_password_available",
]
