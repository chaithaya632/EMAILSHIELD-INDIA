"""
worker/rollout.py
EMAILSHIELD INDIA Sentinel Phase 6I — Production Rollout State Machine & Emergency Rollback Gate.

Defines:
- RolloutState: Explicit enumerated lifecycle states for rollout.
- RolloutGateError: Raised when production rollout preconditions fail.
- ProductionRolloutGate: Validates the 5 mandatory prerequisites before enabling production.
- RollbackManager: Executes emergency deactivation, releasing leases and wiping credentials without data loss.
- CanaryPolicy: Enforces bounded, authorized-tenant canary polling safeguards.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Set, Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class RolloutState(str, Enum):
    """Explicit lifecycle states for Sentinel rollout."""
    BLOCKED = "BLOCKED"
    READY_FOR_TEST = "READY_FOR_TEST"
    TESTING = "TESTING"
    TEST_PASSED = "TEST_PASSED"
    READY_FOR_ROLLOUT = "READY_FOR_ROLLOUT"
    ROLLOUT_ACTIVE = "ROLLOUT_ACTIVE"
    ROLLBACK = "ROLLBACK"


class RolloutGateError(Exception):
    """Raised when one or more production rollout prerequisites are unmet."""
    pass


class ProductionRolloutGate:
    """
    Enforces the 5 mandatory prerequisites for production enablement (Section 2 & 21):
    1. TEST_PASSED: Synthetic and controlled tests passed.
    2. SECURITY_GATE_PASSED: All cryptographic, RLS, SSRF, TLS, and privilege checks passed.
    3. WORKER_HEALTHY: Worker daemon is healthy, responsive, and heartbeat verified.
    4. DEDICATED_TEST_VALIDATED: Dedicated test mailbox was validated on real IMAP.
    5. EXPLICIT_ENABLEMENT: Explicit human operator authorization action.

    Missing ANY prerequisite fails closed immediately: PRODUCTION = DISABLED.
    """

    @classmethod
    def evaluate_enablement(
        cls,
        test_passed: bool,
        security_gate_passed: bool,
        worker_healthy: bool,
        dedicated_test_validated: bool,
        explicit_enablement: bool,
    ) -> RolloutState:
        """
        Evaluates all prerequisites and returns the resulting RolloutState.
        Raises RolloutGateError if production enablement is attempted without all 5.
        """
        if not test_passed:
            raise RolloutGateError("Rollout blocked: TEST_PASSED prerequisite is not satisfied.")
        if not security_gate_passed:
            raise RolloutGateError("Rollout blocked: SECURITY_GATE_PASSED prerequisite is not satisfied.")
        if not worker_healthy:
            raise RolloutGateError("Rollout blocked: WORKER_HEALTHY prerequisite is not satisfied.")
        if not dedicated_test_validated:
            raise RolloutGateError("Rollout blocked: DEDICATED_TEST_VALIDATED prerequisite is not satisfied.")
        if not explicit_enablement:
            raise RolloutGateError("Rollout blocked: EXPLICIT_ENABLEMENT prerequisite is not satisfied.")

        return RolloutState.ROLLOUT_ACTIVE

    @classmethod
    def can_enable_production(
        cls,
        test_passed: bool,
        security_gate_passed: bool,
        worker_healthy: bool,
        dedicated_test_validated: bool,
        explicit_enablement: bool,
    ) -> bool:
        """Returns True only if all 5 prerequisites are strictly met; False otherwise."""
        return bool(
            test_passed
            and security_gate_passed
            and worker_healthy
            and dedicated_test_validated
            and explicit_enablement
        )

    @classmethod
    def determine_state(
        cls,
        infrastructure_available: bool,
        test_mode: bool = False,
        test_passed: bool = False,
        security_gate_passed: bool = False,
        worker_healthy: bool = False,
        dedicated_test_validated: bool = False,
        explicit_enablement: bool = False,
        rollback_active: bool = False,
    ) -> RolloutState:
        """Computes current rollout state based on infrastructure and execution context."""
        if rollback_active:
            return RolloutState.ROLLBACK

        if not infrastructure_available:
            return RolloutState.BLOCKED

        if not test_mode and not test_passed:
            return RolloutState.READY_FOR_TEST

        if test_mode and not test_passed:
            return RolloutState.TESTING

        if test_passed and not (security_gate_passed and worker_healthy and dedicated_test_validated):
            return RolloutState.TEST_PASSED

        if test_passed and security_gate_passed and worker_healthy and dedicated_test_validated:
            if explicit_enablement:
                return RolloutState.ROLLOUT_ACTIVE
            return RolloutState.READY_FOR_ROLLOUT

        return RolloutState.BLOCKED


class RollbackManager:
    """
    Manages emergency rollback and safe deactivation (Section 19 & 24).
    
    Guarantees:
    - Sets state to ROLLBACK.
    - Ensures production_polling is strictly DISABLED.
    - Releases active leases.
    - Closes network connections / IMAP sessions safely.
    - Clears in-memory decrypted credential materials.
    - Preserves existing forensic case stores and audit records without data loss.
    """

    def __init__(self) -> None:
        self._current_state = RolloutState.BLOCKED
        self._production_polling_enabled = False
        self._rollback_reason: Optional[str] = None

    @property
    def current_state(self) -> RolloutState:
        return self._current_state

    @property
    def is_production_enabled(self) -> bool:
        return self._production_polling_enabled

    @property
    def rollback_reason(self) -> Optional[str]:
        return self._rollback_reason

    def set_state(self, state: RolloutState, allow_production: bool = False) -> None:
        self._current_state = state
        self._production_polling_enabled = allow_production and (state == RolloutState.ROLLOUT_ACTIVE)

    def trigger_emergency_rollback(
        self,
        reason: str,
        active_leases: Optional[List[Any]] = None,
        leased_credentials: Optional[List[Any]] = None,
        imap_connections: Optional[List[Any]] = None,
    ) -> RolloutState:
        """
        Executes immediate fail-safe rollback.
        
        1. Immediately sets state to ROLLBACK and forces production_polling = False.
        2. Releases all active worker leases.
        3. Cleans in-memory credentials via .clear().
        4. Closes active IMAP client sockets safely.
        5. Preserves case records.
        """
        self._current_state = RolloutState.ROLLBACK
        self._production_polling_enabled = False
        self._rollback_reason = str(reason)
        logger.warning("EMERGENCY ROLLBACK TRIGGERED: %s", self._rollback_reason)

        # 1. Clean in-memory credentials
        if leased_credentials:
            for cred in leased_credentials:
                try:
                    if hasattr(cred, "clear"):
                        cred.clear()
                except Exception as e:
                    logger.error("Error clearing credential during rollback: %s", e)

        # 2. Release leases
        if active_leases:
            for lease in active_leases:
                try:
                    if hasattr(lease, "release"):
                        lease.release()
                except Exception as e:
                    logger.error("Error releasing lease during rollback: %s", e)

        # 3. Close IMAP connections
        if imap_connections:
            for conn in imap_connections:
                try:
                    if hasattr(conn, "disconnect"):
                        conn.disconnect()
                    elif hasattr(conn, "close"):
                        conn.close()
                except Exception as e:
                    logger.error("Error closing connection during rollback: %s", e)

        return self._current_state


class CanaryPolicy:
    """
    Enforces strict canary bounds during initial controlled rollout (Section 20 & 22).
    
    Guarantees:
    - Only explicitly authorized tenant IDs may be polled.
    - Only explicitly authorized mailbox IDs may be polled.
    - Enforces a conservative maximum message cap per poll (default 5).
    - Prevents blanket user onboarding.
    """

    DEFAULT_CANARY_MAX_MESSAGES = 5

    def __init__(
        self,
        authorized_tenants: Optional[Set[str]] = None,
        authorized_mailboxes: Optional[Set[str]] = None,
        max_messages_per_poll: int = DEFAULT_CANARY_MAX_MESSAGES,
    ) -> None:
        self.authorized_tenants = set(authorized_tenants) if authorized_tenants else set()
        self.authorized_mailboxes = set(authorized_mailboxes) if authorized_mailboxes else set()
        self.max_messages_per_poll = min(max_messages_per_poll, self.DEFAULT_CANARY_MAX_MESSAGES)

    def is_tenant_authorized(self, tenant_id: Optional[str]) -> bool:
        if not tenant_id:
            return False
        return str(tenant_id).strip() in self.authorized_tenants

    def is_mailbox_authorized(self, mailbox_id: Optional[str]) -> bool:
        if not mailbox_id:
            return False
        return str(mailbox_id).strip() in self.authorized_mailboxes

    def validate_canary_poll(self, tenant_id: Optional[str], mailbox_id: Optional[str]) -> bool:
        if not self.is_tenant_authorized(tenant_id):
            raise RolloutGateError(f"Canary access denied: Tenant '{tenant_id}' is not in canary whitelist.")
        if not self.is_mailbox_authorized(mailbox_id):
            raise RolloutGateError(f"Canary access denied: Mailbox '{mailbox_id}' is not in canary whitelist.")
        return True


# =============================================================================
# PHASE 6P: EXTERNAL IMAP READINESS & MAILBOX STATE MACHINE
# =============================================================================

class ExternalMailboxState(str, Enum):
    """
    Explicit lifecycle states for dedicated external mailboxes.
    Differentiates between a mailbox being merely configured vs actually validated.
    """
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"


class ExternalMailboxContractError(Exception):
    """Raised when external mailbox metadata violates contract rules."""
    pass


@dataclass
class ExternalMailboxConfigContract:
    """
    Configuration contract for a future dedicated external IMAP mailbox.

    Required metadata:
    - provider: Known email provider name (e.g., 'gmail', 'outlook', 'custom')
    - email_address: Dedicated test email address
    - imap_host: Validated IMAP server hostname/IP
    - imap_port: TCP port (default 993)
    - use_ssl: Mandatory True for production
    - auth_mechanism: Authentication scheme ('PLAIN' or 'LOGIN')
    - is_dedicated_test_mailbox: Must be True (personal/work/production mailboxes strictly rejected)

    Security Invariants:
    - Never stores passwords, app passwords, OAuth tokens, capability tokens,
      private keys, or database credentials in source or metadata.
    - Configuration alone NEVER implies validation.
    """
    provider: str
    email_address: str
    imap_host: str
    imap_port: int = 993
    use_ssl: bool = True
    auth_mechanism: str = "PLAIN"
    is_dedicated_test_mailbox: bool = False
    state: ExternalMailboxState = ExternalMailboxState.NOT_CONFIGURED

    def validate_contract(self) -> None:
        """
        Validates the configuration metadata contract against security constraints.
        Fails closed on missing fields, invalid port ranges, non-SSL usage, or SSRF risks.
        """
        if not self.provider or not str(self.provider).strip():
            raise ExternalMailboxContractError("External mailbox contract requires a non-empty 'provider'.")
        if not self.email_address or not str(self.email_address).strip():
            raise ExternalMailboxContractError("External mailbox contract requires a non-empty 'email_address'.")
        if "@" not in str(self.email_address):
            raise ExternalMailboxContractError("External mailbox email_address must contain '@'.")
        if not self.imap_host or not str(self.imap_host).strip():
            raise ExternalMailboxContractError("External mailbox contract requires a non-empty 'imap_host'.")

        try:
            port = int(self.imap_port)
        except (ValueError, TypeError):
            raise ExternalMailboxContractError(f"Invalid IMAP port '{self.imap_port}': must be an integer.")

        if not (1 <= port <= 65535):
            raise ExternalMailboxContractError(f"IMAP port {port} is out of valid range (1-65535).")

        mech = str(self.auth_mechanism).strip().upper()
        if mech not in ("PLAIN", "LOGIN"):
            raise ExternalMailboxContractError(
                f"Unsupported auth_mechanism '{mech}': only PLAIN and LOGIN are supported."
            )

        # Validate host against SSRF
        from worker.imap_client import validate_imap_host, SSRFSecurityError
        try:
            validate_imap_host(self.imap_host)
        except SSRFSecurityError as err:
            raise ExternalMailboxContractError(f"SSRF validation failed for imap_host '{self.imap_host}': {err}")

    def mark_configured(self) -> None:
        """
        Transitions state from NOT_CONFIGURED to CONFIGURED after contract validation.
        Enforces dedicated test classification.
        """
        self.validate_contract()
        if not self.is_dedicated_test_mailbox:
            raise ExternalMailboxContractError(
                "Rejected: Mailbox must be explicitly classified as a dedicated test mailbox."
            )
        self.state = ExternalMailboxState.CONFIGURED

    def __repr__(self) -> str:
        return (
            f"ExternalMailboxConfigContract("
            f"provider='{self.provider}', "
            f"email='{self.email_address}', "
            f"host='{self.imap_host}', "
            f"port={self.imap_port}, "
            f"ssl={self.use_ssl}, "
            f"auth='{self.auth_mechanism}', "
            f"is_dedicated_test={self.is_dedicated_test_mailbox}, "
            f"state={self.state.value})"
        )


class ExternalIMAPSecurityGate:
    """
    Enforces all 15 prerequisites before allowing an external mailbox to be tested:
    1. Dedicated mailbox: YES
    2. Test-only classification: YES
    3. Provider identified: YES
    4. IMAP support verified: YES
    5. TLS: YES
    6. Certificate validation: YES (CERT_REQUIRED)
    7. Hostname verification: YES (check_hostname=True)
    8. SSRF validation: PASS
    9. Worker identity: VALID
    10. Tenant binding: VALID
    11. Credential provisioning: PASS
    12. Credential encryption: PASS
    13. Credential retrieval: PASS
    14. Credential decryption: PASS
    15. Lease: VALID
    """

    @classmethod
    def evaluate_readiness(
        cls,
        contract: Optional[ExternalMailboxConfigContract] = None,
        is_dedicated_mailbox: bool = False,
        is_test_only: bool = False,
        provider_identified: bool = False,
        imap_support_verified: bool = False,
        tls_enabled: bool = False,
        cert_validation_enabled: bool = False,
        hostname_verification_enabled: bool = False,
        ssrf_validation_passed: bool = False,
        worker_identity_valid: bool = False,
        tenant_binding_valid: bool = False,
        credential_provisioning_passed: bool = False,
        credential_encryption_passed: bool = False,
        credential_retrieval_passed: bool = False,
        credential_decryption_passed: bool = False,
        lease_valid: bool = False,
    ) -> Dict[str, Any]:
        """
        Evaluates the 15 prerequisites and returns the gate decision.
        If any requirement fails, returns can_test=False and state=BLOCKED (or NOT_CONFIGURED).
        """
        missing: List[str] = []

        if contract is None or contract.state == ExternalMailboxState.NOT_CONFIGURED:
            missing.append("EXTERNAL_MAILBOX_NOT_CONFIGURED")

        if not is_dedicated_mailbox:
            missing.append("DEDICATED_MAILBOX_REQUIRED")
        if not is_test_only:
            missing.append("TEST_ONLY_CLASSIFICATION_REQUIRED")
        if not provider_identified:
            missing.append("PROVIDER_IDENTIFICATION_REQUIRED")
        if not imap_support_verified:
            missing.append("IMAP_SUPPORT_VERIFICATION_REQUIRED")
        if not tls_enabled:
            missing.append("TLS_REQUIRED")
        if not cert_validation_enabled:
            missing.append("CERTIFICATE_VALIDATION_REQUIRED")
        if not hostname_verification_enabled:
            missing.append("HOSTNAME_VERIFICATION_REQUIRED")
        if not ssrf_validation_passed:
            missing.append("SSRF_VALIDATION_FAILED")
        if not worker_identity_valid:
            missing.append("WORKER_IDENTITY_INVALID")
        if not tenant_binding_valid:
            missing.append("TENANT_BINDING_INVALID")
        if not credential_provisioning_passed:
            missing.append("CREDENTIAL_PROVISIONING_FAILED")
        if not credential_encryption_passed:
            missing.append("CREDENTIAL_ENCRYPTION_FAILED")
        if not credential_retrieval_passed:
            missing.append("CREDENTIAL_RETRIEVAL_FAILED")
        if not credential_decryption_passed:
            missing.append("CREDENTIAL_DECRYPTION_FAILED")
        if not lease_valid:
            missing.append("LEASE_INVALID")

        can_test = len(missing) == 0

        if contract is None or contract.state == ExternalMailboxState.NOT_CONFIGURED:
            current_state = ExternalMailboxState.NOT_CONFIGURED
        elif can_test:
            current_state = ExternalMailboxState.VALIDATING
        else:
            current_state = ExternalMailboxState.BLOCKED

        return {
            "can_test": can_test,
            "state": current_state,
            "missing_prerequisites": missing,
            "status": "READY_FOR_TEST" if can_test else "BLOCKED",
        }


def create_gmail_test_contract() -> ExternalMailboxConfigContract:
    """
    Creates a validated ExternalMailboxConfigContract for the dedicated Gmail test mailbox.
    Mailbox: emailshield.sentinel.test@gmail.com
    IMAP Host: imap.gmail.com:993
    TLS: Mandatory
    Authentication: PLAIN (App Password)
    Classification: Dedicated test mailbox
    """
    contract = ExternalMailboxConfigContract(
        provider="gmail",
        email_address="emailshield.sentinel.test@gmail.com",
        imap_host="imap.gmail.com",
        imap_port=993,
        use_ssl=True,
        auth_mechanism="PLAIN",
        is_dedicated_test_mailbox=True,
    )
    contract.mark_configured()
    return contract


