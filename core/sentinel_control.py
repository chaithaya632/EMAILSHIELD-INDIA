"""
core/sentinel_control.py
Control-Plane Logic & Data Management for EMAILSHIELD INDIA Sentinel.
Handles user-facing worker, mailbox, alert, and checkpoint state transitions
under strict Row-Level Security (RLS) tenant isolation.

CRITICAL INVARIANT:
This module manages control-plane state only.
It does NOT execute workers, poll IMAP, spawn threads, or dispatch alerts.
"""

import re
import uuid
from typing import Optional, Dict, Any, List, Tuple

# =====================================================================
# Constants & Defaults
# =====================================================================
MIN_POLL_INTERVAL_SECONDS = 30
MAX_POLL_INTERVAL_SECONDS = 3600
DEFAULT_POLL_INTERVAL_SECONDS = 60

ALLOWED_DESIRED_STATES = ("RUNNING", "STOPPED")
ALLOWED_PROVIDERS = ("gmail", "outlook", "yahoo", "zoho", "custom")
ALLOWED_AUTH_MECHANISMS = ("APP_PASSWORD", "XOAUTH2")
ALLOWED_ALERT_CHANNELS = ("telegram", "whatsapp")

PROVIDER_IMAP_DEFAULTS = {
    "gmail": {"host": "imap.gmail.com", "port": 993, "use_ssl": True},
    "outlook": {"host": "outlook.office365.com", "port": 993, "use_ssl": True},
    "yahoo": {"host": "imap.mail.yahoo.com", "port": 993, "use_ssl": True},
    "zoho": {"host": "imappro.zoho.in", "port": 993, "use_ssl": True},
    "custom": {"host": "", "port": 993, "use_ssl": True},
}


# =====================================================================
# Input Validation (Fail-Closed)
# =====================================================================
def validate_poll_interval(seconds: int) -> None:
    """Validates that poll_interval_seconds falls within bounded limits."""
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        raise ValueError("Poll interval must be an integer.")
    if not (MIN_POLL_INTERVAL_SECONDS <= seconds <= MAX_POLL_INTERVAL_SECONDS):
        raise ValueError(
            f"Poll interval must be between {MIN_POLL_INTERVAL_SECONDS} and "
            f"{MAX_POLL_INTERVAL_SECONDS} seconds (got {seconds})."
        )


def validate_desired_state(state: str) -> None:
    """Validates that desired_state is either 'RUNNING' or 'STOPPED'."""
    if not isinstance(state, str) or state.strip() not in ALLOWED_DESIRED_STATES:
        raise ValueError(f"Desired state must be one of {ALLOWED_DESIRED_STATES} (got '{state}').")


def validate_provider(provider: str) -> None:
    """Validates that the mailbox provider is supported."""
    if not isinstance(provider, str) or provider.strip().lower() not in ALLOWED_PROVIDERS:
        raise ValueError(f"Unsupported provider '{provider}'. Must be one of {ALLOWED_PROVIDERS}.")


def validate_email_syntax(email: str) -> None:
    """Validates that email string has valid general syntax."""
    if not isinstance(email, str) or not email.strip():
        raise ValueError("Email address cannot be empty.")
    # Safe general RFC-5322 regex
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.strip()):
        raise ValueError(f"Invalid email address syntax: '{email}'.")


def validate_imap_port(port: int) -> None:
    """Validates that IMAP port is a valid TCP port number."""
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("IMAP port must be an integer.")
    if not (1 <= port <= 65535):
        raise ValueError(f"IMAP port must be between 1 and 65535 (got {port}).")


def validate_alert_channel(channel: str) -> None:
    """Validates that alert channel is either 'telegram' or 'whatsapp'."""
    if not isinstance(channel, str) or channel.strip().lower() not in ALLOWED_ALERT_CHANNELS:
        raise ValueError(f"Unsupported alert channel '{channel}'. Must be one of {ALLOWED_ALERT_CHANNELS}.")


# =====================================================================
# Worker Control-Plane Operations
# =====================================================================
def get_user_worker(user_id: str, client: Any) -> Optional[Dict[str, Any]]:
    """
    Retrieves the active Sentinel worker record for the authenticated user.
    Uses the authenticated Supabase client where RLS enforces auth.uid() == user_id.
    """
    if not client or not user_id:
        return None
    try:
        res = client.table("sentinel_workers").select("*").eq("user_id", user_id).execute()
        if res and res.data:
            return res.data[0]
        return None
    except Exception:
        return None


def upsert_user_worker(
    user_id: str,
    poll_interval_seconds: int,
    desired_state: str,
    client: Any
) -> Tuple[bool, Any]:
    """
    Creates or updates the user's worker record with validated control-plane parameters.
    CRITICAL: Does NOT permit setting actual_state, lease_owner, or lease_expires_at.
    """
    if not client or not user_id:
        return False, "Authenticated client and user_id are required."

    try:
        validate_poll_interval(poll_interval_seconds)
        validate_desired_state(desired_state)
    except ValueError as ve:
        return False, str(ve)

    payload = {
        "user_id": user_id,
        "poll_interval_seconds": poll_interval_seconds,
        "desired_state": desired_state.strip()
    }

    try:
        res = client.table("sentinel_workers").upsert(
            payload,
            on_conflict="user_id"
        ).execute()
        if res and res.data:
            return True, res.data[0]
        return False, "Failed to upsert worker record."
    except Exception as e:
        return False, f"Worker upsert error: {str(e)}"


def set_worker_desired_state(user_id: str, desired_state: str, client: Any) -> Tuple[bool, str]:
    """
    Updates the desired_state ('RUNNING' | 'STOPPED') for the user's worker.
    Does NOT start or stop any process; sets the intent signal for Phase 4 workers.
    """
    if not client or not user_id:
        return False, "Authenticated client and user_id are required."

    try:
        validate_desired_state(desired_state)
    except ValueError as ve:
        return False, str(ve)

    try:
        res = client.table("sentinel_workers").update({
            "desired_state": desired_state.strip()
        }).eq("user_id", user_id).execute()

        if res and res.data:
            return True, f"Sentinel desired state updated to '{desired_state}'."
        return False, "Worker record not found or update denied."
    except Exception as e:
        return False, f"Failed to update desired state: {str(e)}"


# =====================================================================
# Mailbox Metadata Operations (Blind Storage Protected)
# =====================================================================
def get_user_mailbox(user_id: str, client: Any) -> Optional[Dict[str, Any]]:
    """
    Retrieves safe mailbox metadata for the user via public.sentinel_mailboxes_safe.
    Never requests or returns encrypted_credentials.
    """
    if not client or not user_id:
        return None
    try:
        # Prefer the safe view that explicitly omits encrypted_credentials
        res = client.table("sentinel_mailboxes_safe").select("*").eq("user_id", user_id).execute()
        if res and res.data:
            return res.data[0]
        return None
    except Exception:
        # Fallback query specifying safe columns only
        try:
            safe_cols = "id,user_id,worker_id,created_at,updated_at,provider,email_address,imap_host,imap_port,use_ssl,auth_mechanism,is_active"
            res = client.table("sentinel_mailboxes").select(safe_cols).eq("user_id", user_id).execute()
            if res and res.data:
                return res.data[0]
        except Exception:
            pass
        return None


def save_user_mailbox_metadata(
    user_id: str,
    worker_id: str,
    provider: str,
    email_address: str,
    imap_host: str,
    imap_port: int,
    use_ssl: bool,
    auth_mechanism: str,
    is_active: bool,
    client: Any
) -> Tuple[bool, str]:
    """
    Validates and updates non-sensitive mailbox configuration parameters.
    NOTE ON CREDENTIALS: In Phase 3, encrypted_credentials column-level UPDATE is revoked.
    Credential provisioning will be performed in Phase 4 via the worker provisioning pipeline.
    """
    if not client or not user_id or not worker_id:
        return False, "Authenticated client, user_id, and worker_id are required."

    try:
        validate_provider(provider)
        validate_email_syntax(email_address)
        validate_imap_port(imap_port)
    except ValueError as ve:
        return False, str(ve)

    if not imap_host or not imap_host.strip():
        return False, "IMAP host is required."

    clean_provider = provider.strip().lower()
    clean_auth = auth_mechanism.strip().upper() if auth_mechanism else "APP_PASSWORD"
    if clean_auth not in ALLOWED_AUTH_MECHANISMS:
        clean_auth = "APP_PASSWORD"

    payload = {
        "user_id": user_id,
        "worker_id": worker_id,
        "provider": clean_provider,
        "email_address": email_address.strip(),
        "imap_host": imap_host.strip(),
        "imap_port": imap_port,
        "use_ssl": bool(use_ssl),
        "auth_mechanism": clean_auth,
        "is_active": bool(is_active)
    }

    try:
        # Check if mailbox already exists for update vs insert
        existing = get_user_mailbox(user_id, client)
        if existing:
            # Update safe metadata
            res = client.table("sentinel_mailboxes").update({
                "provider": clean_provider,
                "email_address": email_address.strip(),
                "imap_host": imap_host.strip(),
                "imap_port": imap_port,
                "use_ssl": bool(use_ssl),
                "auth_mechanism": clean_auth,
                "is_active": bool(is_active)
            }).eq("user_id", user_id).execute()
            if res and res.data:
                return True, "Mailbox configuration metadata updated successfully."
            return False, "Failed to update mailbox metadata."
        else:
            # NOTE: New mailbox insertion without credentials is an intentional Phase 3 boundary.
            # Real encrypted credentials will be provisioned in Phase 4.
            return True, "Mailbox configuration validated. Credential provisioning will complete in Phase 4."
    except Exception as e:
        return False, f"Mailbox metadata save error: {str(e)}"


# =====================================================================
# Checkpoint Inspection (Read-Only)
# =====================================================================
def get_user_checkpoint(user_id: str, client: Any) -> Optional[Dict[str, Any]]:
    """
    Retrieves the tenant's active checkpoint record for observation.
    Checkpoints are strictly read-only from the user presentation plane.
    """
    if not client or not user_id:
        return None
    try:
        res = client.table("sentinel_checkpoints").select("*").eq("user_id", user_id).execute()
        if res and res.data:
            return res.data[0]
        return None
    except Exception:
        return None


# =====================================================================
# Alert Configuration Operations
# =====================================================================
def get_user_alerts(user_id: str, client: Any) -> List[Dict[str, Any]]:
    """
    Retrieves the user's configured notification channels.
    Omits encrypted_dispatch_config.
    """
    if not client or not user_id:
        return []
    try:
        safe_cols = "id,user_id,worker_id,created_at,channel,destination_target,is_enabled,high_risk_only,last_dispatch_at,dispatch_count"
        res = client.table("sentinel_alerts").select(safe_cols).eq("user_id", user_id).execute()
        if res and res.data:
            return res.data
        return []
    except Exception:
        return []


def save_user_alert_metadata(
    user_id: str,
    worker_id: str,
    channel: str,
    destination_target: str,
    is_enabled: bool,
    high_risk_only: bool,
    client: Any
) -> Tuple[bool, str]:
    """Validates and updates alert channel metadata."""
    if not client or not user_id or not worker_id:
        return False, "Authenticated client, user_id, and worker_id are required."

    try:
        validate_alert_channel(channel)
    except ValueError as ve:
        return False, str(ve)

    if not destination_target or not destination_target.strip():
        return False, "Destination target (Phone number or Chat ID) is required."

    clean_channel = channel.strip().lower()
    clean_dest = destination_target.strip()

    try:
        existing_alerts = get_user_alerts(user_id, client)
        matched = [a for a in existing_alerts if a.get("channel") == clean_channel]
        if matched:
            alert_id = matched[0]["id"]
            res = client.table("sentinel_alerts").update({
                "destination_target": clean_dest,
                "is_enabled": bool(is_enabled),
                "high_risk_only": bool(high_risk_only)
            }).eq("id", alert_id).eq("user_id", user_id).execute()
            if res and res.data:
                return True, f"{clean_channel.capitalize()} alert configuration updated."
            return False, "Failed to update alert configuration."
        else:
            return True, f"{clean_channel.capitalize()} configuration validated. Credential provisioning will complete in Phase 4."
    except Exception as e:
        return False, f"Alert configuration save error: {str(e)}"


# =====================================================================
# Deactivation & Deletion
# =====================================================================
def deactivate_user_sentinel(user_id: str, client: Any) -> Tuple[bool, str]:
    """
    Deactivates Sentinel by stopping desired worker state, marking mailbox inactive,
    and disabling alerts without deleting historical audit telemetry.
    """
    if not client or not user_id:
        return False, "Authenticated client and user_id are required."

    try:
        client.table("sentinel_workers").update({"desired_state": "STOPPED"}).eq("user_id", user_id).execute()
        client.table("sentinel_mailboxes").update({"is_active": False}).eq("user_id", user_id).execute()
        client.table("sentinel_alerts").update({"is_enabled": False}).eq("user_id", user_id).execute()
        return True, "Sentinel has been deactivated."
    except Exception as e:
        return False, f"Deactivation error: {str(e)}"


def delete_user_sentinel_config(user_id: str, client: Any) -> Tuple[bool, str]:
    """
    Permanently deletes the user's Sentinel configuration.
    Cascading foreign keys in sentinel_schema.sql automatically delete
    the associated mailbox, checkpoint, and alert records.
    """
    if not client or not user_id:
        return False, "Authenticated client and user_id are required."

    try:
        res = client.table("sentinel_workers").delete().eq("user_id", user_id).execute()
        if res and res.data:
            return True, "Sentinel configuration permanently deleted."
        return False, "No Sentinel configuration found to delete."
    except Exception as e:
        return False, f"Deletion error: {str(e)}"
