"""
core/sentinel_control.py
Control-Plane Logic & Data Management for EMAILSHIELD INDIA Sentinel.
Handles user-facing worker, mailbox, alert, and checkpoint state transitions
under strict Row-Level Security (RLS) tenant isolation.

CRITICAL INVARIANT:
This module manages control-plane state only.
It does NOT execute workers, poll IMAP, spawn threads, or dispatch alerts.
"""

import os
import re
import uuid
from typing import Optional, Dict, Any, List, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa

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
    except Exception as e:
        err_msg = str(e)
        if "PGRST303" in err_msg or "JWT expired" in err_msg:
            return False, "Authentication session expired (JWT expired). Please sign in again via the sidebar."
        return False, f"Worker upsert error: {err_msg}"


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
            try:
                from worker.db import LocalWorkerDBClient
                LocalWorkerDBClient.set_desired_state(user_id, desired_state.strip())
            except Exception:
                pass
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
    if not user_id:
        return None
    if client:
        try:
            # Prefer the safe view that explicitly omits encrypted_credentials
            res = client.table("sentinel_mailboxes_safe").select("*").eq("user_id", user_id).execute()
            if res and res.data:
                return res.data[0]
        except Exception:
            # Fallback query specifying safe columns only
            try:
                safe_cols = "id,user_id,worker_id,created_at,updated_at,provider,email_address,imap_host,imap_port,use_ssl,auth_mechanism,is_active"
                res = client.table("sentinel_mailboxes").select(safe_cols).eq("user_id", user_id).execute()
                if res and res.data:
                    return res.data[0]
            except Exception:
                pass

    # Fail closed when Supabase is active and no client is provided
    try:
        from core.supabase_client import is_supabase_configured
        from core.case_store import is_public_multiuser_mode
        if is_public_multiuser_mode() or (is_supabase_configured() and client is None):
            return None
    except Exception:
        pass

    # Fallback to local DB client only when no Supabase client is available
    if not client:
        try:
            from worker.db import LocalWorkerDBClient
            loc = LocalWorkerDBClient()
            loc._load_from_disk()
            for m_id, m in loc.mailboxes.items():
                if m.get("user_id") == str(user_id) and m.get("is_active"):
                    safe_m = dict(m)
                    safe_m.pop("encrypted_credentials", None)
                    safe_m["id"] = m_id
                    return safe_m
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


def mask_email_address(email_addr: Optional[str]) -> str:
    """
    Masks an email address for safe public presentation (e.g. em***st@gmail.com).
    Never exposes full username in plain text while allowing the user to recognize their mailbox.
    """
    if not email_addr or "@" not in email_addr:
        return "Not Configured"
    try:
        local, domain = email_addr.strip().split("@", 1)
        if len(local) <= 2:
            masked_local = local[0] + "***"
        elif len(local) <= 4:
            masked_local = local[0] + "***" + local[-1]
        else:
            masked_local = local[:2] + "***" + local[-2:]
        return f"{masked_local}@{domain}"
    except Exception:
        return "••••••@••••"


def connect_user_sentinel_mailbox(
    user_id: str,
    worker_id: str,
    provider: str,
    email_address: str,
    imap_host: str,
    imap_port: int,
    use_ssl: bool,
    app_password: str,
    client: Any,
    public_key: Optional[rsa.RSAPublicKey] = None,
) -> Tuple[bool, str]:
    """
    Securely provisions an authorized user mailbox with client-side asymmetric encryption.
    
    Guarantees:
    1. Server-side validation of provider, email syntax, and IMAP port.
    2. Zero plaintext password storage: app_password is encrypted using the Worker's
       RSA Public Key (RSA-OAEP + AES-256-GCM) with tenant-bound AAD.
    3. The encryptor possesses ONLY the Public Key and CANNOT decrypt the password.
    4. Upserts sentinel_mailboxes with is_active=True and sets worker desired_state='RUNNING'.
    """
    from core.sentinel_crypto import (
        encrypt_credential_asymmetric,
        load_public_key_from_pem,
        CONTEXT_MAILBOX,
    )

    if not client or not user_id or not worker_id:
        return False, "Authenticated client, user_id, and worker_id are required."

    if not app_password or not app_password.strip():
        return False, "Mailbox App Password is required."

    try:
        validate_provider(provider)
        validate_email_syntax(email_address)
        validate_imap_port(imap_port)
    except ValueError as ve:
        return False, str(ve)

    if not imap_host or not imap_host.strip():
        return False, "IMAP host is required."

    clean_provider = provider.strip().lower()
    clean_email = email_address.strip()
    clean_host = imap_host.strip()

    # 1. Resolve Worker Public Key for Asymmetric Hybrid Envelope Encryption
    pk = public_key
    last_err = ""
    if pk is None:
        try:
            from core.sentinel_crypto import load_public_key_from_env
            pk = load_public_key_from_env("SENTINEL_WORKER_PUBLIC_KEY")
        except Exception as e:
            last_err = f" ({str(e)})"

    if pk is None:
        return False, f"Cannot encrypt credential: Worker Public Key is unavailable{last_err}."

    # 2. Encrypt Credential Asymmetrically
    try:
        encrypted_envelope = encrypt_credential_asymmetric(
            plaintext=app_password.strip(),
            public_key=pk,
            user_id=user_id,
            purpose=CONTEXT_MAILBOX
        )
    except Exception as enc_err:
        return False, f"Credential encryption failed: {str(enc_err)}"

    # 3. Upsert Mailbox Record
    mailbox_payload = {
        "user_id": user_id,
        "worker_id": worker_id,
        "provider": clean_provider,
        "email_address": clean_email,
        "imap_host": clean_host,
        "imap_port": imap_port,
        "use_ssl": bool(use_ssl),
        "encrypted_credentials": encrypted_envelope,
        "auth_mechanism": "APP_PASSWORD",
        "is_active": True,
    }

    try:
        existing = get_user_mailbox(user_id, client)
        if existing:
            try:
                res = client.table("sentinel_mailboxes").update(mailbox_payload, returning="minimal").eq("user_id", user_id).execute()
            except TypeError:
                res = client.table("sentinel_mailboxes").update(mailbox_payload).eq("user_id", user_id).execute()
            
            # Use provisioning RPC for credential rotation under SECURITY DEFINER
            try:
                curr_ver = existing.get("credential_version", 1) or 1
                client.rpc("rpc_set_encrypted_mailbox_credential", {
                    "p_worker_id": worker_id,
                    "p_ciphertext": encrypted_envelope,
                    "p_credential_version": curr_ver + 1
                }).execute()
            except Exception:
                pass
        else:
            try:
                res = client.table("sentinel_mailboxes").insert(mailbox_payload, returning="minimal").execute()
            except TypeError:
                res = client.table("sentinel_mailboxes").insert(mailbox_payload).execute()

        # 4. Activate Worker State to RUNNING with 60s DB baseline interval
        upsert_user_worker(user_id, poll_interval_seconds=60, desired_state="RUNNING", client=client)

        authoritative_mailbox_id = None
        if existing and existing.get("id"):
            authoritative_mailbox_id = str(existing.get("id"))
        else:
            try:
                after_ins = get_user_mailbox(user_id, client)
                if after_ins and after_ins.get("id"):
                    authoritative_mailbox_id = str(after_ins.get("id"))
            except Exception:
                pass

        try:
            from worker.db import LocalWorkerDBClient
            LocalWorkerDBClient.sync_mailbox_and_worker(
                worker_id=worker_id,
                user_id=user_id,
                email_address=clean_email,
                encrypted_credentials=encrypted_envelope,
                imap_host=clean_host,
                imap_port=imap_port,
                use_ssl=bool(use_ssl),
                provider=clean_provider,
                desired_state="RUNNING",
                mailbox_id=authoritative_mailbox_id,
            )
            local_wid_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local", "sentinel_worker_id.txt")
            os.makedirs(os.path.dirname(local_wid_path), exist_ok=True)
            with open(local_wid_path, "w", encoding="utf-8") as f:
                f.write(str(worker_id).strip())

            poll_flag_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local", "sentinel_production_polling.txt")
            with open(poll_flag_path, "w", encoding="utf-8") as f:
                f.write("1")
        except Exception:
            pass

        return True, f"Mailbox {mask_email_address(clean_email)} successfully connected. Live Mail Analysis is ACTIVE."
    except Exception as db_err:
        err_msg = str(db_err)
        if "PGRST303" in err_msg or "JWT expired" in err_msg:
            return False, "Authentication session expired (JWT expired). Please sign in again via the sidebar."
        return False, f"Failed to store mailbox configuration: {err_msg}"


def disconnect_user_sentinel_mailbox(user_id: str, client: Any) -> Tuple[bool, str]:
    """
    Disconnects the user's Sentinel mailbox:
    1. Sets worker desired_state to 'STOPPED'.
    2. Marks mailbox is_active = False and revokes encrypted credentials.
    3. Halts any active worker polling immediately.
    """
    if not client or not user_id:
        return False, "Authenticated client and user_id are required."

    try:
        # Stop worker
        client.table("sentinel_workers").update({
            "desired_state": "STOPPED"
        }).eq("user_id", user_id).execute()

        # Deactivate mailbox and scrub credentials to REVOKED
        try:
            res_m = client.table("sentinel_mailboxes").update({
                "is_active": False,
                "encrypted_credentials": "REVOKED"
            }, returning="minimal").eq("user_id", user_id).execute()
        except TypeError:
            res_m = client.table("sentinel_mailboxes").update({
                "is_active": False,
                "encrypted_credentials": "REVOKED"
            }).eq("user_id", user_id).execute()

        # Check if mailbox is still active in safe view (e.g. on real PostgreSQL with blind RLS)
        mb = get_user_mailbox(user_id, client)
        if mb and mb.get("is_active"):
            # Cascade delete clears the worker and associated mailbox row completely
            delete_user_sentinel_config(user_id, client)

        try:
            from core.sentinel_stats import reset_user_sentinel_stats
            reset_user_sentinel_stats(user_id)
        except Exception:
            pass

        try:
            from worker.db import LocalWorkerDBClient
            LocalWorkerDBClient.deactivate_mailbox(user_id)
        except Exception:
            pass

        try:
            from worker.db import LocalWorkerDBClient
            if not LocalWorkerDBClient.has_other_active_mailboxes(exclude_user_id=user_id):
                poll_flag_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local", "sentinel_production_polling.txt")
                if os.path.exists(poll_flag_path):
                    os.remove(poll_flag_path)
        except Exception:
            pass

        return True, "Mailbox disconnected and Sentinel monitoring stopped."
    except Exception as e:
        return False, f"Disconnection error: {str(e)}"


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

    if not is_enabled and not (destination_target or "").strip():
        # Disconnection flow: disable existing channel record if present
        clean_channel = channel.strip().lower()
        try:
            existing_alerts = get_user_alerts(user_id, client)
            matched = [a for a in existing_alerts if a.get("channel") == clean_channel]
            if matched:
                alert_id = matched[0]["id"]
                client.table("sentinel_alerts").update({
                    "is_enabled": False,
                    "destination_target": ""
                }).eq("id", alert_id).eq("user_id", user_id).execute()
            return True, f"{clean_channel.capitalize()} alerts disconnected."
        except Exception as disc_err:
            return False, f"Disconnection error: {str(disc_err)}"

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
            if res and getattr(res, "data", None):
                return True, f"{clean_channel.capitalize()} alert configuration updated."
            return True, f"{clean_channel.capitalize()} alert configuration updated."
        else:
            res = client.table("sentinel_alerts").insert({
                "user_id": user_id,
                "worker_id": worker_id,
                "channel": clean_channel,
                "destination_target": clean_dest,
                "encrypted_dispatch_config": "CONFIGURED",
                "is_enabled": bool(is_enabled),
                "high_risk_only": bool(high_risk_only)
            }).execute()
            return True, f"{clean_channel.capitalize()} alert configuration saved."
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
        try:
            from worker.db import LocalWorkerDBClient
            if not LocalWorkerDBClient.has_other_active_mailboxes(exclude_user_id=user_id):
                poll_flag_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local", "sentinel_production_polling.txt")
                if os.path.exists(poll_flag_path):
                    os.remove(poll_flag_path)
        except Exception:
            pass
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
        try:
            from worker.db import LocalWorkerDBClient
            if not LocalWorkerDBClient.has_other_active_mailboxes(exclude_user_id=user_id):
                poll_flag_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local", "sentinel_production_polling.txt")
                if os.path.exists(poll_flag_path):
                    os.remove(poll_flag_path)
        except Exception:
            pass
        res = client.table("sentinel_workers").delete().eq("user_id", user_id).execute()
        if res and res.data:
            return True, "Sentinel configuration permanently deleted."
        return False, "No Sentinel configuration found to delete."
    except Exception as e:
        return False, f"Deletion error: {str(e)}"


# =====================================================================
# Sentinel Mail Processing Activity Telemetry
# =====================================================================
def get_user_sentinel_activity_stats(
    user_id: str,
    mailbox_id: Optional[str] = None,
    client: Any = None,
    checkpoint_rec: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Returns tenant-isolated mail processing statistics (Section 5 & 6).
    Guarantees zero cross-tenant leakage.
    """
    from core.sentinel_stats import get_user_sentinel_stats
    return get_user_sentinel_stats(
        user_id=user_id,
        mailbox_id=mailbox_id,
        client=client,
        checkpoint_rec=checkpoint_rec
    )

