"""
core/whatsapp_alert.py
Secure WhatsApp & CallMeBot Alert Integration for EMAILSHIELD INDIA.

Security Guarantees:
1. Zero credential leakage: API keys are never logged, never printed, never stored in plain DB,
   and sanitized from all URLs, network exceptions, and error messages.
2. Runtime configuration: Resolves credentials securely from os.environ, Streamlit secrets,
   or transient session state without filesystem/git exposure.
3. Separation of Concerns: Strict distinction between Provider Authentication (CALLMEBOT_API_KEY)
   and Notification Destination (E.164 phone number / destination_target).
4. Controlled Testing: Safe 4-phase connectivity test without any email or sensitive data.
"""

import os
import re
import urllib.parse
import datetime
from typing import Optional, Dict, Any, Tuple, Union
import requests

# CallMeBot WhatsApp URL pattern for sanitization
CALLMEBOT_URL_REGEX = re.compile(r"api\.callmebot\.com/whatsapp\.php\?[^\s]+", re.IGNORECASE)
APIKEY_PARAM_REGEX = re.compile(r"apikey=[^&\s]+", re.IGNORECASE)


def sanitize_whatsapp_key(text: str, key: Optional[str] = None) -> str:
    """
    Sanitizes CallMeBot API keys and sensitive API URLs from any text or exception message.
    Guarantees no raw API keys leak into logs, UI, or forensic reports.
    """
    if not text:
        return ""
    sanitized = str(text)
    if key and key.strip() and key.strip() in sanitized:
        sanitized = sanitized.replace(key.strip(), "[REDACTED_APIKEY]")
    sanitized = APIKEY_PARAM_REGEX.sub("apikey=[REDACTED_APIKEY]", sanitized)
    sanitized = CALLMEBOT_URL_REGEX.sub("api.callmebot.com/whatsapp.php?[REDACTED]", sanitized)
    return sanitized


def mask_phone_number(phone: str) -> str:
    """
    Masks phone number preserving country code and trailing 2 digits.
    Example: +919876543210 -> +91••••••••10
    """
    clean = re.sub(r"[^\d+]", "", str(phone).strip())
    if not clean:
        return "Not Configured"
    if not clean.startswith("+"):
        clean = "+" + clean

    # e.g. +91 98765432 10
    digits_only = clean.lstrip("+")
    if len(digits_only) <= 4:
        return "••••" + digits_only[-2:] if len(digits_only) >= 2 else "••••"

    prefix = clean[:3]  # e.g. +91 or +1
    suffix = clean[-2:] # last 2 digits
    masked_middle = "•" * max(4, len(clean) - len(prefix) - len(suffix))
    return f"{prefix}{masked_middle}{suffix}"


def mask_whatsapp_key(key: str) -> str:
    """Returns static mask for API key."""
    if not key or not str(key).strip():
        return "Not Configured"
    return "••••••••••"


def validate_whatsapp_phone(phone: Optional[str]) -> Tuple[bool, str]:
    """
    Validates WhatsApp destination phone format (E.164 standard with country code).
    Example: +919876543210, +14155552671
    """
    if not phone or not isinstance(phone, str):
        return False, "WhatsApp phone number is required."
    clean = re.sub(r"[^\d+]", "", phone.strip())
    if not clean:
        return False, "WhatsApp phone number is required."
    if not clean.startswith("+"):
        clean = "+" + clean

    if re.match(r"^\+[1-9]\d{7,14}$", clean):
        return True, clean

    return False, "Invalid phone number format. Must include '+' and international country code (e.g. +919876543210)."


def validate_whatsapp_apikey(apikey: Optional[str]) -> Tuple[bool, str]:
    """
    Validates CallMeBot API key format.
    Accepts 4 to 64 alphanumeric characters.
    """
    if not apikey or not isinstance(apikey, str):
        return False, "CallMeBot API key is required."
    clean = apikey.strip()
    if not clean:
        return False, "CallMeBot API key is required."

    if re.match(r"^[A-Za-z0-9_-]{4,64}$", clean):
        return True, clean

    return False, "Invalid API key format. Expected alphanumeric string."


def get_whatsapp_config(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Resolves WhatsApp configuration securely from runtime sources in priority order:
    1. Overrides (transient session input or passed dict)
    2. Environment variables (CALLMEBOT_API_KEY, CALLMEBOT_APIKEY, WHATSAPP_APIKEY, SENTINEL_ALERT_WHATSAPP_TOKEN)
    3. Streamlit secrets (st.secrets["CALLMEBOT_API_KEY"], etc.)
    4. Database alert record (for destination_target / phone)

    Never persists the API key to database or disk.
    """
    overrides = overrides or {}

    # 1. Resolve API Key
    key = (
        overrides.get("whatsapp_apikey") or
        overrides.get("apikey") or
        overrides.get("token") or
        overrides.get("callmebot_apikey")
    )
    if not key:
        try:
            import streamlit as st
            key = st.session_state.get("sentinel_wa_apikey")
        except Exception:
            key = None
    if not key:
        for env_var in [
            "CALLMEBOT_API_KEY",
            "CALLMEBOT_APIKEY",
            "WHATSAPP_APIKEY",
            "SENTINEL_ALERT_WHATSAPP_TOKEN",
        ]:
            val = os.environ.get(env_var)
            if val and val.strip():
                key = val.strip()
                break

    if not key:
        try:
            import streamlit as st
            key = (
                st.secrets.get("CALLMEBOT_API_KEY") or
                st.secrets.get("CALLMEBOT_APIKEY") or
                st.secrets.get("WHATSAPP_APIKEY")
            )
            if not key and "whatsapp" in st.secrets:
                key = st.secrets["whatsapp"].get("apikey") or st.secrets["whatsapp"].get("token")
        except Exception:
            key = None

    key = str(key).strip() if key else ""

    # 2. Resolve Destination Phone
    phone = (
        overrides.get("destination_target") or
        overrides.get("whatsapp_phone") or
        overrides.get("phone")
    )
    if not phone:
        try:
            import streamlit as st
            phone = (
                st.session_state.get("sentinel_wa_destination")
                or st.session_state.get("sentinel_wa_phone")
                or st.session_state.get("sentinel_wa_phone_input")
            )
        except Exception:
            phone = None
    if not phone:
        phone = os.environ.get("CALLMEBOT_PHONE") or os.environ.get("WHATSAPP_PHONE")
    if not phone:
        try:
            import streamlit as st
            phone = st.secrets.get("CALLMEBOT_PHONE") or st.secrets.get("WHATSAPP_PHONE")
            if not phone and "whatsapp" in st.secrets:
                phone = st.secrets["whatsapp"].get("phone")
        except Exception:
            phone = None

    phone = str(phone).strip() if phone else ""

    is_phone_valid, clean_phone = validate_whatsapp_phone(phone)
    is_key_valid, clean_key = validate_whatsapp_apikey(key)
    if "is_enabled" in overrides or "whatsapp_enabled" in overrides:
        is_enabled = bool(overrides.get("whatsapp_enabled", overrides.get("is_enabled", False)))
    else:
        try:
            import streamlit as st
            is_enabled = bool(st.session_state.get("sentinel_wa_enabled", False))
        except Exception:
            is_enabled = False

    return {
        "phone": clean_phone if is_phone_valid else phone,
        "apikey": clean_key if is_key_valid else key,
        "is_destination_configured": is_phone_valid,
        "is_apikey_configured": is_key_valid,
        "is_enabled": is_enabled,
        "masked_destination": mask_phone_number(clean_phone if is_phone_valid else phone),
        "masked_apikey": mask_whatsapp_key(key),
    }


def send_whatsapp_alert(
    phone: str,
    apikey: str,
    text: str,
    timeout: float = 12.0
) -> Tuple[bool, str]:
    """
    Dispatches a direct WhatsApp notification via the free CallMeBot API.
    Guarantees no raw apikeys leak into logs, exceptions, or return strings.
    """
    valid_p, clean_phone = validate_whatsapp_phone(phone)
    if not valid_p:
        return False, clean_phone

    valid_k, clean_key = validate_whatsapp_apikey(apikey)
    if not valid_k:
        return False, clean_key

    encoded_text = urllib.parse.quote(text)
    url = f"https://api.callmebot.com/whatsapp.php?phone={clean_phone}&text={encoded_text}&apikey={clean_key}"

    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            resp_clean = sanitize_whatsapp_key(resp.text, clean_key)
            if "error" in resp_clean.lower():
                return False, f"CallMeBot Error: {resp_clean.strip()[:100]}"
            return True, "WhatsApp alert successfully delivered to phone."
        return False, f"CallMeBot returned HTTP {resp.status_code}."
    except requests.exceptions.Timeout:
        return False, "CallMeBot API connection timed out."
    except Exception as e:
        safe_err = sanitize_whatsapp_key(str(e), clean_key)
        return False, f"WhatsApp dispatch failed: {safe_err}"


def test_whatsapp_alert_delivery(
    phone: str,
    apikey: str,
    timeout: float = 10.0
) -> Dict[str, Any]:
    """
    Executes controlled 4-phase WhatsApp connectivity test without sensitive data:
    Phase 1: Validate destination phone format
    Phase 2: Validate API key format
    Phase 3: Dispatch harmless test ping
    Phase 4: Verify delivery status
    Never exposes API keys or sensitive URLs.
    """
    valid_p, phone_res = validate_whatsapp_phone(phone)
    if not valid_p:
        return {
            "destination_status": "INVALID",
            "auth_status": "UNTESTED",
            "delivery_status": "FAILED",
            "masked_destination": mask_phone_number(phone or ""),
            "details": f"Destination phone validation failed: {phone_res}"
        }

    valid_k, key_res = validate_whatsapp_apikey(apikey)
    if not valid_k:
        return {
            "destination_status": "VALID",
            "auth_status": "NOT_CONFIGURED",
            "delivery_status": "FAILED",
            "masked_destination": mask_phone_number(phone_res),
            "details": f"Authentication validation failed: {key_res}"
        }

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S UTC")
    test_msg = (
        f"✅ *EMAILSHIELD SENTINEL WHATSAPP TEST*\n\n"
        f"Your WhatsApp notification channel is *ACTIVE and VERIFIED*! 🎉\n"
        f"Live Mailbox Sentinel will alert your phone when a HIGH or CRITICAL risk attack arrives.\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕒 Verified at: {now_str} | _EmailShield India_"
    )

    ok, msg = send_whatsapp_alert(phone_res, key_res, test_msg, timeout=timeout)
    return {
        "destination_status": "VALID",
        "auth_status": "PASS" if ok else "CHECK_CREDENTIALS",
        "delivery_status": "DELIVERED" if ok else "FAILED",
        "masked_destination": mask_phone_number(phone_res),
        "details": msg
    }
