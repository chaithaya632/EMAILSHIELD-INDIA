"""
core/telegram_alert.py
Secure Telegram Alert & Bot Integration for EMAILSHIELD INDIA.

Security Guarantees:
1. Zero token leakage: Tokens are never logged, never printed, never stored in plain DB,
   and sanitized from all URLs, network exceptions, and error messages.
2. Runtime configuration: Resolves credentials securely from os.environ, Streamlit secrets,
   or transient session state without filesystem/git exposure.
3. Separation of Concerns: Strict distinction between Bot Authentication (TELEGRAM_BOT_TOKEN)
   and Notification Destination (TELEGRAM_CHAT_ID / destination_target).
4. Controlled Testing: Safe 4-phase connectivity test without any email or sensitive data.
"""

import os
import re
import datetime
from typing import Optional, Dict, Any, Tuple, Union
import requests

# Telegram bot token regex pattern: <8-10 digits>:<35 alphanumeric/dash/underscore chars>
TELEGRAM_TOKEN_REGEX = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
TELEGRAM_URL_REGEX = re.compile(r"api\.telegram\.org/bot[^/\s]+", re.IGNORECASE)


def sanitize_telegram_token(text: str, token: Optional[str] = None) -> str:
    """
    Sanitizes Telegram Bot Tokens and sensitive API URLs from any text or exception message.
    Guarantees no raw tokens leak into logs, UI, or forensic reports.
    """
    if not text:
        return ""
    sanitized = str(text)
    if token and token.strip() and token.strip() in sanitized:
        sanitized = sanitized.replace(token.strip(), "[REDACTED_BOT_TOKEN]")
    sanitized = TELEGRAM_TOKEN_REGEX.sub("[REDACTED_BOT_TOKEN]", sanitized)
    sanitized = TELEGRAM_URL_REGEX.sub("api.telegram.org/bot[REDACTED_BOT_TOKEN]", sanitized)
    return sanitized


def validate_telegram_token_format(token: Optional[str]) -> bool:
    """Validates Telegram Bot Token format (<bot_id>:<token_string>)."""
    if not token or not isinstance(token, str):
        return False
    clean = token.strip()
    return bool(TELEGRAM_TOKEN_REGEX.match(clean))


def validate_telegram_chat_id(chat_id: Optional[Union[str, int]]) -> Tuple[bool, str]:
    """
    Validates Telegram Chat ID format.
    Accepts:
    - Numeric chat IDs (e.g. 123456789, -100123456789)
    - Public channel/group handles starting with '@' (e.g. @my_channel)
    """
    if chat_id is None:
        return False, "Telegram Chat ID is required."
    cid_str = str(chat_id).strip()
    if not cid_str:
        return False, "Telegram Chat ID is required."

    # Numeric (including negative group/supergroup IDs)
    if re.match(r"^-?\d{5,20}$", cid_str):
        return True, "Valid numeric Chat ID."

    # Channel/Group public handle
    if re.match(r"^@[A-Za-z0-9_]{5,32}$", cid_str):
        return True, "Valid channel handle."

    return False, "Invalid Chat ID. Must be a numeric ID (e.g. 123456789) or public @channel handle."


def mask_telegram_chat_id(chat_id: Optional[Union[str, int]]) -> str:
    """
    Masks Telegram chat ID or handle for secure UI presentation.
    Example: 123456789 -> ••••••789
             @my_channel -> @••••nel
    """
    if chat_id is None:
        return "Not Configured"
    cid_str = str(chat_id).strip()
    if not cid_str:
        return "Not Configured"
    if cid_str.startswith("@"):
        handle = cid_str[1:]
        if len(handle) <= 4:
            return f"@••••{handle[-1:]}"
        return f"@••••{handle[-3:]}"
    # Numeric
    if len(cid_str) <= 4:
        return "••••" + cid_str[-2:] if len(cid_str) >= 2 else "••••"
    return "•" * max(4, len(cid_str) - 3) + cid_str[-3:]


def get_telegram_config(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Resolves Telegram configuration securely from runtime sources in priority order:
    1. Overrides (transient session input or passed dict)
    2. Streamlit session state (sentinel_tg_destination, sentinel_tg_token)
    3. Environment variables (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
    4. Streamlit secrets (st.secrets["TELEGRAM_BOT_TOKEN"], etc.)
    5. Database alert record (for destination_target)

    Never persists the bot token to database or disk.
    """
    overrides = overrides or {}

    # 1. Resolve Bot Token
    token = overrides.get("telegram_token") or overrides.get("bot_token") or overrides.get("token")
    if not token:
        try:
            import streamlit as st
            token = st.session_state.get("sentinel_tg_token") or st.session_state.get("telegram_bot_token")
        except Exception:
            token = None
    if not token:
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        try:
            import streamlit as st
            token = st.secrets.get("TELEGRAM_BOT_TOKEN")
            if not token and "telegram" in st.secrets:
                token = st.secrets["telegram"].get("bot_token") or st.secrets["telegram"].get("token")
        except Exception:
            token = None

    token = str(token).strip() if token else ""

    # 2. Resolve Chat ID (Destination)
    chat_id = overrides.get("destination_target") or overrides.get("telegram_chat_id") or overrides.get("chat_id")
    if not chat_id:
        try:
            import streamlit as st
            chat_id = (
                st.session_state.get("sentinel_tg_destination")
                or st.session_state.get("sentinel_tg_target")
                or st.session_state.get("telegram_chat_id")
                or st.session_state.get("telegram_destination")
            )
        except Exception:
            chat_id = None
    if not chat_id:
        chat_id = os.environ.get("TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_DESTINATION")
    if not chat_id:
        try:
            import streamlit as st
            chat_id = st.secrets.get("TELEGRAM_CHAT_ID")
            if not chat_id and "telegram" in st.secrets:
                chat_id = st.secrets["telegram"].get("chat_id")
        except Exception:
            chat_id = None

    chat_id = str(chat_id).strip() if chat_id else ""

    # 3. Resolve Enabled Flag
    if "is_enabled" in overrides or "telegram_enabled" in overrides:
        is_enabled = bool(overrides.get("telegram_enabled", overrides.get("is_enabled", False)))
    else:
        try:
            import streamlit as st
            is_enabled = bool(st.session_state.get("sentinel_tg_enabled", False))
        except Exception:
            is_enabled = False

    is_token_valid = validate_telegram_token_format(token)
    is_dest_valid, _ = validate_telegram_chat_id(chat_id)

    return {
        "token": token,
        "chat_id": chat_id,
        "is_token_configured": is_token_valid,
        "is_destination_configured": is_dest_valid,
        "is_enabled": is_enabled,
        "masked_destination": mask_telegram_chat_id(chat_id if is_dest_valid else ""),
    }


def verify_telegram_bot_token(bot_token: str, timeout: float = 6.0) -> Tuple[bool, Optional[str], str]:
    """
    Authenticates with the Telegram Bot API using the getMe endpoint.
    Retrieves the public bot username without exposing the token.
    Returns: (is_authenticated, bot_username, message)
    """
    if not validate_telegram_token_format(bot_token):
        return False, None, "Invalid Telegram Bot Token format."

    clean_token = bot_token.strip()
    url = f"https://api.telegram.org/bot{clean_token}/getMe"

    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok") and "result" in data:
                username = data["result"].get("username", "UnknownBot")
                return True, f"@{username}", f"Authenticated successfully as @{username}."
            return False, None, "Telegram API returned unexpected response format."
        elif resp.status_code == 401:
            return False, None, "Telegram authentication failed: Invalid bot token (Unauthorized)."
        elif resp.status_code == 404:
            return False, None, "Telegram authentication failed: Bot not found."
        else:
            return False, None, f"Telegram API returned HTTP {resp.status_code}."
    except requests.exceptions.Timeout:
        return False, None, "Telegram API connection timed out."
    except Exception as e:
        safe_err = sanitize_telegram_token(str(e), clean_token)
        return False, None, f"Telegram connection error: {safe_err}"


def send_telegram_alert(
    bot_token: str,
    chat_id: str,
    text: str,
    timeout: float = 10.0
) -> Tuple[bool, str]:
    """
    Dispatches an instant alert notification via the official Telegram Bot API.
    Sanitizes all responses and error messages so no token ever leaks.
    """
    token = (bot_token or "").strip()
    cid = (chat_id or "").strip()

    if not validate_telegram_token_format(token):
        return False, "Invalid Telegram Bot Token format."

    valid_cid, cid_err = validate_telegram_chat_id(cid)
    if not valid_cid:
        return False, cid_err

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": cid,
        "text": text,
        "parse_mode": "Markdown"
    }

    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        
        if resp.status_code == 200 and data.get("ok"):
            return True, "Telegram alert successfully delivered."

        # Parse and sanitize error description
        err_desc = data.get("description", resp.text[:120]) if data else resp.text[:120]
        safe_desc = sanitize_telegram_token(err_desc, token)

        if "chat not found" in safe_desc.lower():
            return False, (
                "Telegram destination error: 'Chat not found'.\n"
                "👉 Fix: Open your bot in Telegram and click 'START' (bots cannot message you until you press Start).\n"
                "👉 Ensure Chat ID is your numeric ID (from @userinfobot), not your @username."
            )
        elif "bot was blocked" in safe_desc.lower():
            return False, "Telegram destination error: Bot was blocked by the user."
        elif "unauthorized" in safe_desc.lower() or resp.status_code == 401:
            return False, "Telegram authentication failed: Invalid bot token."
        
        return False, f"Telegram dispatch error: {safe_desc}"
    except requests.exceptions.Timeout:
        return False, "Telegram alert dispatch timed out."
    except Exception as e:
        safe_err = sanitize_telegram_token(str(e), token)
        return False, f"Telegram dispatch failed: {safe_err}"


def test_telegram_alert_delivery(
    bot_token: str,
    chat_id: str,
    timeout: float = 8.0
) -> Dict[str, Any]:
    """
    Executes a controlled 4-phase connectivity and delivery test:
    1. Telegram API (reachable)
    2. Telegram Authentication (getMe)
    3. Telegram Destination (syntax & format)
    4. Test Alert delivery (harmless controlled ping, zero email data)

    Never leaks credentials or sensitive information.
    """
    result = {
        "api_status": "FAIL",
        "auth_status": "FAIL",
        "destination_status": "FAIL",
        "delivery_status": "FAILED",
        "bot_username": None,
        "details": "",
    }

    # Step 1 & 2: API reachability & Bot Authentication via getMe
    auth_ok, bot_user, auth_msg = verify_telegram_bot_token(bot_token, timeout=timeout)
    if not auth_ok:
        if "timed out" in auth_msg.lower() or "connection error" in auth_msg.lower():
            result["api_status"] = "FAIL"
            result["auth_status"] = "FAIL"
            result["details"] = f"API unreachable: {auth_msg}"
        else:
            result["api_status"] = "PASS"
            result["auth_status"] = "FAIL"
            result["details"] = auth_msg
        return result

    result["api_status"] = "PASS"
    result["auth_status"] = "PASS"
    result["bot_username"] = bot_user

    # Step 3: Destination validation
    dest_ok, dest_msg = validate_telegram_chat_id(chat_id)
    if not dest_ok:
        result["destination_status"] = "FAIL"
        result["details"] = dest_msg
        return result

    result["destination_status"] = "PASS"

    # Step 4: Controlled test alert delivery
    now_str = datetime.datetime.now().strftime("%d-%b-%Y %I:%M:%S %p")
    test_message = (
        "🛡️ *EMAILSHIELD INDIA — TELEGRAM ALERT TEST*\n\n"
        "✅ *Controlled Verification Alert*\n"
        "Your Sentinel mobile notification channel is *ACTIVE and VERIFIED*!\n"
        "Live Mailbox Sentinel will notify this chat immediately upon detecting HIGH or CRITICAL threats.\n\n"
        "🔒 *Security Note*: Controlled test only. Zero email data or credentials involved.\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕒 Verified at: {now_str} | _EmailShield Sentinel_"
    )

    deliver_ok, deliver_msg = send_telegram_alert(bot_token, chat_id, test_message, timeout=timeout)
    if deliver_ok:
        result["delivery_status"] = "DELIVERED"
        result["details"] = f"Test alert successfully delivered to chat {chat_id} via {bot_user or 'bot'}."
    else:
        result["delivery_status"] = "FAILED"
        result["details"] = deliver_msg

    return result


run_telegram_connectivity_test = test_telegram_alert_delivery

