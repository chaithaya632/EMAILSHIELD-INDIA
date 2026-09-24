"""
core/alert_session.py
Ephemeral, in-memory credential storage for Telegram and WhatsApp threat alerting.

Complies with:
1. Zero Secret Exposure: Plaintext tokens/keys never stored in session_state or logged.
2. Cryptographic Protection: AES-256-GCM authenticated encryption from core.sentinel_crypto
   with per-user context binding and module-level ephemeral 256-bit key.
3. Multi-Tenant Isolation: Credentials stored in _ALERT_SESSION_STORE keyed by user_id.
4. Lifetime Bounded: Purged on explicit disconnect, logout, or server restart.
5. Schema Invariance: No database persistence or migrations required.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple

import streamlit as st

from core.sentinel_crypto import encrypt_secret, decrypt_secret
from core.telegram_alert import mask_telegram_chat_id
from core.whatsapp_alert import mask_phone_number

logger = logging.getLogger(__name__)

# Module-level ephemeral 256-bit AES key (in-memory only, discarded on process exit)
_EPHEMERAL_MASTER_KEY: bytes = os.urandom(32)

# Multi-tenant in-memory alert credentials store keyed by user_id
_ALERT_SESSION_STORE: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# TELEGRAM ALERT SESSION MANAGEMENT
# =============================================================================

def save_telegram_connection(
    user_id: str,
    bot_token: str,
    chat_id: str,
    bot_username: Optional[str] = None,
) -> None:
    """
    Encrypts bot_token and chat_id using AES-256-GCM with context 'telegram_{user_id}'.
    Stores encrypted envelopes in _ALERT_SESSION_STORE[user_id]['telegram'].
    Sets non-secret flags in st.session_state and store.
    Pops temporary widget input keys.
    """
    if not user_id:
        raise ValueError("user_id is required to save Telegram connection.")

    clean_token = str(bot_token).strip()
    clean_chat = str(chat_id).strip()

    enc_token = encrypt_secret(
        clean_token,
        _EPHEMERAL_MASTER_KEY,
        context=f"telegram_{user_id}",
    )
    enc_chat = encrypt_secret(
        clean_chat,
        _EPHEMERAL_MASTER_KEY,
        context=f"telegram_{user_id}",
    )
    masked_dest = mask_telegram_chat_id(clean_chat)

    if user_id not in _ALERT_SESSION_STORE:
        _ALERT_SESSION_STORE[user_id] = {}

    _ALERT_SESSION_STORE[user_id]["telegram"] = {
        "token_envelope": enc_token,
        "chat_envelope": enc_chat,
        "bot_username": bot_username,
        "destination": masked_dest,
        "status": "ACTIVE",
        "connected": True,
    }

    try:
        st.session_state["alert_user_id"] = user_id
        st.session_state["telegram_connected"] = True
        st.session_state["telegram_status"] = "ACTIVE"
        st.session_state["telegram_destination"] = masked_dest
        st.session_state["telegram_bot_user"] = bot_username
        st.session_state.pop("tg_cfg_tok", None)
        st.session_state.pop("tg_cfg_chat", None)
    except Exception:
        pass


def get_telegram_connection(user_id: str) -> Dict[str, Any]:
    """
    Returns {'connected': bool, 'status': str, 'masked_destination': str, 'bot_username': Optional[str]}.
    Checks st.session_state and restores from _ALERT_SESSION_STORE if needed.
    """
    if not user_id:
        return {
            "connected": False,
            "status": "DISCONNECTED",
            "masked_destination": "",
            "bot_username": None,
        }

    tg_store = _ALERT_SESSION_STORE.get(user_id, {}).get("telegram")

    if tg_store and tg_store.get("connected"):
        try:
            st.session_state["alert_user_id"] = user_id
            st.session_state["telegram_connected"] = True
            st.session_state["telegram_status"] = tg_store.get("status", "ACTIVE")
            st.session_state["telegram_destination"] = tg_store.get("destination", "")
            st.session_state["telegram_bot_user"] = tg_store.get("bot_username")
        except Exception:
            pass

        return {
            "connected": True,
            "status": tg_store.get("status", "ACTIVE"),
            "masked_destination": tg_store.get("destination", ""),
            "bot_username": tg_store.get("bot_username"),
        }

    if tg_store:
        return {
            "connected": False,
            "status": tg_store.get("status", "DISCONNECTED"),
            "masked_destination": tg_store.get("destination", ""),
            "bot_username": tg_store.get("bot_username"),
        }

    status = "DISCONNECTED"
    masked_dest = ""
    bot_user = None

    try:
        sess_user = st.session_state.get("alert_user_id") or st.session_state.get("user_id")
        if sess_user == user_id:
            raw_status = st.session_state.get("telegram_status", "DISCONNECTED")
            if raw_status in ("CONNECTION_FAILED", "TEST_FAILED", "DISCONNECTED"):
                status = raw_status
            masked_dest = st.session_state.get("telegram_destination", "")
            bot_user = st.session_state.get("telegram_bot_user")
    except Exception:
        pass

    return {
        "connected": False,
        "status": status,
        "masked_destination": masked_dest,
        "bot_username": bot_user,
    }


def get_telegram_credentials(user_id: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Decrypts and returns (bot_token, chat_id) strictly for runtime test alert delivery.
    Never exposes decrypted credentials outside transient memory scope.
    """
    if not user_id:
        return None, None

    tg_store = _ALERT_SESSION_STORE.get(user_id, {}).get("telegram")
    if not tg_store:
        return None, None

    token_envelope = tg_store.get("token_envelope")
    chat_envelope = tg_store.get("chat_envelope")
    if not token_envelope or not chat_envelope:
        return None, None

    try:
        bot_token = decrypt_secret(
            token_envelope,
            _EPHEMERAL_MASTER_KEY,
            context=f"telegram_{user_id}",
        )
        chat_id = decrypt_secret(
            chat_envelope,
            _EPHEMERAL_MASTER_KEY,
            context=f"telegram_{user_id}",
        )
        return bot_token, chat_id
    except Exception as e:
        logger.error("Failed to decrypt Telegram credentials for user: %s", type(e).__name__)
        return None, None


def disconnect_telegram(user_id: str) -> None:
    """
    Removes Telegram connection from _ALERT_SESSION_STORE and resets
    telegram session state flags in st.session_state.
    """
    if user_id and user_id in _ALERT_SESSION_STORE:
        _ALERT_SESSION_STORE[user_id].pop("telegram", None)

    try:
        st.session_state["alert_user_id"] = user_id
        st.session_state["telegram_connected"] = False
        st.session_state["telegram_status"] = "DISCONNECTED"
        st.session_state["telegram_destination"] = ""
        st.session_state["telegram_bot_user"] = None
    except Exception:
        pass


def set_telegram_status(user_id: str, status: str) -> None:
    """Updates telegram_status in session_state and store (e.g. 'CONNECTION_FAILED', 'TEST_FAILED')."""
    if user_id:
        if user_id not in _ALERT_SESSION_STORE:
            _ALERT_SESSION_STORE[user_id] = {}
        if "telegram" not in _ALERT_SESSION_STORE[user_id]:
            _ALERT_SESSION_STORE[user_id]["telegram"] = {
                "connected": False,
                "status": status,
                "destination": "",
                "bot_username": None,
            }
        else:
            _ALERT_SESSION_STORE[user_id]["telegram"]["status"] = status
            if status != "ACTIVE":
                _ALERT_SESSION_STORE[user_id]["telegram"]["connected"] = False
    try:
        st.session_state["alert_user_id"] = user_id
        st.session_state["telegram_status"] = status
    except Exception:
        pass


# =============================================================================
# WHATSAPP ALERT SESSION MANAGEMENT
# =============================================================================

def save_whatsapp_connection(user_id: str, phone: str, apikey: str) -> None:
    """
    Encrypts phone and apikey using AES-256-GCM with context 'whatsapp_{user_id}'.
    Stores encrypted envelopes in _ALERT_SESSION_STORE[user_id]['whatsapp'].
    Sets non-secret flags in st.session_state and store.
    Pops temporary widget input keys.
    """
    if not user_id:
        raise ValueError("user_id is required to save WhatsApp connection.")

    clean_phone = str(phone).strip()
    clean_key = str(apikey).strip()

    enc_phone = encrypt_secret(
        clean_phone,
        _EPHEMERAL_MASTER_KEY,
        context=f"whatsapp_{user_id}",
    )
    enc_key = encrypt_secret(
        clean_key,
        _EPHEMERAL_MASTER_KEY,
        context=f"whatsapp_{user_id}",
    )
    masked_dest = mask_phone_number(clean_phone)

    if user_id not in _ALERT_SESSION_STORE:
        _ALERT_SESSION_STORE[user_id] = {}

    _ALERT_SESSION_STORE[user_id]["whatsapp"] = {
        "phone_envelope": enc_phone,
        "apikey_envelope": enc_key,
        "destination": masked_dest,
        "status": "ACTIVE",
        "connected": True,
    }

    try:
        st.session_state["alert_user_id"] = user_id
        st.session_state["whatsapp_connected"] = True
        st.session_state["whatsapp_status"] = "ACTIVE"
        st.session_state["whatsapp_destination"] = masked_dest
        st.session_state.pop("wa_cfg_ph", None)
        st.session_state.pop("wa_cfg_key", None)
        st.session_state.pop("wa_cfg_phone", None)
    except Exception:
        pass


def get_whatsapp_connection(user_id: str) -> Dict[str, Any]:
    """
    Returns {'connected': bool, 'status': str, 'masked_destination': str}.
    Checks st.session_state and restores from _ALERT_SESSION_STORE if needed.
    """
    if not user_id:
        return {
            "connected": False,
            "status": "DISCONNECTED",
            "masked_destination": "",
        }

    wa_store = _ALERT_SESSION_STORE.get(user_id, {}).get("whatsapp")

    if wa_store and wa_store.get("connected"):
        try:
            st.session_state["alert_user_id"] = user_id
            st.session_state["whatsapp_connected"] = True
            st.session_state["whatsapp_status"] = wa_store.get("status", "ACTIVE")
            st.session_state["whatsapp_destination"] = wa_store.get("destination", "")
        except Exception:
            pass

        return {
            "connected": True,
            "status": wa_store.get("status", "ACTIVE"),
            "masked_destination": wa_store.get("destination", ""),
        }

    if wa_store:
        return {
            "connected": False,
            "status": wa_store.get("status", "DISCONNECTED"),
            "masked_destination": wa_store.get("destination", ""),
        }

    status = "DISCONNECTED"
    masked_dest = ""

    try:
        sess_user = st.session_state.get("alert_user_id") or st.session_state.get("user_id")
        if sess_user == user_id:
            raw_status = st.session_state.get("whatsapp_status", "DISCONNECTED")
            if raw_status in ("CONNECTION_FAILED", "TEST_FAILED", "DISCONNECTED"):
                status = raw_status
            masked_dest = st.session_state.get("whatsapp_destination", "")
    except Exception:
        pass

    return {
        "connected": False,
        "status": status,
        "masked_destination": masked_dest,
    }


def get_whatsapp_credentials(user_id: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Decrypts and returns (phone, apikey) strictly for runtime test alert delivery.
    Never exposes decrypted credentials outside transient memory scope.
    """
    if not user_id:
        return None, None

    wa_store = _ALERT_SESSION_STORE.get(user_id, {}).get("whatsapp")
    if not wa_store:
        return None, None

    phone_envelope = wa_store.get("phone_envelope")
    apikey_envelope = wa_store.get("apikey_envelope")
    if not phone_envelope or not apikey_envelope:
        return None, None

    try:
        phone = decrypt_secret(
            phone_envelope,
            _EPHEMERAL_MASTER_KEY,
            context=f"whatsapp_{user_id}",
        )
        apikey = decrypt_secret(
            apikey_envelope,
            _EPHEMERAL_MASTER_KEY,
            context=f"whatsapp_{user_id}",
        )
        return phone, apikey
    except Exception as e:
        logger.error("Failed to decrypt WhatsApp credentials for user: %s", type(e).__name__)
        return None, None


def disconnect_whatsapp(user_id: str) -> None:
    """
    Removes WhatsApp connection from _ALERT_SESSION_STORE and resets
    whatsapp session state flags in st.session_state.
    """
    if user_id and user_id in _ALERT_SESSION_STORE:
        _ALERT_SESSION_STORE[user_id].pop("whatsapp", None)

    try:
        st.session_state["alert_user_id"] = user_id
        st.session_state["whatsapp_connected"] = False
        st.session_state["whatsapp_status"] = "DISCONNECTED"
        st.session_state["whatsapp_destination"] = ""
    except Exception:
        pass


def set_whatsapp_status(user_id: str, status: str) -> None:
    """Updates whatsapp_status in session_state and store (e.g. 'CONNECTION_FAILED', 'TEST_FAILED')."""
    if user_id:
        if user_id not in _ALERT_SESSION_STORE:
            _ALERT_SESSION_STORE[user_id] = {}
        if "whatsapp" not in _ALERT_SESSION_STORE[user_id]:
            _ALERT_SESSION_STORE[user_id]["whatsapp"] = {
                "connected": False,
                "status": status,
                "destination": "",
            }
        else:
            _ALERT_SESSION_STORE[user_id]["whatsapp"]["status"] = status
            if status != "ACTIVE":
                _ALERT_SESSION_STORE[user_id]["whatsapp"]["connected"] = False
    try:
        st.session_state["alert_user_id"] = user_id
        st.session_state["whatsapp_status"] = status
    except Exception:
        pass


# =============================================================================
# PURGE / CLEANUP
# =============================================================================

def clear_alert_session(user_id: Optional[str] = None) -> None:
    """
    If user_id: purges _ALERT_SESSION_STORE.pop(user_id, None).
    If user_id is None: clears _ALERT_SESSION_STORE.clear().
    Clears alert keys from st.session_state.
    """
    if user_id:
        _ALERT_SESSION_STORE.pop(user_id, None)
    else:
        _ALERT_SESSION_STORE.clear()

    alert_keys = [
        "alert_user_id",
        "telegram_connected", "telegram_status", "telegram_destination", "telegram_bot_user",
        "whatsapp_connected", "whatsapp_status", "whatsapp_destination",
        "sentinel_tg_token", "sentinel_tg_destination", "sentinel_tg_target",
        "sentinel_tg_enabled", "sentinel_wa_apikey", "sentinel_wa_destination",
        "sentinel_wa_enabled", "_enc_tg_token", "_enc_tg_chat", "_enc_wa_phone",
        "_enc_wa_key", "tg_cfg_tok", "tg_cfg_chat", "wa_cfg_ph", "wa_cfg_key", "wa_cfg_phone"
    ]
    try:
        for k in alert_keys:
            st.session_state.pop(k, None)
    except Exception:
        pass


__all__ = [
    "_ALERT_SESSION_STORE",
    "_EPHEMERAL_MASTER_KEY",
    "save_telegram_connection",
    "get_telegram_connection",
    "get_telegram_credentials",
    "disconnect_telegram",
    "set_telegram_status",
    "save_whatsapp_connection",
    "get_whatsapp_connection",
    "get_whatsapp_credentials",
    "disconnect_whatsapp",
    "set_whatsapp_status",
    "clear_alert_session",
]
