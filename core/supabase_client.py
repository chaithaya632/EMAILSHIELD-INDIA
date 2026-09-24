"""
core/supabase_client.py
Supabase Client & Auth Management for EMAILSHIELD INDIA.
Handles user authentication, session binding, and PostgREST client instantiation.
"""
import os
from typing import Optional, Dict, Any, Tuple
from supabase import create_client, Client, ClientOptions

__all__ = [
    "get_supabase_credentials",
    "is_supabase_configured",
    "get_supabase_client",
    "sign_in_user",
    "sign_up_user",
    "sign_out_user",
    "is_jwt_expired",
    "refresh_user_session",
    "clear_supabase_client_cache",
]


def get_supabase_credentials() -> Tuple[str, str]:
    """Retrieve Supabase URL and Anon Key from environment or Streamlit secrets."""
    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_ANON_KEY", "")
    if not url or not key:
        try:
            import streamlit as st
            url = url or st.secrets.get("SUPABASE_URL", "")
            key = key or st.secrets.get("SUPABASE_ANON_KEY", "")
        except Exception:
            pass
    return url, key


def is_supabase_configured() -> bool:
    """Returns True if valid Supabase connection credentials exist."""
    url, key = get_supabase_credentials()
    return bool(url and key and not url.startswith("your-"))


_CLIENT_CACHE: Dict[Tuple[str, Optional[str]], Client] = {}


def clear_supabase_client_cache(jwt: Optional[str] = None) -> None:
    """Purge cached Supabase client instances on sign-out or session expiry."""
    global _CLIENT_CACHE
    if jwt:
        for k in list(_CLIENT_CACHE.keys()):
            if k[1] == jwt:
                _CLIENT_CACHE.pop(k, None)
    else:
        _CLIENT_CACHE.clear()


def get_supabase_client(jwt: Optional[str] = None) -> Optional[Client]:
    """
    Returns an initialized Supabase Client.
    If jwt is provided, configures the client with the user's Bearer token
    so that PostgreSQL RLS policies evaluate auth.uid() == user_id.
    Reuses connection pools across requests to maintain HTTP keep-alive.
    """
    url, key = get_supabase_credentials()
    if not url or not key:
        return None

    cache_key = (key, jwt)
    if cache_key in _CLIENT_CACHE:
        return _CLIENT_CACHE[cache_key]

    options = ClientOptions()
    if jwt:
        options.headers = {"Authorization": f"Bearer {jwt}"}

    client = create_client(url, key, options=options)
    if len(_CLIENT_CACHE) >= 64:
        _CLIENT_CACHE.clear()
    _CLIENT_CACHE[cache_key] = client
    return client


def sign_in_user(email: str, password: str) -> Tuple[bool, Any]:
    """Authenticate existing user via Supabase Auth."""
    url, key = get_supabase_credentials()
    if not url or not key:
        return False, "Supabase credentials not configured."

    try:
        client = create_client(url, key)
        res = client.auth.sign_in_with_password({"email": email.strip(), "password": password})
        if res and res.session:
            return True, res.session
        return False, "Invalid credentials or authentication failed."
    except Exception as e:
        return False, f"Authentication error: {str(e)}"


def sign_up_user(email: str, password: str, display_name: str = "") -> Tuple[bool, Any]:
    """Register a new user via Supabase Auth and initialize profile."""
    url, key = get_supabase_credentials()
    if not url or not key:
        return False, "Supabase credentials not configured."

    try:
        client = create_client(url, key)
        data = {"display_name": display_name.strip()} if display_name else {}
        res = client.auth.sign_up({"email": email.strip(), "password": password, "options": {"data": data}})
        if res and res.user:
            if res.session:
                user_client = get_supabase_client(res.session.access_token)
                if user_client:
                    try:
                        user_client.table("profiles").upsert({
                            "id": res.user.id,
                            "display_name": display_name.strip()
                        }).execute()
                    except Exception:
                        pass
                return True, res.session
            return True, "Registration successful! Please check your email to verify your account."
        return False, "Registration failed."
    except Exception as e:
        return False, f"Registration error: {str(e)}"


def sign_out_user(jwt: Optional[str] = None) -> bool:
    """Sign out user from Supabase."""
    try:
        client = get_supabase_client(jwt)
        if client:
            client.auth.sign_out()
        return True
    except Exception:
        return False


def is_jwt_expired(jwt_token: Optional[str]) -> bool:
    """
    Checks whether a Supabase JWT access token has expired (or is close to expiring within 30s)
    by decoding its base64 payload claims without cryptographic network verification.
    """
    if not jwt_token or not isinstance(jwt_token, str):
        return True
    try:
        import base64
        import json
        import time

        parts = jwt_token.strip().split(".")
        if len(parts) != 3:
            return True
        payload_b64 = parts[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
        exp = payload.get("exp", 0)
        # 30-second margin before hard rejection
        return time.time() >= (exp - 30)
    except Exception:
        return True


def refresh_user_session(refresh_token: str) -> Tuple[bool, Any]:
    """
    Refreshes an expired user JWT using their stored refresh token.
    Returns: (is_success, session_or_error)
    """
    url, key = get_supabase_credentials()
    if not url or not key or not refresh_token:
        return False, "Supabase credentials or refresh token missing."

    try:
        client = create_client(url, key)
        res = client.auth.refresh_session(refresh_token.strip())
        if res and res.session:
            return True, res.session
        return False, "Failed to refresh session."
    except Exception as e:
        return False, f"Session refresh error: {str(e)}"

