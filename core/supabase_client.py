"""
core/supabase_client.py
Supabase Client & Auth Management for EMAILSHIELD INDIA.
Handles user authentication, session binding, and PostgREST client instantiation.
"""
import os
from typing import Optional, Dict, Any, Tuple
from supabase import create_client, Client, ClientOptions


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


def get_supabase_client(jwt: Optional[str] = None) -> Optional[Client]:
    """
    Returns an initialized Supabase Client.
    If jwt is provided, configures the client with the user's Bearer token
    so that PostgreSQL RLS policies evaluate auth.uid() == user_id.
    """
    url, key = get_supabase_credentials()
    if not url or not key:
        return None

    options = ClientOptions()
    if jwt:
        options.headers = {"Authorization": f"Bearer {jwt}"}

    return create_client(url, key, options=options)


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
