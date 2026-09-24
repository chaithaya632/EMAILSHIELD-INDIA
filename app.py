"""
EMAILSHIELD INDIA — Security Operations Console
Modern, modular Streamlit application for email threat detection, live mailbox monitoring,
and forensic investigation triage across India.
"""
import streamlit as st
import html
import uuid
import datetime
import os
from typing import Tuple, Dict, Any, List, Optional

from views._theme import inject_theme, COLORS
from core.classifier import MLClassifier
from core.agent import AutonomousForensicAgent
from core.rate_limiter import check_sliding_window_rate_limit
from core.sentinel_control import (
    get_user_mailbox,
    get_user_worker,
    get_user_checkpoint,
    mask_email_address
)
from core.alert_session import clear_alert_session

try:
    from core.supabase_client import (
        is_supabase_configured,
        get_supabase_client,
        sign_in_user,
        sign_up_user,
        sign_out_user,
        is_jwt_expired,
        refresh_user_session,
        clear_supabase_client_cache,
    )
except ImportError:
    from core.supabase_client import (
        is_supabase_configured,
        get_supabase_client,
        sign_in_user,
        sign_up_user,
        sign_out_user,
    )
    def is_jwt_expired(jwt_token=None):
        return True
    def refresh_user_session(refresh_token=""):
        return False, "Session refresh unavailable"
    def clear_supabase_client_cache(jwt=None):
        pass

# Page configuration
st.set_page_config(
    page_title="EMAILSHIELD INDIA",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Global theme injection
inject_theme()

# Application-level rate limiter
def check_rate_limit(action: str, max_requests: int = 10, window_seconds: int = 60) -> Tuple[bool, int]:
    if "rate_limits" not in st.session_state:
        st.session_state["rate_limits"] = {}
    return check_sliding_window_rate_limit(
        tracker=st.session_state["rate_limits"],
        action=action,
        max_requests=max_requests,
        window_seconds=window_seconds
    )

# Cached machine learning classifier and forensic agent
@st.cache_resource
def load_ml_classifier():
    return MLClassifier()

ml_classifier = load_ml_classifier()
forensic_agent = AutonomousForensicAgent(ml_classifier)

# ─────────────────────────── Sidebar Branding & Auth ───────────────────────────
st.sidebar.markdown(
    """
    <div style="padding: 6px 0 14px 0; border-bottom: 1px solid #262626; margin-bottom: 14px;">
        <div style="font-size: 1.1rem; font-weight: 800; color: #ededed; letter-spacing: -0.02em;">
            🛡️ EMAILSHIELD <span style="color: #3b82f6; font-size: 0.8em; font-weight: 600;">INDIA</span>
        </div>
        <div style="font-size: 0.7rem; color: #666666; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 2px;">
            SOC • Email Threat Operations
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.sidebar.markdown("### 🔐 Investigator Access")

def clear_investigator_session():
    """Purge all user-specific and live mail session state upon logout or session expiry."""
    keys_to_purge = [
        "user_id", "user_email", "supabase_auth_token", "supabase_refresh_token",
        "mailbox_connected", "mailbox_creds", "mailbox_type", "recent_emails",
        "current_email_bytes", "batch_results", "_cached_analysis_payload",
        "active_investigation_id", "selected_live_mail_id", "selected_live_mail_ids",
        "current_live_mail_index", "live_mail_fetch_limit", "last_live_batch_mailbox_id",
        "live_unified_mailbox_switcher", "email_analysis_source", "batch_inspect_email_bytes",
        "batch_analysis_results", "batch_analysis_metrics", "_pending_close_case_id",
        "c_mb_pwd", "c_mb_email", "c_mb_prov", "c_mb_host", "c_mb_port", "c_mb_ssl", "c_mb_consent",
        "selected_live_mail_uid", "selected_live_mail_message_id", "selected_live_mail_index",
        "live_mail_analysis_status", "live_jump_num",
        "telegram_connected", "telegram_status", "telegram_destination", "telegram_bot_user",
        "whatsapp_connected", "whatsapp_status", "whatsapp_destination",
        "sentinel_tg_token", "sentinel_tg_destination", "sentinel_tg_target",
        "sentinel_tg_enabled", "sentinel_wa_apikey", "sentinel_wa_destination",
        "sentinel_wa_enabled", "_enc_tg_token", "_enc_tg_chat", "_enc_wa_phone",
        "_enc_wa_key"
    ]
    clear_alert_session(user_id=st.session_state.get("user_id"))
    clear_supabase_client_cache(st.session_state.get("supabase_auth_token"))
    for k in keys_to_purge:
        st.session_state.pop(k, None)
    for k in list(st.session_state.keys()):
        if k.startswith("chk_live_") or k.startswith("live_") or k.startswith("c_mb_"):
            st.session_state.pop(k, None)
    st.session_state.clear()

if is_supabase_configured():
    # Proactively check whether active JWT has expired
    active_jwt = st.session_state.get("supabase_auth_token")
    if active_jwt and is_jwt_expired(active_jwt):
        refreshed = False
        refresh_tok = st.session_state.get("supabase_refresh_token")
        if refresh_tok:
            ok_ref, ref_res = refresh_user_session(refresh_tok)
            if ok_ref and ref_res:
                st.session_state["supabase_auth_token"] = ref_res.access_token
                st.session_state["supabase_refresh_token"] = getattr(ref_res, "refresh_token", None)
                refreshed = True
        if not refreshed:
            clear_investigator_session()
            st.sidebar.warning("⚠️ Session expired. Please sign in again.")

    if "user_id" not in st.session_state or not st.session_state["user_id"]:
        auth_tab1, auth_tab2 = st.sidebar.tabs(["Sign In", "Register"])
        with auth_tab1:
            login_email = st.text_input("Email:", key="sb_login_email")
            login_pass = st.text_input("Password:", type="password", key="sb_login_pass")
            if st.button("Sign In", type="primary", key="btn_sb_login"):
                if login_email and login_pass:
                    ok, res = sign_in_user(login_email, login_pass)
                    if ok:
                        st.session_state["user_id"] = res.user.id
                        st.session_state["user_email"] = res.user.email
                        st.session_state["supabase_auth_token"] = res.access_token
                        st.session_state["supabase_refresh_token"] = getattr(res, "refresh_token", None)
                        st.success(f"Welcome, {res.user.email}!")
                        st.rerun()
                    else:
                        st.error(res)
                else:
                    st.warning("Please enter email and password.")
        with auth_tab2:
            reg_name = st.text_input("Investigator Name:", key="sb_reg_name")
            reg_email = st.text_input("Email:", key="sb_reg_email")
            reg_pass = st.text_input("Password:", type="password", key="sb_reg_pass")
            if st.button("Create Account", key="btn_sb_reg"):
                if reg_email and reg_pass:
                    ok, res = sign_up_user(reg_email, reg_pass, display_name=reg_name)
                    if ok:
                        if hasattr(res, "user"):
                            st.session_state["user_id"] = res.user.id
                            st.session_state["user_email"] = res.user.email
                            st.session_state["supabase_auth_token"] = res.access_token
                            st.session_state["supabase_refresh_token"] = getattr(res, "refresh_token", None)
                        st.success("Account created successfully!")
                        st.rerun()
                    else:
                        st.error(res)
                else:
                    st.warning("Please enter email and password.")
        st.sidebar.markdown("---")
    else:
        u_email = st.session_state.get("user_email", "Investigator")
        c_u1, c_u2 = st.sidebar.columns([3, 1])
        with c_u1:
            st.sidebar.markdown(f"👤 **Investigator:** `{u_email[:20]}`")
            st.sidebar.caption("🛡️ Private RLS workspace")
        with c_u2:
            if st.sidebar.button("Logout", key="btn_sb_logout", help="Sign out and purge session"):
                sign_out_user(st.session_state.get("supabase_auth_token"))
                clear_investigator_session()
                st.rerun()
        st.sidebar.markdown("---")
else:
    st.sidebar.caption("ℹ️ **Local Sandbox Mode** (No Supabase credentials configured)")
    if st.session_state.get("user_id"):
        u_email = st.session_state.get("user_email", "Investigator")
        c_u1, c_u2 = st.sidebar.columns([3, 1])
        with c_u1:
            st.sidebar.markdown(f"👤 **Investigator:** `{u_email[:20]}`")
            st.sidebar.caption("🛡️ Private workspace")
        with c_u2:
            if st.sidebar.button("Logout", key="btn_sb_logout_local", help="Sign out and purge session"):
                clear_investigator_session()
                st.rerun()
    st.sidebar.markdown("---")

user_client = get_supabase_client(st.session_state.get("supabase_auth_token")) if is_supabase_configured() and st.session_state.get("supabase_auth_token") else None
current_user_id = st.session_state.get("user_id")

# Quick connected mailbox badge in sidebar
if st.session_state.get("mailbox_connected", False):
    creds = st.session_state.get("mailbox_creds", {})
    disp_email = creds.get("email", "Mailbox")
    col_sb_m1, col_sb_m2 = st.sidebar.columns([3, 1])
    with col_sb_m1:
        st.sidebar.markdown(f"📬 `{disp_email[:18]}`")
    with col_sb_m2:
        if st.sidebar.button("✕", key="btn_sb_quick_disc", help="Disconnect ephemeral mailbox"):
            for k in ["mailbox_connected", "mailbox_creds", "mailbox_type", "recent_emails", "current_email_bytes", "batch_results"]:
                st.session_state.pop(k, None)
            st.rerun()
    st.sidebar.markdown("---")

# ─────────────────────────── View Module Mapping ───────────────────────────
from views import (
    dashboard,
    analyze,
    investigations,
    ioc_intel,
    reports,
    alerts,
    settings,
)

nav_options = [
    "🏠 Dashboard",
    "🔍 Analyze Email",
    "📁 Investigations",
    "🌐 Threat Intelligence",
    "📊 Reports",
    "📱 Alerts",
    "⚙️ Mailbox & Settings"
]

page_map = {
    "🏠 Dashboard": dashboard,
    "🔍 Analyze Email": analyze,
    "📁 Investigations": investigations,
    "🌐 Threat Intelligence": ioc_intel,
    "📊 Reports": reports,
    "📱 Alerts": alerts,
    "⚙️ Mailbox & Settings": settings,
}

current_idx = min(max(st.session_state.get("active_view_idx", 0), 0), len(nav_options) - 1)

selected_nav = st.sidebar.radio(
    "Console Navigation",
    options=nav_options,
    index=current_idx,
    key="sb_main_nav_radio"
)

# Keep active_view_idx in sync for programmatic navigation
for idx, opt in enumerate(nav_options):
    if opt == selected_nav:
        st.session_state["active_view_idx"] = idx
        break

# Route-aware context: query mailbox/worker/checkpoint only when target page needs them
mailbox_rec, worker_rec, checkpoint_rec = None, None, None
if current_user_id and user_client:
    is_live = selected_nav == "🔍 Analyze Email" and st.session_state.get("email_analysis_source") == "📬 Select from Live Mail"
    if selected_nav in ("🏠 Dashboard", "⚙️ Mailbox & Settings") or is_live:
        try: mailbox_rec = get_user_mailbox(current_user_id, user_client)
        except Exception: pass
    if selected_nav in ("🏠 Dashboard", "⚙️ Mailbox & Settings", "📱 Alerts"):
        try: worker_rec = get_user_worker(current_user_id, user_client)
        except Exception: pass
    if selected_nav in ("🏠 Dashboard", "⚙️ Mailbox & Settings"):
        try: checkpoint_rec = get_user_checkpoint(current_user_id, user_client)
        except Exception: pass

# Context dictionary passed to active page
page_ctx = {
    "forensic_agent": forensic_agent,
    "ml_classifier": ml_classifier,
    "mailbox_rec": mailbox_rec,
    "worker_rec": worker_rec,
    "checkpoint_rec": checkpoint_rec,
    "check_rate_limit": check_rate_limit
}

# Render selected page module
selected_page = page_map.get(selected_nav, dashboard)
selected_page.render(current_user_id, user_client, **page_ctx)
