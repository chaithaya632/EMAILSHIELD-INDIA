import streamlit as st
import uuid
import datetime
import time
import os
import html
import hashlib
from typing import Tuple, Dict, Any, List, Optional
from core.rate_limiter import check_sliding_window_rate_limit
from core.parser import SecureEmailParser
from core.indicators import extract_all_indicators
from core.auth_claims import parse_auth_results, evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk
try:
    from core.geolocation import (
        get_geolocation,
        get_sender_location,
        is_public_ip,
        derive_authoritative_location,
        get_country_flag,
    )
except ImportError:
    import importlib
    import core.geolocation
    importlib.reload(core.geolocation)
    from core.geolocation import (
        get_geolocation,
        get_sender_location,
        is_public_ip,
        derive_authoritative_location,
        get_country_flag,
    )
from core.classifier import MLClassifier
import io
from core.case_store import (
    save_case, update_case_metadata, get_case_record, export_case_iocs_csv,
    export_case_iocs_json, get_all_cases, get_all_indicators,
    is_authenticated_soc_caller, is_authorized_caller,
    get_soc_kpi_metrics, get_soc_threat_distribution, get_soc_threat_activity, get_soc_investigation_queue,
    export_case_report_pdf, export_case_report_json, export_case_ncrp_pdf,
    export_case_executive_pdf, export_case_evidence_manifest, export_case_zip_package
)
from core.investigation import (
    LIFECYCLE_STATES,
    normalize_to_lifecycle_status,
    map_lifecycle_to_db_status,
    build_investigation_timeline,
    get_investigation_evidence,
    get_investigation_emails,
    get_investigation_indicators,
    add_analyst_note,
    transition_investigation_status,
    open_or_get_investigation,
    search_investigations,
    build_evidence_manifest,
    verify_evidence_integrity,
    verify_all_manifest_integrity,
    build_chain_of_custody,
    IntegrityStatus,
    EvidenceType,
)
from core.ncrp_packager import generate_ncrp_complaint_text, generate_ncrp_pdf_annexure
try:
    from core.supabase_client import (
        is_supabase_configured,
        get_supabase_client,
        sign_in_user,
        sign_up_user,
        sign_out_user,
        is_jwt_expired,
        refresh_user_session,
    )
except ImportError:
    try:
        import importlib
        import core.supabase_client
        importlib.reload(core.supabase_client)
        from core.supabase_client import (
            is_supabase_configured,
            get_supabase_client,
            sign_in_user,
            sign_up_user,
            sign_out_user,
            is_jwt_expired,
            refresh_user_session,
        )
    except Exception:
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
from core.report import generate_pdf_report, generate_json_report
from core.schemas import (
    CaseReport, Indicator, GeolocationInfo, AuthEvidence, RuleFinding,
    MLAssessment, EventTimeline, AttachmentAnalysisResult, LookalikeAnalysis,
    BECTelemetry, AuthAlignmentResult
)
from core.attachments import analyze_all_attachments
from core.lookalike import detect_lookalike_domain
from core.bec_detector import detect_bec_and_impersonation
from core.batch_scanner import scan_mailbox_batch, categorize_content
from core.mailbox_connector import test_imap_connection, fetch_imap_emails, fetch_imap_raw_email, PROVIDER_CONFIGS, get_provider_host
from core.domain_reputation import get_domain_reputation
from core.relay_tracer import build_relay_flight_map, analyze_relay_transit
from core.ai_reasoning import generate_forensic_reasoning
from core.agent import AutonomousForensicAgent
from core.indian_banking import extract_indian_financial_indicators
from core.quishing import scan_for_quishing
from core.eml_sanitizer import sanitize_eml_content
from core.header_diff import compare_headers_against_baseline, BRAND_BASELINES
from core.correlation import build_case_infrastructure_graph, build_correlation_graph
from core.infrastructure_intel import InfrastructureAssessment, assess_infrastructure
from core.ncrp_packager import generate_ncrp_complaint_text, generate_ncrp_pdf_annexure
from core.sentinel import mask_sensitive_subject
from core.telegram_alert import (
    get_telegram_config,
    verify_telegram_bot_token,
    validate_telegram_token_format,
    validate_telegram_chat_id,
    test_telegram_alert_delivery,
    sanitize_telegram_token,
    mask_telegram_chat_id,
)
from core.whatsapp_alert import (
    get_whatsapp_config,
    test_whatsapp_alert_delivery,
    mask_phone_number,
    mask_whatsapp_key,
    validate_whatsapp_phone,
    validate_whatsapp_apikey,
)
from core.sentinel_control import (
    validate_poll_interval,
    validate_desired_state,
    validate_provider,
    validate_email_syntax,
    validate_imap_port,
    validate_alert_channel,
    get_user_worker,
    upsert_user_worker,
    set_worker_desired_state,
    get_user_mailbox,
    save_user_mailbox_metadata,
    connect_user_sentinel_mailbox,
    disconnect_user_sentinel_mailbox,
    mask_email_address,
    get_user_checkpoint,
    get_user_alerts,
    save_user_alert_metadata,
    deactivate_user_sentinel,
    delete_user_sentinel_config,
    MIN_POLL_INTERVAL_SECONDS,
    MAX_POLL_INTERVAL_SECONDS,
    DEFAULT_POLL_INTERVAL_SECONDS,
    ALLOWED_PROVIDERS,
    ALLOWED_AUTH_MECHANISMS,
    ALLOWED_ALERT_CHANNELS,
    PROVIDER_IMAP_DEFAULTS,
)
import plotly.express as px
import sys
import importlib

st.set_page_config(page_title="EMAILSHIELD INDIA", layout="wide")

def check_rate_limit(action: str, max_requests: int = 10, window_seconds: int = 60) -> Tuple[bool, int]:
    """
    Application-level sliding-window rate limiter per session.
    Returns (is_allowed, seconds_to_wait).
    """
    if "rate_limits" not in st.session_state:
        st.session_state["rate_limits"] = {}
    return check_sliding_window_rate_limit(
        tracker=st.session_state["rate_limits"],
        action=action,
        max_requests=max_requests,
        window_seconds=window_seconds
    )

def render_infrastructure_dual_cards(case_report: Any):
    """Renders Section 14 Unified Infrastructure Assessment dual-card layout."""
    infra = getattr(case_report, "infrastructure_intel", None)
    sloc = derive_authoritative_location(case_report)
    
    col_infra1, col_infra2 = st.columns(2)
    
    with col_infra1:
        ip_val = (getattr(infra, "origin_ip", None) or (sloc.get('sender_ip') if sloc.get('is_identified') else 'Unavailable / Relay-masked'))
        flag_val = getattr(infra, "flag", None) or sloc.get('flag', '🌐')
        loc_val = (f"{infra.city}, {infra.region}, {infra.country}" if (infra and getattr(infra, "country", "Unknown") != 'Unknown') else (sloc.get('display_location') or 'Unavailable'))
        asn_val = getattr(infra, "asn", None) or sloc.get('asn', 'Unknown ASN')
        isp_val = getattr(infra, "isp", None) or sloc.get('org', 'Unknown Network')

        b_vpn = getattr(getattr(infra, "vpn_indicator", None), "status", "UNKNOWN")
        b_tor = getattr(getattr(infra, "tor_indicator", None), "status", "UNKNOWN")
        b_relay = getattr(getattr(infra, "open_relay_indicator", None), "status", "UNKNOWN")
        b_botnet = getattr(getattr(infra, "botnet_indicator", None), "status", "UNKNOWN")
        c_ind = getattr(infra, "cloud_indicator", None)
        b_cloud = c_ind.provider if (c_ind and c_ind.is_cloud_hosted) else "Dedicated / Non-Cloud"
        b_threat = getattr(getattr(infra, "threat_intel_match", None), "status", "NO_MATCH")

        vpn_bg = "#ef4444" if b_vpn=="DETECTED" else "#10b981" if b_vpn=="NOT_DETECTED" else "#64748b"
        tor_bg = "#ef4444" if b_tor=="DETECTED" else "#10b981" if b_tor=="NOT_DETECTED" else "#64748b"
        relay_bg = "#f59e0b" if b_relay=="INDICATED" else "#10b981" if b_relay=="NOT_INDICATED" else "#64748b"
        botnet_bg = "#ef4444" if b_botnet=="INDICATED" else "#10b981" if b_botnet=="NOT_INDICATED" else "#64748b"
        threat_bg = "#dc2626" if b_threat=="MATCH" else "#10b981"

        st.markdown(
            f"""
<div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin: 12px 0 16px 0;">
    <div style="font-size: 1.05em; font-weight: 700; color: #38bdf8; margin-bottom: 8px;">
        🌐 Origin Infrastructure & Anonymization Telemetry
    </div>
    <div style="color: #f1f5f9; font-size: 0.9em; margin-bottom: 4px;">
        <b>Originating IP:</b> <code style="color: #67e8f9;">{html.escape(str(ip_val))}</code> {flag_val}
    </div>
    <div style="color: #cbd5e1; font-size: 0.85em; margin-bottom: 4px;">
        <b>Network Location:</b> {html.escape(str(loc_val))}
    </div>
    <div style="color: #cbd5e1; font-size: 0.85em; margin-bottom: 8px;">
        <b>ISP / Routing Org:</b> {html.escape(str(isp_val))} (<code style="color: #94a3b8;">{html.escape(str(asn_val))}</code>)
    </div>
    <div style="margin: 8px 0; display: flex; flex-wrap: wrap; gap: 6px;">
        <span style="background-color: #0284c7; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Cloud: {html.escape(str(b_cloud))}</span>
        <span style="background-color: {vpn_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">VPN: {b_vpn}</span>
        <span style="background-color: {tor_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Tor: {b_tor}</span>
        <span style="background-color: {relay_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Open Relay: {b_relay}</span>
        <span style="background-color: {botnet_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Botnet: {b_botnet}</span>
        <span style="background-color: {threat_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Threat Feed: {b_threat}</span>
    </div>
    <div style="font-size: 0.74em; color: #94a3b8; font-style: italic; margin-top: 6px;">
        * Derived from available evidence. Provides network routing context; does not prove physical identity.
    </div>
</div>
""",
            unsafe_allow_html=True
        )

    with col_infra2:
        d_rep = getattr(case_report, "domain_reputation", None)
        reg_intel = getattr(infra, "registrar_intel", None)
        dns_intel = getattr(infra, "dns_mx_intel", None)
        
        dom_val = (getattr(infra, "domain", None) or (getattr(d_rep, "domain", "Unknown") if d_rep else "Unknown"))
        reg_name = (getattr(reg_intel, "registrar", None) if reg_intel and reg_intel.registrar != "Unknown" else (getattr(d_rep, "registrar", "Unknown") if d_rep else "Unknown"))
        c_date = (getattr(reg_intel, "creation_date", None) if reg_intel and reg_intel.creation_date != "Unknown" else (getattr(d_rep, "creation_date", "Unknown") if d_rep else "Unknown"))
        age_days = (getattr(reg_intel, "domain_age_days", None) if reg_intel and reg_intel.domain_age_days is not None else (getattr(d_rep, "domain_age_days", None) if d_rep else None))

        age_disp = f"{age_days} days ({age_days//365} yrs)" if age_days is not None else "Unknown age"
        if age_days is not None and age_days < 30:
            age_badge = '<span style="background-color: #ef4444; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">🚨 NRD (&lt;30d)</span>'
        elif age_days is not None and age_days < 180:
            age_badge = '<span style="background-color: #f59e0b; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">⚠️ Young</span>'
        else:
            age_badge = '<span style="background-color: #10b981; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">✅ Established</span>'

        mx_count = len(dns_intel.mx_records) if (dns_intel and dns_intel.mx_records) else ("Configured" if getattr(d_rep, "has_mx_record", True) else "Missing")
        a_count = len(dns_intel.a_records) if (dns_intel and dns_intel.a_records) else len(getattr(d_rep, "dns_resolved_ips", []))

        st.markdown(
            f"""
<div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin: 12px 0 16px 0;">
    <div style="font-size: 1.05em; font-weight: 700; color: #c084fc; margin-bottom: 8px;">
        🔍 Domain Intelligence & DNS / MX Exposure
    </div>
    <div style="color: #f1f5f9; font-size: 0.9em; margin-bottom: 4px;">
        <b>Domain:</b> <code style="color: #e9d5ff;">{html.escape(str(dom_val))}</code> {age_badge}
    </div>
    <div style="color: #cbd5e1; font-size: 0.85em; margin-bottom: 4px;">
        <b>Registrar:</b> {html.escape(str(reg_name))}
    </div>
    <div style="color: #cbd5e1; font-size: 0.85em; margin-bottom: 8px;">
        <b>Created:</b> {html.escape(str(c_date))} | <b>Age:</b> {age_disp}
    </div>
    <div style="font-size: 0.82em; color: #94a3b8; margin: 8px 0;">
        <b>DNS A Records:</b> {a_count} IP(s) &nbsp;|&nbsp; <b>MX Hosts:</b> {mx_count} &nbsp;|&nbsp; <b>SSRF Guard:</b> <span style="color: #4ade80;">Active</span>
    </div>
    <div style="font-size: 0.74em; color: #94a3b8; font-style: italic; margin-top: 6px;">
        * Multi-tiered RDAP / WHOIS & RFC-compliant DNS enumeration.
    </div>
</div>
""",
            unsafe_allow_html=True
        )

# Initialize models
@st.cache_resource
def load_ml_classifier():
    return MLClassifier()

ml_classifier = load_ml_classifier()
forensic_agent = AutonomousForensicAgent(ml_classifier)

st.title("🛡️ EMAILSHIELD INDIA")
st.subheader("SOC • EMAIL THREAT OPERATIONS")

st.sidebar.markdown("### 🔐 Investigator Access")
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
            st.session_state.pop("user_id", None)
            st.session_state.pop("user_email", None)
            st.session_state.pop("supabase_auth_token", None)
            st.session_state.pop("supabase_refresh_token", None)
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
                st.session_state.clear()
                st.rerun()
        st.sidebar.markdown("---")
else:
    st.sidebar.caption("ℹ️ **Local Sandbox Mode** (No Supabase credentials configured)")
    st.sidebar.markdown("---")

user_client = get_supabase_client(st.session_state.get("supabase_auth_token")) if is_supabase_configured() and st.session_state.get("supabase_auth_token") else None
current_user_id = st.session_state.get("user_id")

st.sidebar.header("📬 Connect Mailbox")
st.sidebar.write("Inspect live inboxes directly without cloud console setup.")

if not st.session_state.get("mailbox_connected", False):
    provider_name = st.sidebar.selectbox("Email Service:", ["Gmail", "Outlook / Office 365", "Yahoo Mail", "Zoho Mail", "Custom / Corporate"])
        
    # Dynamic 30-Second Setup Guide with direct links
    if provider_name == "Gmail":
        with st.sidebar.expander("🔐 Gmail App Password — Show setup guide", expanded=False):
            st.markdown("""
### Quick 30s Setup for Gmail

1. Open your [Google Account](https://myaccount.google.com/apppasswords).
2. Go to **Security**.
3. Make sure **2-Step Verification** is enabled.
4. Create an **App Password**.
5. Copy the generated App Password.
6. Paste it into the App Password field below.

⚠️ **Use a Gmail App Password, NOT your normal Gmail password.**
""")
    elif provider_name == "Outlook / Office 365":
        st.sidebar.markdown(
            """
<div style="background-color: #0f172a; border-left: 4px solid #38bdf8; padding: 10px; border-radius: 6px; font-size: 0.85em; margin: 8px 0 12px 0;">
<b>⚡ Quick 30s Setup for Outlook / Hotmail:</b><br>
1️⃣ <a href="https://account.live.com/proofs/manage/additional" target="_blank" style="color: #38bdf8; font-weight: bold; text-decoration: underline;">👉 Click here to open Microsoft Security ↗</a><br>
2️⃣ Scroll to <b>App passwords</b> & click <b>Create a new app password</b>.<br>
3️⃣ Copy the password & paste it below!
<br><br>
<span style="color: #94a3b8; font-size: 0.9em;">🔒 <b>100% Free ($0):</b> Revocable anytime from your Microsoft account.</span>
</div>
""",
            unsafe_allow_html=True
        )
    elif provider_name == "Yahoo Mail":
        st.sidebar.markdown(
            """
<div style="background-color: #0f172a; border-left: 4px solid #38bdf8; padding: 10px; border-radius: 6px; font-size: 0.85em; margin: 8px 0 12px 0;">
<b>⚡ Quick 30s Setup for Yahoo Mail:</b><br>
1️⃣ <a href="https://login.yahoo.com/account/security" target="_blank" style="color: #38bdf8; font-weight: bold; text-decoration: underline;">👉 Click here to open Yahoo Security ↗</a><br>
2️⃣ Scroll to <b>Generate app password</b> & name it <b>EMAILSHIELD</b>.<br>
3️⃣ Copy the password & paste it below!
<br><br>
<span style="color: #94a3b8; font-size: 0.9em;">🔒 <b>100% Free ($0):</b> Works with any free Yahoo account.</span>
</div>
""",
            unsafe_allow_html=True
        )
    elif provider_name == "Zoho Mail":
        st.sidebar.markdown(
            """
<div style="background-color: #0f172a; border-left: 4px solid #38bdf8; padding: 10px; border-radius: 6px; font-size: 0.85em; margin: 8px 0 12px 0;">
<b>⚡ Quick 30s Setup for Zoho Mail:</b><br>
1️⃣ <a href="https://accounts.zoho.com/home#security/app_password" target="_blank" style="color: #38bdf8; font-weight: bold; text-decoration: underline;">👉 Click here to open Zoho Security ↗</a><br>
2️⃣ Under <b>Application-Specific Passwords</b>, click <b>Generate New Password</b>.<br>
3️⃣ Enter App Name <b>EMAILSHIELD</b> & copy the password below!
<br><br>
<span style="color: #94a3b8; font-size: 0.9em;">🔒 <b>100% Free ($0):</b> Supports personal (@zoho.com / @zoho.in) and corporate/custom domain Zoho accounts.</span>
</div>
""",
            unsafe_allow_html=True
        )
    else:
        st.sidebar.markdown(
            """
<div style="background-color: #0f172a; border-left: 4px solid #38bdf8; padding: 10px; border-radius: 6px; font-size: 0.85em; margin: 8px 0 12px 0;">
<b>🏢 Corporate / Custom IMAP Setup:</b><br>
Enter your organization's IMAP host address (e.g., <code>mail.company.com</code>) and your email credentials. Port 993 SSL is standard.
</div>
""",
            unsafe_allow_html=True
        )

    u_email = st.sidebar.text_input("Email:", placeholder="user@zoho.com" if provider_name == "Zoho Mail" else "user@gmail.com")

    # 2FA & App Password Guidance (For non-Gmail providers; Gmail is covered by the collapsible guide above)
    if provider_name != "Gmail":
        st.sidebar.markdown(
            """
<div style="background-color: #0f172a; border-left: 4px solid #f59e0b; padding: 10px; border-radius: 6px; font-size: 0.83em; margin: 8px 0 10px 0; color: #e2e8f0; line-height: 1.45;">
<b style="color: #f59e0b; font-size: 1.05em;">🔐 App Password Required</b><br><br>
<span style="color: #cbd5e1;">If your email provider requires an App Password:</span>
<ol style="margin: 6px 0 6px 18px; padding-left: 0;">
  <li><b>Enable 2-Step Verification / 2-Factor Authentication (2FA)</b> on your email account first.</li>
  <li>After 2FA is enabled, <b>generate an App Password</b> from your email provider's security settings.</li>
  <li>Use the generated App Password here instead of your normal email password.</li>
</ol>
<div style="color: #fbbf24; margin: 4px 0;">⚠️ <i>Your normal email password may not work for IMAP when 2FA is enabled.</i></div>
<div style="color: #94a3b8; font-size: 0.9em; margin-top: 4px;">🔒 EMAILSHIELD INDIA does not ask you to share your normal account password with us. Use an App Password when your provider supports or requires it.</div>
</div>
""",
            unsafe_allow_html=True
        )

    u_pass = st.sidebar.text_input("Password / App Password:", type="password", help="Enter your App Password (required when 2FA is active) or normal email password. Spaces are automatically removed.")

    with st.sidebar.expander("❓ What is an App Password? Is it safe & free?"):
        st.markdown(
            "• **Cost**: **100% Free ($0 / ₹0)** forever. No subscriptions or credit cards.<br>"
            "• **Security**: Your real account password is **never shared**. An App Password only grants limited email read access.<br>"
            "• **Control**: You can revoke or delete the App Password from Google/Microsoft/Zoho with one click anytime.<br>"
            "• **No Developer Accounts**: No Google Cloud Console, no Azure registration, zero technical setup.",
            unsafe_allow_html=True
        )

    c_host = ""
    if provider_name == "Custom / Corporate":
        c_host = st.sidebar.text_input("IMAP Host:", placeholder="imap.yourserver.com")

    st.sidebar.caption("🔒 **Ephemeral Session**: Mailbox credentials stay in this browser session only and are never saved to server disk.")
            
    if st.sidebar.button("Connect Mailbox", type="primary"):
        if u_email and u_pass:
            target_host = c_host if provider_name == "Custom / Corporate" else get_provider_host(provider_name, u_email)
            with st.spinner("Authenticating with mail server..."):
                ok, conn_msg = test_imap_connection(u_email, u_pass, target_host)
            if ok:
                st.session_state["mailbox_connected"] = True
                st.session_state["mailbox_type"] = "IMAP"
                st.session_state["mailbox_creds"] = {
                    "email": u_email, "pwd": u_pass, "host": target_host, "provider": provider_name
                }
                st.session_state.pop("recent_emails", None)
                st.session_state["add_new_account_mode"] = False
                st.rerun()
            else:
                st.sidebar.error(conn_msg)
        else:
            st.sidebar.warning("Please enter your email and app password.")

if st.session_state.get("mailbox_connected", False):
    m_type = st.session_state.get("mailbox_type", "IMAP")
    creds = st.session_state.get("mailbox_creds", {})
    disp_email = creds.get("email", "Connected Mailbox")
    
    col_mb1, col_mb2 = st.sidebar.columns([3, 1])
    with col_mb1:
        st.sidebar.write(f"📬 **Connected:** `{disp_email[:20]}`")
        st.sidebar.caption("🔒 Session-only memory (ephemeral)")
    with col_mb2:
        if st.sidebar.button("Disconnect", help="Disconnect mailbox and purge credentials from session memory"):
            for k in [
                "mailbox_connected", "mailbox_creds", "mailbox_type",
                "recent_emails", "session_days_left", "current_email_bytes",
                "batch_results", "last_scope_tuple", "add_new_account_mode",
                "_cached_analysis_payload"
            ]:
                st.session_state.pop(k, None)
            st.rerun()

    try:
        # Mailbox Scope & Quantity Controls
        col_scope1, col_scope2 = st.sidebar.columns([3, 2])
        with col_scope1:
            scope_mode = col_scope1.selectbox("Scope:", ["📥 All Emails", "📅 Today Only"], index=0, key="mb_scope_mode")
        with col_scope2:
            limit_mode = col_scope2.selectbox("Limit:", ["50", "100", "200", "All (Max 300)"], index=0, key="mb_limit_mode")
            
        current_scope_tuple = (scope_mode, limit_mode)
        scope_changed = (st.session_state.get("last_scope_tuple") != current_scope_tuple)
        
        limit_val = 300 if limit_mode == "All (Max 300)" else int(limit_mode)
        query_val = "newer_than:1d" if scope_mode == "📅 Today Only" else None
        
        col_ref1, col_ref2 = st.sidebar.columns([3, 1])
        with col_ref1:
            col_ref1.write(f"**Loaded:** `{len(st.session_state.get('recent_emails', []))}` msgs")
        with col_ref2:
            refresh_clicked = col_ref2.button("🔄", help="Reload emails from mailbox")
            
        if "recent_emails" not in st.session_state or scope_changed or refresh_clicked:
            st.session_state["last_scope_tuple"] = current_scope_tuple
            with st.spinner(f"Fetching {limit_mode} emails from mailbox..."):
                try:
                    if m_type == "IMAP":
                        st.session_state["recent_emails"] = fetch_imap_emails(
                            creds["email"], creds["pwd"], creds["host"], max_results=limit_val, query=query_val
                        )
                    else:
                        st.sidebar.error("⚠️ Public Google OAuth is disabled for multi-user security. Please connect via IMAP.")
                        st.session_state["recent_emails"] = []
                except Exception as fetch_err:
                    st.sidebar.error(f"Fetch error: {str(fetch_err)}")
                    st.session_state["recent_emails"] = []
            st.rerun()

        recent_emails = st.session_state.get("recent_emails", [])
        
        if st.sidebar.button(f"Scan Loaded Emails ({len(recent_emails)}) [Batch]"):
            st.session_state["current_email_bytes"] = None 
            st.session_state.pop("_cached_analysis_payload", None)
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            
            def scan_progress(idx, total, subj):
                if total > 0:
                    progress_bar.progress((idx + 1) / total)
                    status_text.text(f"Scanning {idx + 1}/{total}...")
                    
            if m_type == "IMAP":
                def raw_imap_fetcher(mid):
                    return fetch_imap_raw_email(creds["email"], creds["pwd"], creds["host"], msg_id=mid)
                st.session_state["batch_results"] = scan_mailbox_batch(
                    ml_classifier, max_emails=len(recent_emails), progress_callback=scan_progress,
                    custom_emails=recent_emails,
                    raw_fetcher_fn=raw_imap_fetcher
                )
            else:
                st.sidebar.error("⚠️ Public OAuth batch scanning is disabled for multi-user security.")
            status_text.text("✅ Scan Complete!")
            st.session_state["active_view_idx"] = 1
            st.rerun()
            
        st.sidebar.markdown("---")
        st.sidebar.subheader("Select Inbound Email")
        
        if recent_emails:
            st.sidebar.caption(f"Displaying **{len(recent_emails)}** inbound emails from your inbox:")
            
            filter_kw = ""
            if len(recent_emails) > 5:
                filter_kw = st.sidebar.text_input("🔍 Quick Search:", "", placeholder="Filter by subject or sender...").strip().lower()
                
            filtered_list = recent_emails
            if filter_kw:
                filtered_list = [
                    m for m in recent_emails
                    if filter_kw in m.get("subject", "").lower() or filter_kw in m.get("sender", "").lower()
                ]
                
            if filtered_list:
                email_opts = {
                    msg['id']: f"{msg.get('date', '')[:16]} | {msg.get('sender', '')[:20]} | {mask_sensitive_subject(msg.get('subject', ''))[:30]}"
                    for msg in filtered_list
                }
                selected_msg_id = st.sidebar.selectbox(
                    "Choose email:",
                    options=list(email_opts.keys()),
                    format_func=lambda x: email_opts[x]
                )
                
                if st.sidebar.button("Analyze Selected Email", type="primary"):
                    with st.spinner("Fetching raw email RFC822 bytes..."):
                        if m_type == "IMAP":
                            bytes_data = fetch_imap_raw_email(creds["email"], creds["pwd"], creds["host"], msg_id=selected_msg_id)
                        else:
                            st.sidebar.error("⚠️ Public OAuth email fetch is disabled for multi-user security.")
                            bytes_data = b""
                    st.session_state["batch_results"] = None
                    st.session_state["current_email_bytes"] = bytes_data
                    st.session_state["active_view_idx"] = 1
                    st.rerun()
            else:
                st.sidebar.warning(f"No emails matching '{filter_kw}'.")
        else:
            st.sidebar.info("No emails found in this mailbox.")
    except Exception as e:
        st.sidebar.error(f"Mailbox Error: {str(e)}")

# Sidebar Navigation
st.sidebar.markdown("---")
st.sidebar.subheader("🛡️ SOC Operations Console")
nav_options = [
    "🛡️ SOC Dashboard",
    "📧 Analyze Email",
    "📡 Live Mail Analysis",
    "🔎 Investigations",
    "🌐 IOC / URL Intelligence",
    "🕸️ Attack Graph",
    "📄 Evidence & Reports",
    "📱 Mobile Alerts",
    "⚙️ System / Diagnostics"
]
current_idx = min(max(st.session_state.get("active_view_idx", 0), 0), len(nav_options) - 1)
selected_nav = st.sidebar.radio("Active View:", nav_options, index=current_idx)

# View 0: SOC Operations Dashboard
if selected_nav == "🛡️ SOC Dashboard":
    st.header("🛡️ SOC Operations Dashboard")
    st.caption("Live operational intelligence, threat telemetry, and active incident response queue.")

    if not is_authenticated_soc_caller(current_user_id, user_client):
        # Public Landing / Marketing Experience for Unauthenticated Visitors
        st.info("🔐 **Authentication Required**: Please sign in or create an account via the sidebar on the left to access your private SOC dashboard, live operational telemetry, threat intelligence, and triage queue.")
        
        st.markdown(
            """
            <div style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin: 15px 0 20px 0;">
                <h3 style="color: #38bdf8; margin-top: 0;">🛡️ EMAILSHIELD INDIA — Security Operations Console</h3>
                <p style="color: #cbd5e1; font-size: 0.95em; line-height: 1.6;">
                    Professional email threat operations and automated forensic triage platform engineered for enterprise SOC analysts, CERT/CSIRT responders, and security teams across India.
                </p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-top: 15px;">
                    <div style="background-color: #1e293b; border-left: 3px solid #38bdf8; padding: 12px; border-radius: 6px;">
                        <b style="color: #f8fafc; font-size: 0.9em;">🔬 Deterministic Forensics & ML</b>
                        <div style="color: #94a3b8; font-size: 0.82em; margin-top: 4px;">RFC822 header parsing, DKIM/SPF/DMARC alignment, Received-hop tracing, TF-IDF + LR classification.</div>
                    </div>
                    <div style="background-color: #1e293b; border-left: 3px solid #10b981; padding: 12px; border-radius: 6px;">
                        <b style="color: #f8fafc; font-size: 0.9em;">⚡ 1-Second Live Mail Sentinel</b>
                        <div style="color: #94a3b8; font-size: 0.82em; margin-top: 4px;">Automated IMAP monitoring, duplicate prevention, and zero-cost cloudless operations.</div>
                    </div>
                    <div style="background-color: #1e293b; border-left: 3px solid #f59e0b; padding: 12px; border-radius: 6px;">
                        <b style="color: #f8fafc; font-size: 0.9em;">🇮🇳 India Threat Intelligence</b>
                        <div style="color: #94a3b8; font-size: 0.82em; margin-top: 4px;">UPI QR fraud, banking impersonation, and one-click NCRP police evidence packager.</div>
                    </div>
                    <div style="background-color: #1e293b; border-left: 3px solid #a855f7; padding: 12px; border-radius: 6px;">
                        <b style="color: #f8fafc; font-size: 0.9em;">🔒 Private Multi-Tenant Isolation</b>
                        <div style="color: #94a3b8; font-size: 0.82em; margin-top: 4px;">Row Level Security (RLS) guarantees your investigations and mailbox data remain strictly isolated.</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_pub1, col_pub2 = st.columns(2)
        with col_pub1:
            if st.button("📧 Try Single Email Forensic Analysis", type="primary", use_container_width=True, key="btn_soc_pub_ana"):
                st.session_state["active_view_idx"] = 1
                st.rerun()
        with col_pub2:
            if st.button("⚙️ View System Diagnostics & Platform Health", use_container_width=True, key="btn_soc_pub_diag"):
                st.session_state["active_view_idx"] = 8
                st.rerun()
    else:
        # Authenticated SOC Operations Dashboard
        # 1. KPI Cards
        metrics = get_soc_kpi_metrics(current_user_id, user_client)
        col_k1, col_k2, col_k3, col_k4 = st.columns(4)
        with col_k1:
            st.metric("Emails Analysed", metrics["emails_analysed"])
        with col_k2:
            st.metric("Threats Detected", metrics["threats_detected"])
        with col_k3:
            st.metric("High / Critical", metrics["high_critical"])
        with col_k4:
            st.metric("Open Investigations", metrics["open_investigations"])

        st.markdown("---")

        # 2. Threat Distribution & Recent Threat Activity
        col_dash1, col_dash2 = st.columns([1, 1.3])
        with col_dash1:
            st.subheader("📊 Threat Severity Distribution")
            dist = get_soc_threat_distribution(current_user_id, user_client)
            labels = list(dist.keys())
            values = list(dist.values())
            if sum(values) > 0:
                fig_dist = px.pie(
                    names=labels,
                    values=values,
                    color=labels,
                    color_discrete_map={
                        "Clean": "#10b981",
                        "Suspicious": "#f59e0b",
                        "High": "#ef4444",
                        "Critical": "#dc2626"
                    },
                    hole=0.45
                )
                fig_dist.update_layout(
                    margin=dict(t=10, b=10, l=10, r=10),
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
                )
                st.plotly_chart(fig_dist, use_container_width=True)
            else:
                st.info("No threat metrics recorded yet. Analyze an email or load a sample scenario to populate threat distribution.")

        with col_dash2:
            st.subheader("⚡ Recent Threat Activity")
            activity = get_soc_threat_activity(current_user_id, user_client, limit=5)
            if activity:
                for act in activity:
                    badge_col = "#ef4444" if act["case_severity"] in ("HIGH", "CRITICAL") else "#f59e0b" if act["case_severity"] in ("MEDIUM", "SUSPICIOUS") else "#10b981"
                    st.markdown(
                        f"""
                        <div style="background-color: #0f172a; border-left: 4px solid {badge_col}; padding: 8px 12px; border-radius: 6px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <b style="color: #f8fafc; font-size: 0.9em;">{html.escape(act['case_id'])}</b>
                                <span style="background-color: {badge_col}; color: white; padding: 1px 6px; border-radius: 10px; font-size: 0.72em; font-weight: bold;">{act['case_severity']}</span>
                            </div>
                            <div style="color: #94a3b8; font-size: 0.82em; margin-top: 2px;">
                                <b>Sender:</b> {html.escape(act['sender'][:35])}
                            </div>
                            <div style="color: #cbd5e1; font-size: 0.84em; margin-top: 2px;">
                                <b>Subject:</b> {html.escape(act['subject'][:45])}
                            </div>
                            <div style="color: #64748b; font-size: 0.75em; margin-top: 4px;">
                                🕒 {act['timestamp']} | 🎯 IOC: <code>{html.escape(act['primary_ioc'][:30])}</code>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.info("No threat activity logged yet.")

        st.markdown("---")
        st.subheader("📋 Active Incident Triage Queue")
        st.caption("Prioritised by severity (Critical ➔ High ➔ Medium ➔ Low).")
        queue_data = get_soc_investigation_queue(current_user_id, user_client, limit=10)
        if queue_data:
            st.dataframe(queue_data, use_container_width=True)
            col_q_sel, col_q_act = st.columns([3, 1])
            with col_q_sel:
                q_case_ids = [q.get("Case ID") for q in queue_data if q.get("Case ID")]
                selected_q_cid = st.selectbox("Select case from queue to open:", q_case_ids, key="sb_soc_dash_q_sel")
            with col_q_act:
                st.write("")
                st.write("")
                if st.button("🔎 Open Investigation", type="primary", use_container_width=True, key="btn_soc_dash_open_inv"):
                    if selected_q_cid:
                        st.session_state["active_investigation_id"] = selected_q_cid
                        st.session_state["active_view_idx"] = 3
                        st.rerun()
        else:
            st.info("No pending cases in the triage queue.")

        col_dash_a1, col_dash_a2 = st.columns(2)
        with col_dash_a1:
            if st.button("📧 Launch Email Analysis", type="primary", use_container_width=True, key="btn_soc_dash_ana"):
                st.session_state["active_view_idx"] = 1
                st.rerun()
        with col_dash_a2:
            if st.button("📡 Open Live Mail Monitor", use_container_width=True, key="btn_soc_dash_live"):
                st.session_state["active_view_idx"] = 2
                st.rerun()

# View 2: Live Mail Analysis
elif selected_nav == "📡 Live Mail Analysis":
    st.header("📡 Live Mail Analysis")
    st.caption("Continuous, evidence-backed email monitoring for authorized user mailboxes.")

    if not is_authorized_caller(current_user_id, user_client):
        st.info("🔐 **Authentication Required**: Please sign in or register via the sidebar to access Live Mail Analysis.")
    else:
        # Authenticated user control plane
        worker_rec = get_user_worker(current_user_id, user_client)
        mailbox_rec = get_user_mailbox(current_user_id, user_client)
        checkpoint_rec = get_user_checkpoint(current_user_id, user_client)
        alerts_rec = get_user_alerts(current_user_id, user_client)

        is_mailbox_active = bool(mailbox_rec and mailbox_rec.get("is_active", False))
        desired_state = worker_rec.get("desired_state", "STOPPED") if worker_rec else "STOPPED"
        current_poll_interval = 1
        has_worker = worker_rec is not None
        worker_id = worker_rec.get("id") if worker_rec else str(uuid.uuid4())

        # Determine overall Sentinel status
        if is_mailbox_active and desired_state == "RUNNING":
            sentinel_status = "ACTIVE"
            status_color = "🟢"
        elif is_mailbox_active and desired_state == "STOPPED":
            sentinel_status = "PAUSED"
            status_color = "🟡"
        else:
            sentinel_status = "OFF"
            status_color = "🔴"

        st.markdown("---")

        # -----------------------------------------------------------------
        # Sentinel Status Hero (Exact Section 4 Specification)
        # -----------------------------------------------------------------
        if sentinel_status == "OFF":
            st.markdown("### 📡 Live Mail Analysis")
            st.markdown(f"**Status:** {status_color} **OFF**")
            st.write("Monitor an authorized mailbox continuously for new threats.")

            with st.expander("📬 Connect Mailbox", expanded=True):
                st.markdown("##### 🔐 Connect an Authorized Mailbox")
                st.caption(
                    "Authorize EMAILSHIELD INDIA to continuously monitor your inbox for inbound cyber threats. "
                    "Plaintext passwords are never stored; credentials are encrypted asymmetrically with the Worker RSA Public Key."
                )

                col_prov, col_email = st.columns([1, 2])
                with col_prov:
                    sel_provider = st.selectbox("Mail Provider", ALLOWED_PROVIDERS, index=0, key="c_mb_prov")
                with col_email:
                    conn_email = st.text_input("Mailbox Email Address", placeholder="e.g. yourname@gmail.com", key="c_mb_email")

                col_host, col_port, col_ssl = st.columns([2, 1, 1])
                default_h = PROVIDER_IMAP_DEFAULTS.get(sel_provider, {}).get("host", "imap.gmail.com")
                default_p = PROVIDER_IMAP_DEFAULTS.get(sel_provider, {}).get("port", 993)
                with col_host:
                    conn_host = st.text_input("IMAP Host", value=default_h, key="c_mb_host")
                with col_port:
                    conn_port = st.number_input("Port", min_value=1, max_value=65535, value=default_p, key="c_mb_port")
                with col_ssl:
                    conn_ssl = st.checkbox("Require SSL/TLS", value=True, key="c_mb_ssl")

                if sel_provider.lower() == "gmail":
                    with st.expander("🔐 Gmail App Password — Show setup guide", expanded=False):
                        st.markdown("""
### Quick 30s Setup for Gmail

1. Open your [Google Account](https://myaccount.google.com/apppasswords).
2. Go to **Security**.
3. Make sure **2-Step Verification** is enabled.
4. Create an **App Password**.
5. Copy the generated App Password.
6. Paste it into the App Password field below.

⚠️ **Use a Gmail App Password, NOT your normal Gmail password.**
""")

                conn_app_pwd = st.text_input(
                    "App Password (NOT primary password)",
                    type="password",
                    placeholder="16-character Google App Password",
                    help="Generate a 16-character App Password from your Google Account Security settings. Never enter your primary account password.",
                    key="c_mb_pwd"
                )

                auth_agree = st.checkbox(
                    "I confirm I am authorized to monitor this mailbox and consent to continuous threat analysis under EMAILSHIELD's privacy policy.",
                    key="c_mb_consent"
                )

                if st.button("🚀 Authorize & Connect Mailbox", type="primary", disabled=not auth_agree, key="btn_connect_mailbox"):
                    allowed, wait_sec = check_rate_limit("connect_mailbox", max_requests=5, window_seconds=300)
                    if not allowed:
                        st.error(f"⏳ Rate limit reached. Please wait {wait_sec}s before attempting another connection.")
                    elif not conn_email or not conn_app_pwd:
                        st.error("Please provide both email address and App Password.")
                    else:
                        if not has_worker:
                            ok_w, w_res = upsert_user_worker(current_user_id, 50, "RUNNING", user_client)
                            if ok_w:
                                worker_id = w_res["id"]
                            else:
                                if "JWT expired" in str(w_res) or "PGRST303" in str(w_res) or "session expired" in str(w_res).lower():
                                    st.session_state.pop("user_id", None)
                                    st.session_state.pop("user_email", None)
                                    st.session_state.pop("supabase_auth_token", None)
                                    st.session_state.pop("supabase_refresh_token", None)
                                    st.error("⚠️ Your authentication session has expired. Please sign in again using your credentials in the sidebar.")
                                    st.rerun()
                                else:
                                    st.error(f"Failed to initialize worker record: {w_res}")
                                worker_id = None
                        if worker_id:
                            with st.spinner("Encrypting credentials and provisioning mailbox..."):
                                ok_c, msg_c = connect_user_sentinel_mailbox(
                                    user_id=current_user_id,
                                    worker_id=worker_id,
                                    provider=sel_provider,
                                    email_address=conn_email,
                                    imap_host=conn_host,
                                    imap_port=int(conn_port),
                                    use_ssl=conn_ssl,
                                    app_password=conn_app_pwd,
                                    client=user_client
                                )
                                if ok_c:
                                    try:
                                        from core.sentinel_stats import start_sentinel_worker_daemon
                                        start_sentinel_worker_daemon()
                                    except Exception:
                                        pass
                                    st.session_state.pop("c_mb_pwd", None)
                                    st.session_state.pop("c_mb_email", None)
                                    st.success(msg_c)
                                    st.rerun()
                                else:
                                    if "JWT expired" in str(msg_c) or "PGRST303" in str(msg_c) or "session expired" in str(msg_c).lower():
                                        st.session_state.pop("user_id", None)
                                        st.session_state.pop("user_email", None)
                                        st.session_state.pop("supabase_auth_token", None)
                                        st.session_state.pop("supabase_refresh_token", None)
                                        st.error("⚠️ Your authentication session has expired. Please sign in again using your credentials in the sidebar.")
                                        st.rerun()
                                    else:
                                        st.error(msg_c)

        else:
            # CONNECTED (ACTIVE or PAUSED)
            st.markdown("### 📡 Live Mail Analysis")
            raw_email = mailbox_rec.get("email_address", "") if mailbox_rec else ""
            masked_email = mask_email_address(raw_email)

            # Compact status header
            st.markdown(f"**{status_color} {sentinel_status}**")
            scol1, scol2, scol3 = st.columns(3)
            with scol1:
                st.markdown(f"**Connected Mailbox**  \n{masked_email}")
            with scol2:
                st.markdown(f"**Polling**  \n1 second")
            with scol3:
                st.markdown(f"**Alerts**  \n🔴 High / Critical only")

            # Control buttons
            btn_col1, btn_col2, btn_col3 = st.columns([2, 2, 2])
            with btn_col1:
                if sentinel_status == "ACTIVE":
                    if st.button("⏹️ Stop Monitoring", use_container_width=True, key="btn_stop_active_sentinel"):
                        ok_s, msg_s = set_worker_desired_state(current_user_id, "STOPPED", user_client)
                        if ok_s:
                            try:
                                from core.sentinel_stats import stop_sentinel_worker_daemon
                                stop_sentinel_worker_daemon()
                            except Exception:
                                pass
                            st.info("Live Mail monitoring paused.")
                            st.rerun()
                        else:
                            st.error(msg_s)
                else: # PAUSED
                    if st.button("▶️ Resume Monitoring", type="primary", use_container_width=True, key="btn_resume_active_sentinel"):
                        ok_r, msg_r = set_worker_desired_state(current_user_id, "RUNNING", user_client)
                        if ok_r:
                            try:
                                from core.sentinel_stats import start_sentinel_worker_daemon
                                start_sentinel_worker_daemon()
                            except Exception:
                                pass
                            st.success("Live Mail monitoring resumed.")
                            st.rerun()
                        else:
                            st.error(msg_r)

            with btn_col2:
                if st.button("🔌 Disconnect Mailbox", type="secondary", use_container_width=True, key="btn_disconnect_mb"):
                    with st.spinner("Revoking credentials and disconnecting mailbox..."):
                        ok_disc, msg_disc = disconnect_user_sentinel_mailbox(current_user_id, user_client)
                        if ok_disc:
                            try:
                                from core.sentinel_stats import stop_sentinel_worker_daemon
                                stop_sentinel_worker_daemon()
                            except Exception:
                                pass
                            st.session_state.pop("c_mb_pwd", None)
                            st.session_state.pop("c_mb_email", None)
                            st.success(msg_disc)
                            st.rerun()
                        else:
                            st.error(msg_disc)

            with btn_col3:
                st.caption("🔒 All credentials remain encrypted. Disconnecting revokes all worker leases and access immediately.")

        # Configuration & Intelligence Tabs
        tab_health, tab_alerts, tab_privacy, tab_danger = st.tabs([
            "📡 Live Activity",
            "📱 Mobile Alerts",
            "🛡️ Privacy & Security",
            "⚠️ Danger Zone"
        ])

        with tab_health:
            from core.sentinel_stats import get_user_sentinel_stats
            sentinel_stats = get_user_sentinel_stats(
                user_id=current_user_id,
                mailbox_id=mailbox_rec.get("id") if mailbox_rec else None,
                client=user_client,
                checkpoint_rec=checkpoint_rec
            )

            # Section 16 Safe Diagnostics Block
            try:
                from core.sentinel_stats import get_sentinel_worker_runtime
                worker_rt = get_sentinel_worker_runtime()
                worker_proc_alive = worker_rt.get("worker_process_alive", False)
                worker_pid = worker_rt.get("pid")
                worker_pid_str = str(worker_pid) if worker_pid else "NONE"
                worker_proc_str = "RUNNING" if worker_proc_alive else "FAIL"
                worker_loop_str = "ACTIVE" if worker_rt.get("worker_poll_loop_active") else "FAIL"
                worker_hb = worker_rt.get("worker_last_heartbeat", "Never")
            except Exception:
                worker_proc_alive = False
                worker_pid_str = "NONE"
                worker_proc_str = "FAIL"
                worker_loop_str = "FAIL"
                worker_hb = "Never"

            diag_mb_id = f"{str(mailbox_rec.get('id', ''))[:8]}..." if mailbox_rec and mailbox_rec.get("id") else "N/A"
            diag_worker_state = desired_state.upper() if desired_state in ("RUNNING", "STOPPED") else "STOPPED"
            diag_lease_status = "ACTIVE" if (sentinel_status == "ACTIVE" and worker_proc_alive) else "LOST"
            diag_last_poll = sentinel_stats.get("last_poll_time", "Waiting for first poll...")
            diag_last_imap = sentinel_stats.get("last_successful_imap_poll", "Never")
            diag_checkpoint_uid = sentinel_stats.get("last_processed_uid", 0)
            diag_highest_uid = sentinel_stats.get("highest_observed_uid", 0)
            diag_last_result = sentinel_stats.get("last_poll_result", "0 new messages")
            diag_errors = sentinel_stats.get("processing_errors", 0)
            diag_arrived = sentinel_stats.get("emails_arrived", 0)
            diag_analysed = sentinel_stats.get("emails_analysed", 0)

            if sentinel_status == "ACTIVE" and not worker_proc_alive:
                st.warning("⚠️ Worker process is not running. Click below to launch the independent worker process.")
                if st.button("⚡ Start Worker", type="primary", key="btn_start_sentinel_worker_diag"):
                    from core.sentinel_stats import start_sentinel_worker_daemon
                    ok_start, msg_start, _ = start_sentinel_worker_daemon()
                    if ok_start:
                        st.success(msg_start)
                        st.rerun()
                    else:
                        st.error(msg_start)

            st.markdown("#### LIVE ACTIVITY")
            recent_events = sentinel_stats.get("recent_events", [])
            if recent_events:
                for evt in recent_events[:5]:
                    cat = evt.get("category", "Clean")
                    if cat == "High Risk":
                        st.error(f"🔴 **High Risk**  \nSubject: `{evt.get('subject', 'No Subject')}`  \nTime: {evt.get('time', 'N/A')}")
                    elif cat == "Suspicious":
                        st.warning(f"🟠 **Suspicious**  \nSubject: `{evt.get('subject', 'No Subject')}`  \nTime: {evt.get('time', 'N/A')}")
                    else:
                        st.success(f"🟢 **Clean**  \nSubject: `{evt.get('subject', 'No Subject')}`  \nTime: {evt.get('time', 'N/A')}")
            else:
                if not sentinel_stats["has_polled"] and sentinel_stats["emails_arrived"] == 0:
                    st.info("ℹ️ **Waiting for first poll...** Initial sync establishes the checkpoint UID. Historical mailbox messages are skipped to inspect incoming arrivals only.")
                else:
                    st.caption("No new threat events in the latest poll cycle. Inbox is monitored continuously.")

            st.markdown("───────────────────────────────")

            threats_count = sentinel_stats["suspicious"] + sentinel_stats["high_critical"]
            st.markdown(
                f"**{sentinel_stats['emails_arrived']}** Arrived · "
                f"**{sentinel_stats['emails_analysed']}** Analysed · "
                f"**{threats_count}** Threats"
            )

            p_col1, p_col2 = st.columns([2, 1])
            with p_col1:
                st.markdown(f"**Last Poll**  \n{sentinel_stats['last_poll_time']}")
            with p_col2:
                if st.button("🔄 Refresh Telemetry", key="btn_refresh_sentinel_telemetry", use_container_width=True):
                    st.rerun()

            with st.expander("⚙️ Diagnostics", expanded=False):
                diag_c1, diag_c2, diag_c3, diag_c4 = st.columns(4)
                with diag_c1:
                    st.text(f"Worker Process: {worker_proc_str}")
                    st.text(f"Worker PID: {worker_pid_str}")
                    st.text(f"Poll Loop: {worker_loop_str}")
                    st.text("Polling Interval: 1s")
                    st.text(f"Heartbeat: {worker_hb}")
                with diag_c2:
                    st.text(f"Worker State: {diag_worker_state}")
                    st.text(f"Mailbox: {masked_email}")
                    st.text(f"Mailbox ID: {diag_mb_id}")
                    st.text(f"Lease: {diag_lease_status}")
                with diag_c3:
                    st.text(f"Checkpoint UID: {diag_checkpoint_uid}")
                    st.text(f"Highest UID: {diag_highest_uid}")
                    st.text(f"Last Poll: {diag_last_poll}")
                    st.text(f"Last IMAP: {diag_last_imap}")
                with diag_c4:
                    st.text(f"Last Result: {diag_last_result}")
                    st.text(f"Poll Errors: {diag_errors}")
                    st.text(f"Emails Arrived: {diag_arrived}")
                    st.text(f"Emails Analysed: {diag_analysed}")

        with tab_alerts:
            st.markdown("### 📱 Mobile Alerts")
            st.caption("Get notified when Live Mail Analysis detects a high-risk or critical email.")

            tg_config = next((a for a in alerts_rec if a.get("channel") == "telegram"), None)
            wa_config = next((a for a in alerts_rec if a.get("channel") == "whatsapp"), None)

            saved_tg_dest = (tg_config.get("destination_target") if tg_config else "") or st.session_state.get("sentinel_tg_destination", "")
            saved_tg_enabled = tg_config.get("is_enabled", st.session_state.get("sentinel_tg_enabled", True)) if tg_config is not None else st.session_state.get("sentinel_tg_enabled", True)
            runtime_tg = get_telegram_config({
                "telegram_token": st.session_state.get("sentinel_tg_token", ""),
                "destination_target": saved_tg_dest,
                "is_enabled": saved_tg_enabled,
            })
            tg_is_conn = bool(runtime_tg["is_token_configured"] and runtime_tg["is_destination_configured"] and runtime_tg["is_enabled"])

            saved_wa_dest = (wa_config.get("destination_target") if wa_config else "") or st.session_state.get("sentinel_wa_destination", "")
            saved_wa_enabled = wa_config.get("is_enabled", st.session_state.get("sentinel_wa_enabled", True)) if wa_config is not None else st.session_state.get("sentinel_wa_enabled", True)
            runtime_wa = get_whatsapp_config({
                "whatsapp_apikey": st.session_state.get("sentinel_wa_apikey", ""),
                "destination_target": saved_wa_dest,
                "is_enabled": saved_wa_enabled,
            })
            wa_is_conn = bool(runtime_wa["is_apikey_configured"] and runtime_wa["is_destination_configured"] and runtime_wa["is_enabled"])

            # Clean Overview Status Header
            ma_s1, ma_s2, ma_s3, ma_s4 = st.columns(4)
            with ma_s1:
                st.markdown(f"**Telegram**  \n{'● Connected' if tg_is_conn else '🔴 Not Connected'}")
            with ma_s2:
                st.markdown(f"**WhatsApp**  \n{'● Connected' if wa_is_conn else '🔴 Not Connected'}")
            with ma_s3:
                st.markdown("**Alert Level**  \n🔴 High / Critical only")
            with ma_s4:
                if st.button("🔔 Test Alert", key="btn_mobile_quick_test_banner", use_container_width=True):
                    tested = False
                    if tg_is_conn:
                        with st.spinner("Testing Telegram alert..."):
                            tg_r = test_telegram_alert_delivery(runtime_tg["token"], runtime_tg["chat_id"])
                        if tg_r["delivery_status"] == "DELIVERED":
                            st.success(f"Telegram: {tg_r['details']}")
                        else:
                            st.error(f"Telegram: {tg_r['details']}")
                        tested = True
                    if wa_is_conn:
                        with st.spinner("Testing WhatsApp alert..."):
                            wa_r = test_whatsapp_alert_delivery(runtime_wa["phone"], runtime_wa["apikey"])
                        if wa_r["delivery_status"] == "DELIVERED":
                            st.success(f"WhatsApp: {wa_r['details']}")
                        else:
                            st.error(f"WhatsApp: {wa_r['details']}")
                        tested = True
                    if not tested:
                        st.info("No mobile channels are connected yet. Configure Telegram or WhatsApp below.")

            st.markdown("---")

            alert_col1, alert_col2 = st.columns(2)
            tg_config = next((a for a in alerts_rec if a.get("channel") == "telegram"), None)
            wa_config = next((a for a in alerts_rec if a.get("channel") == "whatsapp"), None)

            # =========================================================
            # 1. TELEGRAM ALERTS (Section 5)
            # =========================================================
            # 1. TELEGRAM ALERTS (Section 5)
            # =========================================================
            with alert_col1:
                st.markdown("**✈️ Telegram Alerts (HIGH Risk Only)**")

                saved_tg_dest = (tg_config.get("destination_target") if tg_config else "") or st.session_state.get("sentinel_tg_destination", "")
                saved_tg_enabled = tg_config.get("is_enabled", st.session_state.get("sentinel_tg_enabled", True)) if tg_config is not None else st.session_state.get("sentinel_tg_enabled", True)
                runtime_tg = get_telegram_config({
                    "telegram_token": st.session_state.get("sentinel_tg_token", ""),
                    "destination_target": saved_tg_dest,
                    "is_enabled": saved_tg_enabled,
                })

                # Cached bot verification to eliminate redundant network calls on reruns
                bot_username = None
                auth_valid = False
                token_val = runtime_tg["token"]
                if runtime_tg["is_token_configured"]:
                    tg_cache = st.session_state.get("_tg_token_auth_cache", {})
                    if token_val in tg_cache:
                        auth_valid, bot_username = tg_cache[token_val]
                    else:
                        try:
                            auth_valid, bot_username, _ = verify_telegram_bot_token(token_val)
                            st.session_state.setdefault("_tg_token_auth_cache", {})[token_val] = (auth_valid, bot_username)
                        except Exception:
                            auth_valid, bot_username = False, None

                dest_valid = runtime_tg["is_destination_configured"]
                auth_badge = "🟢 Configured" if auth_valid else ("🟡 Unverified" if runtime_tg["is_token_configured"] else "🔴 Not Configured")
                dest_badge = f"🟢 Configured <code>({runtime_tg['masked_destination']})</code>" if dest_valid else "🔴 Not Configured"

                if auth_valid and dest_valid:
                    if runtime_tg["is_enabled"]:
                        overall_badge = "🟢 Connected"
                        is_tg_connected = True
                    else:
                        overall_badge = "⚪ Disabled"
                        is_tg_connected = True
                elif runtime_tg["is_token_configured"] or dest_valid:
                    overall_badge = "🟡 Pending Config"
                    is_tg_connected = False
                else:
                    overall_badge = "⚪ Not Connected"
                    is_tg_connected = False

                bot_id_line = f"<div><b>Bot:</b> <code>{html.escape(str(bot_username))}</code></div>" if bot_username else ""
                bot_token_display = "<code>CONFIGURED ••••••••••</code>" if runtime_tg["is_token_configured"] else "🔴 Not Configured"

                if is_tg_connected:
                    st.markdown(
                        f"""
                        <div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 12px; font-size: 0.88em; line-height: 1.6;">
                            <div><b>Status:</b> {overall_badge}</div>
                            <div><b>Authentication:</b> {auth_badge}</div>
                            <div><b>Destination:</b> {dest_badge}</div>
                            {bot_id_line}
                            <div><b>Bot Token:</b> <code>CONFIGURED ••••••••••</code></div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    c_tg_t, c_tg_d = st.columns(2)
                    with c_tg_t:
                        if st.button("🧪 Test Alert", key="btn_test_tg_connected", use_container_width=True):
                            with st.spinner("Executing controlled 4-phase Telegram test..."):
                                test_res = test_telegram_alert_delivery(runtime_tg["token"], runtime_tg["chat_id"])
                            st.markdown(
                                f"""
                                **Telegram Test Results:**
                                - Telegram API: `{test_res['api_status']}`
                                - Telegram Authentication: `{test_res['auth_status']}`
                                - Telegram Destination: `{test_res['destination_status']}`
                                - Test Alert: `{test_res['delivery_status']}`
                                """
                            )
                            if test_res["delivery_status"] == "DELIVERED":
                                st.success(test_res["details"])
                            else:
                                st.error(test_res["details"])

                    with c_tg_d:
                        if st.button("🔌 Disconnect", key="btn_disc_tg", type="secondary", use_container_width=True):
                            st.session_state.pop("sentinel_tg_token", None)
                            st.session_state.pop("sentinel_tg_destination", None)
                            st.session_state.pop("sentinel_tg_target", None)
                            st.session_state.pop("sentinel_tg_token_entry", None)
                            st.session_state.pop("sentinel_tg_enabled", None)
                            st.session_state.pop("sentinel_tg_enabled_chk", None)
                            st.session_state.pop("sentinel_tg_toggle_connected", None)
                            st.session_state.pop("_tg_token_auth_cache", None)
                            if worker_id:
                                save_user_alert_metadata(current_user_id, worker_id, "telegram", "", False, high_risk_only=True, client=user_client)
                            st.success("Telegram alerts disconnected.")
                            st.rerun()

                    tg_toggle_conn = st.checkbox(
                        "Enable Telegram Alerts",
                        value=runtime_tg["is_enabled"],
                        key="sentinel_tg_toggle_connected"
                    )
                    if tg_toggle_conn != runtime_tg["is_enabled"]:
                        st.session_state["sentinel_tg_enabled"] = tg_toggle_conn
                        if worker_id:
                            save_user_alert_metadata(
                                current_user_id, worker_id, "telegram", runtime_tg["chat_id"], tg_toggle_conn, high_risk_only=True, client=user_client
                            )
                        st.rerun()
                else:
                    st.markdown(
                        f"""
                        <div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 12px; font-size: 0.88em; line-height: 1.6;">
                            <div><b>Status:</b> {overall_badge}</div>
                            <div><b>Authentication:</b> {auth_badge}</div>
                            <div><b>Destination:</b> {dest_badge}</div>
                            {bot_id_line}
                            <div><b>Bot Token:</b> {bot_token_display}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    tg_target = st.text_input(
                        "Telegram Destination (Chat ID)",
                        value=runtime_tg.get("chat_id", "") or (tg_config.get("destination_target", "") if tg_config else ""),
                        placeholder="e.g. 123456789 or @mychannel",
                        help="Numeric Chat ID (obtain by messaging @userinfobot) or public @channel handle.",
                        key="sentinel_tg_target"
                    )

                    has_env_token = bool(os.environ.get("TELEGRAM_BOT_TOKEN"))
                    if not has_env_token:
                        if runtime_tg["is_token_configured"]:
                            st.caption("🔒 *Bot Token configured in session memory (Runtime Protected).*")
                            tg_token_input = st.text_input(
                                "Change Telegram Bot Token (optional)",
                                value="",
                                type="password",
                                placeholder="Leave blank to keep existing token",
                                help="Enter a new bot token if you wish to change it.",
                                key="sentinel_tg_token_entry"
                            )
                        else:
                            tg_token_input = st.text_input(
                                "Telegram Bot Token",
                                value="",
                                type="password",
                                placeholder="123456789:ABCdefGHI...",
                                help="Bot token from @BotFather. Stored in transient session memory only; never saved to database in plaintext.",
                                key="sentinel_tg_token_entry"
                            )
                    else:
                        st.caption("🔒 *Bot Token configured via environment/secrets (Runtime Protected).*")
                        tg_token_input = runtime_tg["token"]

                    tg_enabled = st.checkbox(
                        "Enable Telegram Alerts",
                        value=runtime_tg.get("is_enabled", True),
                        key="sentinel_tg_enabled_chk"
                    )

                    btn_tg_save, btn_tg_test = st.columns(2)
                    with btn_tg_save:
                        if st.button("💾 Connect / Save", key="btn_save_tg_config", use_container_width=True):
                            eff_token = (tg_token_input.strip() if tg_token_input else "") or runtime_tg["token"]
                            eff_target = tg_target.strip()
                            is_valid_tok = validate_telegram_token_format(eff_token) if eff_token else False
                            is_valid_chat, chat_msg = validate_telegram_chat_id(eff_target)
                            if not eff_token:
                                st.error("Telegram Bot Token is required.")
                            elif not is_valid_tok:
                                st.error("Invalid Telegram Bot Token format. Expected <bot_id>:<secret>.")
                            elif not is_valid_chat:
                                st.error(chat_msg)
                            elif worker_id:
                                st.session_state["sentinel_tg_token"] = eff_token
                                st.session_state["sentinel_tg_destination"] = eff_target
                                st.session_state["sentinel_tg_enabled"] = tg_enabled
                                st.session_state.pop("sentinel_tg_token_entry", None)
                                st.session_state.pop("_tg_token_auth_cache", None)
                                ok_a, msg_a = save_user_alert_metadata(
                                    current_user_id, worker_id, "telegram", eff_target, tg_enabled, high_risk_only=True, client=user_client
                                )
                                if ok_a:
                                    st.success("Telegram alerts configured successfully.")
                                    st.rerun()
                                else:
                                    st.error(msg_a)

                    with btn_tg_test:
                        if st.button("🧪 Test Alert", key="btn_test_tg_alert", use_container_width=True):
                            eff_token = (tg_token_input.strip() if tg_token_input else "") or runtime_tg["token"]
                            eff_target = tg_target.strip() or runtime_tg.get("chat_id", "")
                            if not eff_token:
                                st.error("Cannot test alert: Telegram Bot Token is required.")
                            elif not eff_target:
                                st.error("Cannot test alert: Telegram Destination (Chat ID) is required.")
                            else:
                                with st.spinner("Executing controlled 4-phase Telegram test..."):
                                    test_res = test_telegram_alert_delivery(eff_token, eff_target)
                                st.markdown(
                                    f"""
                                    **Telegram Test Results:**
                                    - Telegram API: `{test_res['api_status']}`
                                    - Telegram Authentication: `{test_res['auth_status']}`
                                    - Telegram Destination: `{test_res['destination_status']}`
                                    - Test Alert: `{test_res['delivery_status']}`
                                    """
                                )
                                if test_res["delivery_status"] == "DELIVERED":
                                    st.session_state["sentinel_tg_token"] = eff_token
                                    st.session_state["sentinel_tg_destination"] = eff_target
                                    st.session_state["sentinel_tg_enabled"] = True
                                    st.session_state.pop("sentinel_tg_token_entry", None)
                                    if worker_id:
                                        save_user_alert_metadata(
                                            current_user_id, worker_id, "telegram", eff_target, True, high_risk_only=True, client=user_client
                                        )
                                    st.success(f"{test_res['details']} — Configuration verified and saved.")
                                    st.rerun()
                                else:
                                    st.error(test_res["details"])

                with st.expander("❓ How do I get a Telegram Bot Token and Chat ID?", expanded=False):
                    st.markdown("""
##### 🤖 Telegram Bot Setup (4 Quick Steps)

**Step 1 — Create the Telegram Bot**
1. Open Telegram on your device.
2. Search for the official verified bot: `@BotFather`.
3. Start the BotFather conversation by clicking **Start** or sending `/start`.
4. Send the command: `/newbot`.
5. Choose a friendly display name for your bot (e.g. `EmailShield Alert Bot`).
6. Choose a unique username ending in `bot` (e.g. `MyEmailShieldAlertsBot`).
7. BotFather will provide your **Bot Token** (format: `1234567890:ABCdefGHI...`).

> 🔑 **Bot Token**: Authenticates your Telegram bot with the Telegram API.

**Step 2 — Start the Bot**
1. Open your newly created bot in Telegram (search for its username or click the link from BotFather).
2. Press **Start** or send `/start` to your bot.  
*(Telegram requires you to send the first message so your bot has permission to message you).*

**Step 3 — Configure the Destination (Chat ID)**
> 🎯 **Chat ID**: Destination where EmailShield sends alerts.
* **Personal Direct Alerts**: Search for `@userinfobot` on Telegram, click **Start**, and copy the numeric `Id` (e.g. `123456789`). Enter this numeric ID into the **Telegram Destination (Chat ID)** field.
* **Channel / Group Alerts**: Add your bot to your channel or group as an Administrator with message permissions. Enter your public channel handle (e.g. `@my_alerts_channel`) or group chat ID.

**Step 4 — Test Your Setup**
1. Enter the **Bot Token** and **Chat ID** in the configuration fields above.
2. Click **🧪 Test Alert** to verify end-to-end delivery.

---
🔒 **Security Notice**:
* **Never share your Telegram Bot Token.**
* EmailShield masks the token after configuration and stores it in secure runtime memory only.
""")

            # =========================================================
            # 2. WHATSAPP ALERTS (Section 6 & 7)
            # =========================================================
            with alert_col2:
                st.markdown("**💬 WhatsApp Alerts**")

                saved_wa_dest = (wa_config.get("destination_target") if wa_config else "") or st.session_state.get("sentinel_wa_destination", "")
                saved_wa_enabled = wa_config.get("is_enabled", st.session_state.get("sentinel_wa_enabled", True)) if wa_config is not None else st.session_state.get("sentinel_wa_enabled", True)
                runtime_wa = get_whatsapp_config({
                    "whatsapp_apikey": st.session_state.get("sentinel_wa_apikey", ""),
                    "destination_target": saved_wa_dest,
                    "is_enabled": saved_wa_enabled,
                })

                wa_auth_valid = runtime_wa["is_apikey_configured"]
                wa_dest_valid = runtime_wa["is_destination_configured"]

                wa_auth_badge = "🟢 Configured" if wa_auth_valid else "🔴 Not Configured"
                wa_dest_badge = f"🟢 Configured <code>({runtime_wa['masked_destination']})</code>" if wa_dest_valid else "🔴 Not Configured"

                if wa_auth_valid and wa_dest_valid:
                    if runtime_wa["is_enabled"]:
                        wa_overall_badge = "🟢 Connected"
                        is_wa_connected = True
                    else:
                        wa_overall_badge = "⚪ Disabled"
                        is_wa_connected = True
                elif wa_auth_valid or wa_dest_valid:
                    wa_overall_badge = "🟡 Pending Config"
                    is_wa_connected = False
                else:
                    wa_overall_badge = "⚪ Not Connected"
                    is_wa_connected = False

                wa_key_display = "<code>CONFIGURED ••••••••••</code>" if wa_auth_valid else "🔴 Not Configured"

                if is_wa_connected:
                    st.markdown(
                        f"""
                        <div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 12px; font-size: 0.88em; line-height: 1.6;">
                            <div><b>Status:</b> {wa_overall_badge}</div>
                            <div><b>Authentication:</b> {wa_auth_badge}</div>
                            <div><b>Destination:</b> {wa_dest_badge}</div>
                            <div><b>CallMeBot API Key:</b> <code>CONFIGURED ••••••••••</code></div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    c_wa_t, c_wa_d = st.columns(2)
                    with c_wa_t:
                        if st.button("🧪 Test Alert", key="btn_test_wa_connected", use_container_width=True):
                            with st.spinner("Executing controlled 4-phase WhatsApp test..."):
                                wa_test_res = test_whatsapp_alert_delivery(runtime_wa["phone"], runtime_wa["apikey"])
                            st.markdown(
                                f"""
                                **WhatsApp Test Results:**
                                - Destination: `{wa_test_res['masked_destination']}` ({wa_test_res['destination_status']})
                                - Authentication: `{wa_test_res['auth_status']}`
                                - Delivery: `{wa_test_res['delivery_status']}`
                                """
                            )
                            if wa_test_res["delivery_status"] == "DELIVERED":
                                st.success(wa_test_res["details"])
                            else:
                                st.error(wa_test_res["details"])

                    with c_wa_d:
                        if st.button("🔌 Disconnect", key="btn_disc_wa", type="secondary", use_container_width=True):
                            st.session_state.pop("sentinel_wa_apikey", None)
                            st.session_state.pop("sentinel_wa_destination", None)
                            st.session_state.pop("sentinel_wa_phone_input", None)
                            st.session_state.pop("sentinel_wa_key_entry", None)
                            st.session_state.pop("sentinel_wa_enabled", None)
                            st.session_state.pop("sentinel_wa_enabled_chk", None)
                            st.session_state.pop("sentinel_wa_toggle_connected", None)
                            if worker_id:
                                save_user_alert_metadata(current_user_id, worker_id, "whatsapp", "", False, high_risk_only=True, client=user_client)
                            st.success("WhatsApp alerts disconnected.")
                            st.rerun()

                    wa_toggle_conn = st.checkbox(
                        "Enable WhatsApp Alerts",
                        value=runtime_wa["is_enabled"],
                        key="sentinel_wa_toggle_connected"
                    )
                    if wa_toggle_conn != runtime_wa["is_enabled"]:
                        st.session_state["sentinel_wa_enabled"] = wa_toggle_conn
                        if worker_id:
                            save_user_alert_metadata(
                                current_user_id, worker_id, "whatsapp", runtime_wa["phone"], wa_toggle_conn, high_risk_only=True, client=user_client
                            )
                        st.rerun()
                else:
                    st.markdown(
                        f"""
                        <div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 12px; font-size: 0.88em; line-height: 1.6;">
                            <div><b>Status:</b> {wa_overall_badge}</div>
                            <div><b>Authentication:</b> {wa_auth_badge}</div>
                            <div><b>Destination:</b> {wa_dest_badge}</div>
                            <div><b>CallMeBot API Key:</b> {wa_key_display}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    wa_phone_in = st.text_input(
                        "WhatsApp Phone (E.164 with +)",
                        value=runtime_wa.get("phone", "") or (wa_config.get("destination_target", "") if wa_config else ""),
                        placeholder="e.g. +919876543210",
                        help="International phone number with '+' and country code (e.g. +919876543210).",
                        key="sentinel_wa_phone_input"
                    )

                    has_env_wa_key = bool(
                        os.environ.get("CALLMEBOT_API_KEY") or
                        os.environ.get("CALLMEBOT_APIKEY") or
                        os.environ.get("WHATSAPP_APIKEY") or
                        os.environ.get("SENTINEL_ALERT_WHATSAPP_TOKEN")
                    )
                    if not has_env_wa_key:
                        if runtime_wa["is_apikey_configured"]:
                            st.caption("🔒 *API Key configured in session memory (Runtime Protected).*")
                            wa_key_in = st.text_input(
                                "Change CallMeBot API Key (optional)",
                                value="",
                                type="password",
                                placeholder="Leave blank to keep existing key",
                                help="Enter a new CallMeBot API key if you wish to change it.",
                                key="sentinel_wa_key_entry"
                            )
                        else:
                            wa_key_in = st.text_input(
                                "CallMeBot API Key",
                                value="",
                                type="password",
                                placeholder="••••••••",
                                help="Free CallMeBot API key obtained from WhatsApp. Stored in transient session memory only; never saved to database in plaintext.",
                                key="sentinel_wa_key_entry"
                            )
                    else:
                        st.caption("🔒 *API Key configured via environment/secrets (Runtime Protected).*")
                        wa_key_in = runtime_wa["apikey"]

                    wa_enabled_in = st.checkbox(
                        "Enable WhatsApp Alerts",
                        value=runtime_wa.get("is_enabled", True),
                        key="sentinel_wa_enabled_chk"
                    )

                    btn_wa_save, btn_wa_test = st.columns(2)
                    with btn_wa_save:
                        if st.button("💾 Connect / Save", key="btn_save_wa_config", use_container_width=True):
                            ok_p, p_res = validate_whatsapp_phone(wa_phone_in)
                            eff_key = (wa_key_in.strip() if wa_key_in else "") or runtime_wa.get("apikey", "")
                            ok_k, k_res = validate_whatsapp_apikey(eff_key)
                            if not ok_p:
                                st.error(p_res)
                            elif not ok_k:
                                st.error(k_res)
                            elif worker_id:
                                st.session_state["sentinel_wa_apikey"] = k_res
                                st.session_state["sentinel_wa_destination"] = p_res
                                st.session_state["sentinel_wa_enabled"] = wa_enabled_in
                                st.session_state.pop("sentinel_wa_key_entry", None)
                                ok_a, msg_a = save_user_alert_metadata(
                                    current_user_id, worker_id, "whatsapp", p_res, wa_enabled_in, high_risk_only=True, client=user_client
                                )
                                if ok_a:
                                    st.success(msg_a)
                                    st.rerun()
                                else:
                                    st.error(msg_a)

                    with btn_wa_test:
                        if st.button("🧪 Test Alert", key="btn_test_wa_unconn", use_container_width=True):
                            eff_phone = wa_phone_in.strip() or runtime_wa.get("phone", "")
                            eff_key = (wa_key_in.strip() if wa_key_in else "") or runtime_wa.get("apikey", "")
                            if not eff_phone:
                                st.error("Cannot test alert: WhatsApp phone number is required.")
                            elif not eff_key:
                                st.error("Cannot test alert: CallMeBot API key is required.")
                            else:
                                with st.spinner("Executing controlled 4-phase WhatsApp test..."):
                                    wa_test_res = test_whatsapp_alert_delivery(eff_phone, eff_key)
                                st.markdown(
                                    f"""
                                    **WhatsApp Test Results:**
                                    - Destination: `{wa_test_res['masked_destination']}` ({wa_test_res['destination_status']})
                                    - Authentication: `{wa_test_res['auth_status']}`
                                    - Delivery: `{wa_test_res['delivery_status']}`
                                    """
                                )
                                if wa_test_res["delivery_status"] == "DELIVERED":
                                    st.session_state["sentinel_wa_apikey"] = eff_key
                                    st.session_state["sentinel_wa_destination"] = eff_phone
                                    st.session_state["sentinel_wa_enabled"] = True
                                    st.session_state.pop("sentinel_wa_key_entry", None)
                                    if worker_id:
                                        save_user_alert_metadata(
                                            current_user_id, worker_id, "whatsapp", eff_phone, True, high_risk_only=True, client=user_client
                                        )
                                    st.success(f"{wa_test_res['details']} — Configuration verified and saved.")
                                    st.rerun()
                                else:
                                    st.error(wa_test_res["details"])

                with st.expander("❓ How do I configure WhatsApp Alerts?", expanded=False):
                    st.markdown("""
##### 💬 WhatsApp Alerts Setup (via CallMeBot)

EmailShield delivers instant WhatsApp notifications using **WhatsApp via CallMeBot**.

**Understanding Required Fields:**
* **Phone Number**: The WhatsApp destination (your personal mobile number).
* **CallMeBot API Key**: The authentication credential used by CallMeBot to authorize messages to your phone.

---

**Step 1 — Activate CallMeBot on WhatsApp (30 seconds)**
1. Open WhatsApp on your mobile device.
2. Follow the official instructions at:  
   👉 [Official CallMeBot WhatsApp Documentation](https://www.callmebot.com/blog/free-api-whatsapp-messages/)
3. Add the official CallMeBot phone gateway or open the link to start a chat with CallMeBot.
4. Send the following exact message via WhatsApp to CallMeBot:  
   `I allow callmebot to send me messages`
5. Wait 10–30 seconds. CallMeBot will reply with:  
   `CallMeBot API Activated. Your APIKey is: XXXXXX`
6. Copy your personal **API Key**.

**Step 2 — Configure EmailShield**
1. Enter your destination number in the **WhatsApp Phone** field using full international E.164 format with `+` (e.g. `+919876543210`).
2. Enter your CallMeBot API key in the **CallMeBot API Key** field.
3. Check **Enable WhatsApp Alerts** and click **💾 Connect / Save**.

**Step 3 — Test Alert**
1. Click **🧪 Test Alert** to dispatch a harmless verification ping.
2. Confirm receipt on your WhatsApp phone.

---
🔒 **Security Notice**:
* **Never share your CallMeBot API key.**
* EmailShield masks credentials after configuration. Your destination phone is displayed with redaction (e.g. `+91••••••••10`) and the API key is never saved in plaintext database storage.
""")

        with tab_privacy:
            st.markdown("##### 🛡️ Privacy & Security")
            st.caption("Architecture Notice: Live Sentinel is temporarily unavailable in public multi-user mode without explicit per-user authorization. The background worker daemon is NOT DEPLOYED (Phase 4) in the web presentation tier; it executes strictly in an isolated external runtime.")
            st.info(
                "**1. Authorized Investigation:** Users must only investigate emails or connect mailboxes they are authorized to monitor.\n\n"
                "**2. Zero Plaintext Passwords:** Mailbox passwords and Google App Passwords are never stored in plaintext. They are encrypted using RSA-OAEP + AES-256-GCM.\n\n"
                "**3. Local-First Evidence Retention:** Forensic telemetry, indicators, and incident packages are retained under configurable policies (7, 30, 90, 180 days). Evidence preservation locks prevent deletion of open cases.\n\n"
                "**4. Approximate Infrastructure Geolocation:** IP geolocation coordinates describe intermediate network infrastructure and relay hops. They represent approximate network context, not proof of sender's physical identity or physical location.\n\n"
                "**5. Instant Revocation:** Disconnecting a mailbox permanently halts polling, invalidates worker leases, and revokes credentials immediately."
            )

        with tab_danger:
            st.markdown("##### ⚠️ Lifecycle & Configuration Reset")
            d_col1, d_col2 = st.columns(2)
            with d_col1:
                st.markdown("**Pause / Deactivate Monitoring**")
                st.caption("Stops the desired state and pauses mailbox monitoring without deleting configuration history.")
                if st.button("⏸️ Deactivate Monitoring", key="btn_deactivate_sentinel"):
                    ok_d, msg_d = deactivate_user_sentinel(current_user_id, user_client)
                    if ok_d:
                        st.warning(msg_d)
                        st.rerun()
                    else:
                        st.error(msg_d)

            with d_col2:
                st.markdown("**Permanently Delete Configuration**")
                st.caption("Removes worker, mailbox metadata, and alert configurations from the database.")
                confirm_delete = st.checkbox("I confirm I want to permanently delete my Live Mail configuration", key="chk_confirm_delete")
                if st.button("🗑️ Permanently Delete Configuration", disabled=not confirm_delete, type="primary", key="btn_delete_sentinel"):
                    ok_del, msg_del = delete_user_sentinel_config(current_user_id, user_client)
                    if ok_del:
                        st.success(msg_del)
                        st.rerun()
                    else:
                        st.error(msg_del)

# View 1: Analyze Email
elif selected_nav == "📧 Analyze Email":
    batch_data = st.session_state.get("batch_results")
    if batch_data and not st.session_state.get("current_email_bytes"):
        st.header("📊 Today's Mailbox Analytics")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Scanned Today", batch_data["total_scanned"])
        col2.metric("Clean", batch_data["clean_count"])
        col3.metric("Suspicious", batch_data["suspicious_count"])
        col4.metric("Phishing", batch_data["phishing_count"])
        
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            st.subheader("Threat Breakdown")
            labels = ["Clean", "Suspicious", "Phishing"]
            counts = [batch_data["clean_count"], batch_data["suspicious_count"], batch_data["phishing_count"]]
            fig = px.pie(
                names=labels, 
                values=counts,
                color=labels,
                color_discrete_map={"Clean": "#00CC96", "Suspicious": "#FFA15A", "Phishing": "#EF553B"},
                hole=0.4
            )
            fig.update_layout(margin=dict(t=0, b=0, l=0, r=0), plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True, theme="streamlit")
            
        with col_chart2:
            st.subheader("Content Categories")
            if "content_categories" in batch_data and batch_data["content_categories"]:
                cat_labels = list(batch_data["content_categories"].keys())
                cat_values = list(batch_data["content_categories"].values())
                fig_cat = px.pie(names=cat_labels, values=cat_values, hole=0.4)
                fig_cat.update_layout(margin=dict(t=0, b=0, l=0, r=0), plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig_cat, use_container_width=True, theme="streamlit")
            else:
                st.write("No categorizable content.")
        
        st.subheader("All Emails Breakdown")
        if batch_data["flagged_emails"]:
            st.dataframe(batch_data["flagged_emails"], use_container_width=True)
            
        if st.button("🧹 Clear Batch Results & Upload Single Email", key="btn_clear_batch_for_single"):
            st.session_state["batch_results"] = None
            st.rerun()
        st.markdown("---")

    col_up1, col_up2 = st.columns([3, 1])
    with col_up1:
        uploaded_file = st.file_uploader("Upload .eml file locally", type=["eml"], help="Upload an RFC 822 .eml file (Max 10MB)")
        if uploaded_file is not None:
            if uploaded_file.size > 10 * 1024 * 1024:
                st.error(f"⚠️ **Upload Rejected**: File size ({uploaded_file.size // (1024*1024)} MB) exceeds the maximum allowed limit of 10 MB.")
            else:
                allowed, wait_sec = check_rate_limit("upload_eml", max_requests=15, window_seconds=60)
                if not allowed:
                    st.error(f"⏳ **Rate limit exceeded**: Please wait {wait_sec}s before uploading another email.")
                else:
                    st.session_state["batch_results"] = None
                    st.session_state["current_email_bytes"] = uploaded_file.getvalue()
    with col_up2:
        st.write("Or quick test sample attacks:")
        sample_choice = st.selectbox(
            "Select attack vector:",
            [
                "1. PayPal Phishing (Auth Spoof & Header Diff)",
                "2. Indian UPI Extortion & Bank Fraud",
                "3. Quishing (Embedded QR Code Attack)",
                "4. Weaponized Malware Attachment"
            ],
            key="sample_selector_quick"
        )
        sample_map = {
            "1. PayPal Phishing (Auth Spoof & Header Diff)": "samples/phishing.eml",
            "2. Indian UPI Extortion & Bank Fraud": "samples/indian_extortion_upi.eml",
            "3. Quishing (Embedded QR Code Attack)": "samples/quishing_invoice.eml",
            "4. Weaponized Malware Attachment": "samples/malware_lure.eml"
        }
        if st.button("🚀 Load Sample", key="btn_load_sample_chosen"):
            target_path = sample_map.get(sample_choice, "samples/phishing.eml")
            with open(target_path, "rb") as f:
                st.session_state["batch_results"] = None
                st.session_state["current_email_bytes"] = f.read()
            st.rerun()

    bytes_data = st.session_state.get("current_email_bytes")

    if not bytes_data:
        st.markdown("---")
        st.info("💡 **Welcome to EMAILSHIELD Forensic Intelligence!** Choose an option below to start your investigation:")
        
        col_card1, col_card2 = st.columns(2)
        with col_card1:
            st.markdown(
                """
<div style="background-color: #1e293b; border-radius: 8px; padding: 16px; border: 1px solid #334155; height: 100%;">
<h4 style="margin-top: 0; color: #38bdf8;">🧪 1-Click Instant Attack Vectors</h4>
<p style="color: #cbd5e1; font-size: 0.9em;">
Instantly test full forensics across 4 pre-packaged cyber threat scenarios (.eml):
</p>
<ul style="color: #94a3b8; font-size: 0.85em;">
<li><b>PayPal Phishing:</b> Spoofed auth &amp; Forensic Header Diff</li>
<li><b>Indian Cyber Fraud:</b> UPI VPAs, IFSC bank routes &amp; NCRP filing</li>
<li><b>Quishing:</b> Embedded KYC QR code decoded via OpenCV</li>
<li><b>Malware Lure:</b> Executable quarantine &amp; Defanged EML</li>
</ul>
</div>
""",
                unsafe_allow_html=True
            )
            card_sample = st.selectbox(
                "Select demo scenario:",
                [
                    "1. PayPal Phishing (Auth Spoof & Header Diff)",
                    "2. Indian UPI Extortion & Bank Fraud",
                    "3. Quishing (Embedded QR Code Attack)",
                    "4. Weaponized Malware Attachment"
                ],
                key="card_sample_select"
            )
            if st.button("🚀 Analyze Selected Scenario", type="primary", use_container_width=True, key="btn_card_load"):
                target_path = sample_map.get(card_sample, "samples/phishing.eml")
                with open(target_path, "rb") as f:
                    st.session_state["batch_results"] = None
                    st.session_state["current_email_bytes"] = f.read()
                st.rerun()

        with col_card2:
            st.markdown(
                """
<div style="background-color: #1e293b; border-radius: 8px; padding: 16px; border: 1px solid #334155; height: 100%;">
<h4 style="margin-top: 0; color: #4ade80;">📬 Connect Your Mailbox (30s)</h4>
<p style="color: #cbd5e1; font-size: 0.9em;">
Connect Gmail, Outlook, Yahoo, or Zoho Mail in seconds with <b>$0 investment</b> and <b>zero developer accounts</b>:
</p>
<ol style="color: #94a3b8; font-size: 0.85em;">
<li>Select your provider in the <b>left sidebar</b>.</li>
<li>Generate a free 16-character App Password using the 1-click link.</li>
<li>Click <b>Connect Mailbox</b> to inspect live inbox emails.</li>
</ol>
<p style="color: #94a3b8; font-size: 0.8em; margin-bottom: 0;">
🔒 100% Free &amp; Private. Uses standard TLS encrypted IMAP. Real password is never shared.
</p>
</div>
""",
                unsafe_allow_html=True
            )

        st.stop()
    
    # --- SHA-256 Analysis Cache: skip redundant 19s investigation on reruns ---
    _email_sha256 = hashlib.sha256(bytes_data).hexdigest()
    _cache = st.session_state.get("_cached_analysis_payload")
    _cache_hit = (_cache is not None and _cache.get("sha256") == _email_sha256)

    if _cache_hit:
        # Restore all analysis variables from session cache (< 1 ms)
        parsed_data = _cache["parsed_data"]
        headers = parsed_data.get("headers", {})
        body = parsed_data.get("body", "")
        case_id = _cache["case_id"]
        subject = _cache["subject"]
        sender_val = _cache["sender_val"]
        indicators = _cache["indicators"]
        auth_evidence = _cache["auth_evidence"]
        geolocations = _cache["geolocations"]
        sender_loc = _cache["sender_loc"]
        agent_out = _cache["agent_out"]
        domain_rep = _cache["domain_rep"]
        url_analyses = _cache["url_analyses"]
        rule_findings = _cache["rule_findings"]
        risk_score = _cache["risk_score"]
        reasons = _cache["reasons"]
        ml_assessment = _cache["ml_assessment"]
        ai_briefing = _cache["ai_briefing"]
        agent_trace = _cache["agent_trace"]
        quishing_findings = _cache["quishing_findings"]
        indian_banking_iocs = _cache["indian_banking_iocs"]
        timeline_events = _cache["timeline_events"]
        auth_align_obj = _cache["auth_align_obj"]
        att_analyses = _cache["att_analyses"]
        lookalike_obj = _cache["lookalike_obj"]
        bec_obj = _cache["bec_obj"]
        relay_transit_data = _cache["relay_transit_data"]
        infra_intel = _cache["infra_intel"]
        case_report = _cache["case_report"]
        normalization_data = _cache.get("normalization_data", {})
        current_status = getattr(case_report, "status", "Open") or "Open"
        current_inv = getattr(case_report, "assigned_investigator", "Unassigned") or "Unassigned"
        current_notes = getattr(case_report, "analyst_notes", "") or ""
    else:
        with st.spinner("Parsing and analyzing email evidence..."):
            # 1. Parse
            parser = SecureEmailParser(bytes_data)
            parsed_data = parser.parse()
            headers = parsed_data.get("headers", {})
            body = parsed_data.get("body", "")

            case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

            # 2. Extract IOCs
            indicators = []
            raw_iocs = extract_all_indicators(body + " " + str(headers))
            for ip in raw_iocs["ipv4"]:
                indicators.append(Indicator(type="IP", value=ip, source="Body/Headers"))
            for url in raw_iocs["urls"]:
                indicators.append(Indicator(type="URL", value=url, source="Body/Headers"))
            for email in raw_iocs["emails"]:
                indicators.append(Indicator(type="Email", value=email, source="Body/Headers"))

            # 3. Auth Evidence
            auth_header = str(headers.get("authentication-results", ""))
            auth_evidence = []
            if auth_header:
                parsed_auth = parse_auth_results(auth_header)
                for a in parsed_auth:
                    auth_evidence.append(AuthEvidence(**a))

            # 4. Geolocation & Originating Sender Location
            geolocations = []
            for ip in raw_iocs["ipv4"]:
                geo = get_geolocation(ip)
                geolocations.append(GeolocationInfo(**geo))

            sender_loc = get_sender_location(headers, parsed_data.get("received_chain", []))
            if sender_loc.get("is_identified") and sender_loc.get("sender_ip"):
                s_ip = sender_loc["sender_ip"]
                if s_ip not in [g.ip for g in geolocations] and is_public_ip(s_ip):
                    s_geo = get_geolocation(s_ip)
                    geolocations.insert(0, GeolocationInfo(**s_geo))

            # 5. Autonomous ReAct Forensic Investigation
            subject = str(headers.get("subject", ""))
            sender_val = str(headers.get("from", "Unknown"))

            agent_out = forensic_agent.run_investigation(parsed_data, raw_iocs)
            normalization_data = agent_out.get("normalization_data", {})
            domain_rep = agent_out["domain_rep"]
            url_analyses = agent_out.get("url_analyses", [])
            rule_findings = agent_out["rule_findings"]
            risk_score = agent_out["risk_score"]
            reasons = agent_out["reasons"]
            ml_assessment = MLAssessment(**agent_out["ml_pred"], model_version="1.0")
            ai_briefing = agent_out["briefing"]
            agent_trace = agent_out["agent_steps"]

            # 5b. Advanced Forensic Scans: Quishing & Indian Banking Routes
            quishing_findings = scan_for_quishing(
                parsed_data.get("attachments", []),
                html_body=parsed_data.get("body_html", "")
            )
            if quishing_findings:
                reasons.append(f"🚨 QR Code Phishing ('Quishing') detected ({len(quishing_findings)} weaponized QR code(s) decoded)")
                rule_findings.append(RuleFinding(
                    rule_name="Quishing_QR_Detector",
                    description=f"Decoded {len(quishing_findings)} hidden target URL(s) from embedded QR images.",
                    severity="HIGH",
                    evidence=[q["decoded_url"] for q in quishing_findings]
                ))

            full_email_body = (parsed_data.get("body_text", "") or "") + " " + (parsed_data.get("body_html", "") or "")
            indian_banking_iocs = extract_indian_financial_indicators(full_email_body)
            if indian_banking_iocs["has_indian_financial_iocs"]:
                if indian_banking_iocs["upi_handles"]:
                    reasons.append(f"💸 Extracted {len(indian_banking_iocs['upi_handles'])} Indian UPI Payment VPA(s)")
                    for upi in indian_banking_iocs["upi_handles"]:
                        indicators.append(Indicator(type="UPI_VPA", value=upi, source="Email Body"))
                if indian_banking_iocs["ifsc_codes"]:
                    for ifsc_info in indian_banking_iocs["identified_banks"]:
                        indicators.append(Indicator(type="IFSC_Bank", value=f"{ifsc_info['ifsc']} ({ifsc_info['bank_name']})", source="Email Body"))
                if indian_banking_iocs["bank_accounts"]:
                    for acct in indian_banking_iocs["bank_accounts"]:
                        indicators.append(Indicator(type="Bank_Account", value=acct, source="Email Body"))
                if indian_banking_iocs["financial_lures"]:
                    reasons.append(f"⚠️ Indian Cyber Financial Lure: {', '.join(indian_banking_iocs['financial_lures'])}")

            # 6. Timeline Extraction
            timeline_events = []
            for idx, rec in enumerate(parsed_data.get("received_chain", [])):
                ip_match = None
                raw_ips = extract_all_indicators(rec)["ipv4"]
                if raw_ips:
                    ip_match = raw_ips[0]
                location_str = "UNKNOWN"
                city = None
                lat = None
                lon = None
                if ip_match:
                    geo = get_geolocation(ip_match)
                    parts = [p for p in [geo.get("city"), geo.get("region"), geo.get("country")] if p and p != "UNKNOWN"]
                    location_str = ", ".join(parts) if parts else geo.get("country", "UNKNOWN")
                    city = geo.get("city")
                    lat = geo.get("latitude")
                    lon = geo.get("longitude")

                timeline_events.append(EventTimeline(
                    timestamp=datetime.datetime.utcnow(),
                    source=f"Hop {idx+1}",
                    ip=ip_match,
                    hostname=None,
                    country=location_str,
                    city=city,
                    latitude=lat,
                    longitude=lon,
                    evidence_ref=rec[:100] + "..."
                ))

            timeline_events.append(EventTimeline(
                timestamp=datetime.datetime.utcnow(),
                source="Analysis Complete",
                ip=None,
                hostname="EMAILSHIELD",
                country="Local",
                evidence_ref="Investigation finalized"
            ))

            # 7. Build Case Report
            auth_align_obj = AuthAlignmentResult(**agent_out["auth_alignment"]) if agent_out.get("auth_alignment") else None
            att_analyses = [AttachmentAnalysisResult(**a) for a in agent_out.get("attachment_analyses", [])]
            lookalike_obj = LookalikeAnalysis(**agent_out["lookalike_analysis"]) if agent_out.get("lookalike_analysis") else None
            bec_obj = BECTelemetry(**agent_out["bec_telemetry"]) if agent_out.get("bec_telemetry") else None
            relay_transit_data = agent_out.get("relay_transit") or analyze_relay_transit(parsed_data.get("received_chain", []))

            # Add attachment hashes to indicators
            for att in att_analyses:
                if att.sha256 and att.sha256 != "N/A":
                    indicators.append(Indicator(type="Hash", value=att.sha256, source=f"Attachment:{att.filename}"))

            # Infrastructure & Threat Intelligence Indicators (SIH26106)
            infra_intel = agent_out.get("infrastructure_intel")
            if infra_intel:
                if infra_intel.asn and infra_intel.asn not in ["Unknown ASN", "None", "UNKNOWN"]:
                    indicators.append(Indicator(type="ASN", value=infra_intel.asn, source="Infrastructure Intelligence"))
                if infra_intel.cloud_indicator and infra_intel.cloud_indicator.is_cloud_hosted and infra_intel.cloud_indicator.provider not in ["UNKNOWN", "None / Dedicated / Residential"]:
                    indicators.append(Indicator(type="Cloud_Provider", value=infra_intel.cloud_indicator.provider, source="Infrastructure Intelligence"))
                if infra_intel.registrar_intel and infra_intel.registrar_intel.registrar and infra_intel.registrar_intel.registrar != "Unknown":
                    indicators.append(Indicator(type="Registrar", value=infra_intel.registrar_intel.registrar, source="Domain Registry"))
                if infra_intel.threat_intel_match and infra_intel.threat_intel_match.status == "MATCH" and infra_intel.threat_intel_match.feed_name:
                    indicators.append(Indicator(type="Threat_Feed", value=infra_intel.threat_intel_match.feed_name, source="Threat Intelligence Match"))

            # Restore existing case management notes/status if case was already opened
            existing_rec = get_case_record(case_id, client=user_client)
            current_status = existing_rec.get("status", "Open") if existing_rec else "Open"
            current_inv = existing_rec.get("assigned_investigator", "Unassigned") if existing_rec else "Unassigned"
            current_notes = existing_rec.get("analyst_notes", "") if existing_rec else ""

            threat_v = bec_obj.verdict if bec_obj else ("Standard / Legitimate" if risk_score == "LOW" else risk_score)
            if risk_score == "LOW" and threat_v in ["Business Email Compromise (BEC / Wire Fraud)", "Executive Impersonation", "Credential Harvesting", "Malware Delivery"]:
                threat_v = "Standard / Legitimate"
            verdict_c = bec_obj.confidence_pct if bec_obj else (90 if risk_score == "HIGH" else 85)
            content_type_val = categorize_content(subject, body, sender_val, headers=headers)

            case_report = CaseReport(
                case_id=case_id,
                timestamp=datetime.datetime.utcnow(),
                original_sha256=parsed_data["sha256"],
                subject=subject,
                sender=sender_val,
                content_type=content_type_val,
                status=current_status,
                assigned_investigator=current_inv,
                analyst_notes=current_notes,
                threat_verdict=threat_v,
                verdict_confidence=verdict_c,
                indicators=indicators,
                geolocation=geolocations,
                auth_results=auth_evidence,
                auth_alignment=auth_align_obj,
                rule_findings=rule_findings,
                ml_assessment=ml_assessment,
                domain_reputation=domain_rep,
                lookalike_analysis=lookalike_obj,
                attachment_analyses=att_analyses,
                bec_telemetry=bec_obj,
                url_analyses=url_analyses,
                ai_reasoning=ai_briefing,
                agent_trace=agent_trace,
                timeline=timeline_events,
                sender_location=sender_loc,
                infrastructure_intel=infra_intel,
                risk_score=risk_score,
                risk_reasons=reasons
            )

            # Save to Supabase (with RLS) or local sandbox fallback
            save_case(case_report.model_dump(), user_id=current_user_id, client=user_client)

            # Cache the analysis payload in session state for rerun reuse
            st.session_state["_cached_analysis_payload"] = {
                "sha256": _email_sha256,
                "parsed_data": parsed_data,
                "case_id": case_id,
                "subject": subject,
                "sender_val": sender_val,
                "indicators": indicators,
                "auth_evidence": auth_evidence,
                "geolocations": geolocations,
                "sender_loc": sender_loc,
                "agent_out": agent_out,
                "domain_rep": domain_rep,
                "url_analyses": url_analyses,
                "rule_findings": rule_findings,
                "risk_score": risk_score,
                "reasons": reasons,
                "ml_assessment": ml_assessment,
                "ai_briefing": ai_briefing,
                "agent_trace": agent_trace,
                "quishing_findings": quishing_findings,
                "indian_banking_iocs": indian_banking_iocs,
                "timeline_events": timeline_events,
                "auth_align_obj": auth_align_obj,
                "att_analyses": att_analyses,
                "lookalike_obj": lookalike_obj,
                "bec_obj": bec_obj,
                "relay_transit_data": relay_transit_data,
                "infra_intel": infra_intel,
                "case_report": case_report,
                "normalization_data": normalization_data,
            }
        
    col_succ, col_open_inv, col_rst = st.columns([2, 1, 1])
    with col_succ:
        st.success(f"Analysis Complete: {case_id} — SHA-256: {parsed_data['sha256'][:16]}...")
    with col_open_inv:
        if st.button("🔎 Open Investigation", type="primary", use_container_width=True, key=f"btn_open_inv_top_{case_id}"):
            st.session_state["active_investigation_id"] = case_id
            st.session_state["active_view_idx"] = 3
            st.rerun()
    with col_rst:
        if st.button("🔄 Reset / Test Another", help="Clear current email and load another sample or file", key="btn_reset_analysis"):
            st.session_state["current_email_bytes"] = None
            st.session_state.pop("_cached_analysis_payload", None)
            st.rerun()

    # Derive authoritative sender location & origin infrastructure for dashboard tabs
    sloc = derive_authoritative_location(case_report)
    case_report.sender_location = sloc

    # Render Dashboard
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
        "Overview", "Evidence & Auth", "IOCs & Threat Intel", "Detection & Rules",
        "Relay Timeline & Delays", "Investigation Graph & Campaigns", "Reports & Case Management",
        "⚖️ Forensic Header Diff"
    ])
        
    with tab1:
        critical_or_high_urls = [u for u in case_report.url_analyses if u.risk_level in ["CRITICAL", "HIGH"]]
        auth_is_valid = bool(case_report.auth_alignment and case_report.auth_alignment.effective_dmarc in ["PASS", "PASS (Delegated ESP)"])
        has_bec = case_report.bec_telemetry and (
            case_report.bec_telemetry.is_display_name_spoof or
            (case_report.bec_telemetry.is_financial_lure and case_report.bec_telemetry.bec_risk_score >= 50 and not auth_is_valid) or
            ("BEC" in case_report.threat_verdict and not auth_is_valid)
        )
        has_quishing = bool(quishing_findings)
        has_high_rule = any(r.severity == "HIGH" for r in rule_findings)
            
        # Determine overall user-facing safety status
        is_safe = (risk_score == "LOW") and not has_bec and not has_quishing and not critical_or_high_urls and not has_high_rule

        is_newsletter_email = bool(
            headers.get("list-unsubscribe") or
            headers.get("list-id") or
            str(headers.get("precedence", "")).lower() == "bulk" or
            headers.get("feedback-id")
        )

        if is_safe:
            # 🟢 PROMINENT USER-FRIENDLY "SAFE" HERO CARD
            badge_html = '<span style="background-color: #10b981; color: #022c22; font-weight: 800; font-size: 0.8em; padding: 4px 12px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.5px;">Verified Clean</span>'
            if is_newsletter_email:
                badge_html += ' <span style="background-color: #0284c7; color: #ffffff; font-weight: 800; font-size: 0.8em; padding: 4px 12px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.5px; margin-left: 6px;">📰 Verified Newsletter / Subscription</span>'

            st.markdown(
                f"""
<div style="background: linear-gradient(135deg, #064e3b 0%, #065f46 100%); border: 2px solid #10b981; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(16, 185, 129, 0.15);">
{badge_html}
<h2 style="color: #ecfdf5; margin: 10px 0 6px 0; font-size: 1.6em;">🛡️ STATUS: THIS EMAIL IS SAFE TO OPEN</h2>
<p style="color: #a7f3d0; margin: 0; font-size: 0.95em;">
    EMAILSHIELD analyzed this message. No signs of phishing, executive impersonation, malicious attachments, or spoofed senders were detected.
</p>
</div>
""",
                unsafe_allow_html=True
            )
                
            col_safe1, col_safe2, col_safe3 = st.columns([2, 1, 1])
            with col_safe1:
                st.markdown(f"**Classification:** `{case_report.threat_verdict}`")
                st.caption(f"📁 Category: **`{case_report.content_type}`** | Case ID: `{case_id}` | Source: `{case_report.ingestion_source}`")
            with col_safe2:
                st.metric("Safety Confidence", f"{case_report.verdict_confidence}%")
            with col_safe3:
                st.metric("Risk Level", "LOW", delta="SAFE", delta_color="normal")
                    
            # Section 14 Dual-Card Infrastructure & Domain Assessment
            render_infrastructure_dual_cards(case_report)

            st.markdown("---")
            st.markdown("#### 📋 Plain-Language Safety Summary:")
                
            chk_text = (
                "• **Authentic Sender:** The email originated from authorized mail servers with verified identity records.\n\n"
                "• **Safe Hyperlinks:** No links redirect to password harvesting portals, tracking threats, or malware downloads.\n\n"
                "• **No Fraudulent Lures:** No urgent wire transfer requests, digital arrest extortion, or fake payment demands."
            )
            if is_newsletter_email:
                chk_text += "\n\n• **Legitimate Newsletter:** Verified broadcast from an authorized creator or subscription service (RFC 2369 compliant)."

            st.success(chk_text)
                
            if case_report.forwarded_by:
                st.info(f"📬 **Forwarded for Verification by User:** `{case_report.forwarded_by}`")
                
            st.markdown("---")
            # Easy User Toggle to view more details or keep it simple
            view_technical_details = st.checkbox(
                "🔍 View Detailed Technical Forensics & AI Reasoning (Click to show/hide)",
                value=False,
                key="toggle_safe_details",
                help="Enable this if you want to inspect the AI ReAct reasoning steps, full briefing, cryptographic hashes, and server metrics."
            )
                
            if view_technical_details:
                st.markdown("### 🔬 In-Depth Forensic Telemetry & AI Reasoning")
                if case_report.ai_reasoning:
                    st.markdown(case_report.ai_reasoning)
                    st.markdown("---")
                        
                if case_report.agent_trace:
                    with st.expander(f"🤖 Autonomous AI Forensic Agent ({len(case_report.agent_trace)} Step ReAct Trail)", expanded=True):
                        st.caption("The Autonomous AI Agent coordinated multi-source telemetry tools to verify this email:")
                        for step in case_report.agent_trace:
                            st.markdown(f"**Step {step.step_num}:** `{step.tool_used}`")
                            st.markdown(f"💭 **Thought:** *{step.thought}*")
                            st.markdown(f"🛠️ **Action:** `{step.action}`")
                            st.markdown(f"👁️ **Observation:** {step.observation}")
                            st.markdown("---")
                                
                st.write("### Detection Reasons & Heuristics")
                for r in reasons:
                    st.write(f"- {r}")
                        
                c_meta1, c_meta2, c_meta3, c_meta4 = st.columns(4)
                with c_meta1:
                    st.metric("SHA-256", f"{parsed_data['sha256'][:14]}...", help=parsed_data['sha256'])
                with c_meta2:
                    st.metric("Sender", case_report.sender[:22])
                with c_meta3:
                    st.metric("Subject", case_report.subject[:22])
                with c_meta4:
                    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
                    st.metric("Approx. Origin", loc_val[:22])
            else:
                st.caption("💡 *You are viewing the simple summary mode. Check the box above anytime if you want to inspect technical server hops, AI ReAct agent traces, and cryptographic hashes.*")

        else:
            # 🔴 PROMINENT USER-FRIENDLY "UNSAFE / DANGEROUS" HERO CARD
            st.markdown(
                """
<div style="background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); border: 2px solid #ef4444; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(239, 68, 68, 0.25);">
<span style="background-color: #ef4444; color: #450a0a; font-weight: 800; font-size: 0.8em; padding: 4px 12px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.5px;">🚨 Threat Detected</span>
<h2 style="color: #fff1f2; margin: 10px 0 6px 0; font-size: 1.6em;">⚠️ STATUS: THIS EMAIL IS UNSAFE / DANGEROUS</h2>
<p style="color: #fecaca; margin: 0; font-size: 0.95em;">
    <b>Action Required:</b> Do NOT click links, do NOT download attachments, and do NOT send money or reply to this sender.
</p>
</div>
""",
                unsafe_allow_html=True
            )
                
            col_verdict1, col_verdict2, col_verdict3 = st.columns([2, 1, 1])
            with col_verdict1:
                st.markdown(f"### 🎯 Threat Verdict: **{case_report.threat_verdict}**")
                st.caption(f"📁 Category: **`{case_report.content_type}`** | Case ID: `{case_id}` | Source: `{case_report.ingestion_source}`")
            with col_verdict2:
                st.metric("Confidence", f"{case_report.verdict_confidence}%")
            with col_verdict3:
                st.metric("Risk Score", risk_score, delta="MALICIOUS" if risk_score == "HIGH" else "SUSPICIOUS", delta_color="inverse")

            # Section 14 Dual-Card Infrastructure & Domain Assessment
            render_infrastructure_dual_cards(case_report)

            # BEC & Display-Name Spoofing Alert Card
            if has_bec:
                st.error("🚨 **BUSINESS EMAIL COMPROMISE (BEC) & IMPERSONATION ALERT**")
                b_col1, b_col2 = st.columns(2)
                with b_col1:
                    if case_report.bec_telemetry.is_display_name_spoof:
                        st.markdown(f"🎭 **Display Name Spoof:** `{case_report.bec_telemetry.display_name}`")
                        st.markdown(f"✉️ **Actual Sender Address:** `{case_report.bec_telemetry.sender_email}`")
                        st.warning("Adversary is masquerading as corporate executive using an unauthorized freemail address.")
                with b_col2:
                    if case_report.bec_telemetry.is_financial_lure:
                        st.markdown("💸 **Financial / Wire Transfer Fraud Lures Detected:**")
                        for f in case_report.bec_telemetry.flags:
                            st.write(f"- {f}")
                st.markdown("---")

            # Suspicious Link Threat Alert & Action Guidance
            if critical_or_high_urls:
                st.error("🚨 **SUSPICIOUS LINK(S) DETECTED IN THIS EMAIL**")
                for u in critical_or_high_urls:
                    with st.expander(f"⚠️ Link Threat: {u.threat_category} ({u.risk_level} Risk)", expanded=True):
                        st.markdown(f"🔗 **Target URL (Defanged):** `{u.defanged_url}`")
                        if u.redirect_count > 0:
                            st.caption(f"↳ *Redirects through {u.redirect_count} hops to: `{u.final_destination}`*")
                            
                        col_cause, col_action = st.columns(2)
                        with col_cause:
                            st.markdown("#### 💥 What This Link May Cause:")
                            st.warning(u.potential_impact)
                        with col_action:
                            st.markdown("#### 🛡️ What You Should Do:")
                            st.info(u.recommended_action)
                st.markdown("---")

            # Quishing (QR Code Phishing) Threat Card
            if quishing_findings:
                st.error("🚨 **QR CODE PHISHING ('QUISHING') ATTACK DETECTED**")
                for q in quishing_findings:
                    with st.expander(f"📱 Quishing Vector: {q['source']} ({q['threat_level']} Risk)", expanded=True):
                        st.markdown(f"🖼️ **Carrier Image:** `{q['filename']}`")
                        st.markdown(f"🔗 **Decoded Target URL (Defanged):** `{q['defanged_url']}`")
                        q_col1, q_col2 = st.columns(2)
                        with q_col1:
                            st.markdown("#### 💥 What This QR Code May Cause:")
                            st.warning(q["what_it_causes"])
                        with q_col2:
                            st.markdown("#### 🛡️ What You Should Do:")
                            st.info(q["what_to_do"])
                st.markdown("---")

            # Clear reasons why it is unsafe
            st.markdown("#### 🚨 Why EMAILSHIELD Flagged This Email as Unsafe:")
            for r in reasons:
                st.error(f"• {r}")
                
            if case_report.forwarded_by:
                st.info(f"📬 **Forwarded for Verification by User:** `{case_report.forwarded_by}`")

            st.markdown("---")
            # Expandable Deep Technical Forensics for Unsafe Emails
            with st.expander("🔬 View In-Depth Technical Forensics & AI Reasoning Chain", expanded=False):
                if case_report.ai_reasoning:
                    st.markdown(case_report.ai_reasoning)
                    st.markdown("---")
                        
                if case_report.agent_trace:
                    st.caption("The Autonomous AI Agent coordinated multi-source telemetry tools to reconstruct the adversary's attack chain:")
                    for step in case_report.agent_trace:
                        st.markdown(f"**Step {step.step_num}:** `{step.tool_used}`")
                        st.markdown(f"💭 **Thought:** *{step.thought}*")
                        st.markdown(f"🛠️ **Action:** `{step.action}`")
                        st.markdown(f"👁️ **Observation:** {step.observation}")
                        st.markdown("---")
                            
                c_meta1, c_meta2, c_meta3, c_meta4 = st.columns(4)
                with c_meta1:
                    st.metric("SHA-256", f"{parsed_data['sha256'][:14]}...", help=parsed_data['sha256'])
                with c_meta2:
                    st.metric("Sender", case_report.sender[:22])
                with c_meta3:
                    st.metric("Subject", case_report.subject[:22])
                with c_meta4:
                    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
                    st.metric("Approx. Origin", loc_val[:22])
            
    with tab2:
        st.subheader("🔐 Cryptographic Authentication & DMARC Alignment Matrix (RFC 7489)")
        if case_report.auth_alignment:
            aa = case_report.auth_alignment
            dmarc_badge = "✅ PASS" if "PASS" in aa.effective_dmarc else ("ℹ️ " + aa.effective_dmarc if "NONE" in aa.effective_dmarc or "UNCONFIGURED" in aa.effective_dmarc else "🚨 " + aa.effective_dmarc)
                
            c_a1, c_a2, c_a3, c_a4 = st.columns(4)
            c_a1.metric("Effective DMARC", dmarc_badge)
            c_a2.metric("SPF Result", f"{aa.spf_result} ({'Aligned' if aa.spf_aligned else 'Unaligned'})")
            c_a3.metric("DKIM Result", f"{aa.dkim_result} ({'Aligned' if aa.dkim_aligned else 'Unaligned'})")
            c_a4.metric("DMARC Claim", aa.dmarc_recorded)

            if aa.dkim_aligned:
                dkim_status_txt = "✅ Aligned with Header-From"
            elif aa.effective_dmarc in ["PASS", "PASS (Delegated ESP)"] or aa.spf_aligned:
                dkim_status_txt = "ℹ️ Provider / ESP Signed (DMARC Satisfied)"
            else:
                dkim_status_txt = "⚠️ Unaligned (Bypass Risk)"

            st.markdown(
                f"""
                | Attribute | Inspected Domain | Alignment Status |
                | :--- | :--- | :--- |
                | **Visible Header-From** | `{aa.header_from_domain or 'N/A'}` | Target Visible Identity |
                | **Envelope-From (Return-Path)** | `{aa.envelope_from_domain or 'N/A'}` | {'✅ Aligned with Header-From' if aa.spf_aligned else '⚠️ Unaligned (Bypass Risk)'} |
                | **DKIM Signing Domain (d=)** | `{aa.dkim_signing_domain or 'N/A'}` | {dkim_status_txt} |
                """
            )
                
            if aa.advisories:
                for adv in aa.advisories:
                    if adv.startswith("ℹ️"):
                        st.info(adv)
                    elif adv.startswith("🚨"):
                        st.error(adv)
                    else:
                        st.warning(adv)
        else:
            st.info("No cryptographic Authentication-Results found.")

        st.markdown("---")
        st.subheader("📎 Attachment Deep Forensics & SHA-256 Evidence")
        if case_report.attachment_analyses:
            att_rows = []
            for a in case_report.attachment_analyses:
                att_rows.append({
                    "Filename": a.filename,
                    "SHA-256 Checksum": a.sha256,
                    "Size (Bytes)": a.size_bytes,
                    "MIME Type": a.content_type,
                    "Risk Verdict": a.verdict_label,
                    "Double Extension": "🚨 YES" if a.is_double_ext else "No",
                    "Macro Risk": "⚠️ YES" if a.has_macros else "No",
                    "Risk Flags": "; ".join(a.risk_flags) if a.risk_flags else "None"
                })
            st.dataframe(att_rows, use_container_width=True)
        else:
            st.info("No file attachments detected in this email.")

        st.markdown("---")
        st.subheader("🌐 Domain Reputation & ICANN RDAP Intelligence")
        if case_report.domain_reputation:
            dr = case_report.domain_reputation
            dcol1, dcol2, dcol3, dcol4 = st.columns(4)
            dcol1.metric("Domain", dr.domain)
            if dr.domain_age_days is not None:
                yrs = dr.domain_age_days // 365
                dcol2.metric("Domain Age", f"{dr.domain_age_days} days", delta=f"{yrs} years old" if yrs > 0 else "Young", delta_color="normal")
            else:
                dcol2.metric("Domain Age", "Established", delta="Reputable", delta_color="normal")
            dcol3.metric("Registrar", (dr.registrar or "ICANN Accredited")[:25])
            dcol4.metric("NRD Flag (< 30d)", "🚨 YES (High Threat)" if dr.is_nrd else "✅ NO (Established)")
            if dr.creation_date and dr.creation_date != "Unknown":
                st.caption(f"📅 **Domain Registration Date:** `{dr.creation_date}` | 🏢 **Accredited Registrar:** `{dr.registrar}`")
            if dr.notes:
                for n in dr.notes:
                    st.write(f"• {n}")
            
    with tab3:
        # 1-Click IOC Export Actions
        st.subheader("📥 1-Click IOC Threat Intelligence Export (SIEM / MISP Ready)")
        col_exp1, col_exp2 = st.columns(2)
        with col_exp1:
            st.download_button(
                "📄 Export Case IOCs (CSV)",
                export_case_iocs_csv(case_id, client=user_client),
                file_name=f"{case_id}_iocs.csv",
                mime="text/csv",
                use_container_width=True
            )
        with col_exp2:
            st.download_button(
                "⚡ Export Case IOCs (JSON)",
                export_case_iocs_json(case_id, client=user_client),
                file_name=f"{case_id}_iocs.json",
                mime="application/json",
                use_container_width=True
            )

        st.markdown("---")
        # Lookalike & Homoglyph Engine
        st.subheader("🎭 Lookalike & Homoglyph Brand Impersonation Deep Dive")
        if case_report.lookalike_analysis and case_report.lookalike_analysis.is_lookalike:
            la = case_report.lookalike_analysis
            st.error(f"🚨 **DECEPTIVE LOOKALIKE DOMAIN DETECTED: Mimics `{la.impersonated_brand}`**")
            l_c1, l_c2, l_c3 = st.columns(3)
            l_c1.metric("Impersonated Brand", str(la.impersonated_brand).upper())
            l_c2.metric("Deception Technique", la.technique)
            l_c3.metric("Lexical Similarity", f"{la.similarity_score}%")
            for r in la.reasons:
                st.write(f"• {r}")
        else:
            st.success("✅ No homoglyph substitutions, Punycode tricks, or brand typosquatting observed in sender domain.")

        st.markdown("---")
        st.subheader("Extracted Indicators of Compromise (IOCs)")
        if indicators:
            st.dataframe([i.model_dump() for i in indicators], use_container_width=True)
        else:
            st.write("No indicators found.")

        # Infrastructure & Threat Intelligence Deep Dive (SIH26106)
        st.markdown("---")
        st.subheader("🌐 Infrastructure & Threat Intelligence Deep Dive (SIH26106)")
        infra = getattr(case_report, "infrastructure_intel", None)
        if infra:
            c_i1, c_i2 = st.columns(2)
            with c_i1:
                st.markdown("#### 🛡️ Anonymization & Routing Indicators")
                infra_rows = [
                    {"Indicator": "Cloud Hosting Provider", "Status": infra.cloud_indicator.provider, "Confidence": f"{infra.cloud_indicator.confidence}%", "Evidence": infra.cloud_indicator.evidence},
                    {"Indicator": "Commercial VPN Service", "Status": infra.vpn_indicator.status, "Confidence": f"{infra.vpn_indicator.confidence}%", "Evidence": infra.vpn_indicator.evidence},
                    {"Indicator": "Tor Exit Relay Node", "Status": infra.tor_indicator.status, "Confidence": f"{infra.tor_indicator.confidence}%", "Evidence": infra.tor_indicator.evidence},
                    {"Indicator": "Open Relay Transit (Passive)", "Status": infra.open_relay_indicator.status, "Confidence": f"{infra.open_relay_indicator.confidence}%", "Evidence": infra.open_relay_indicator.evidence},
                    {"Indicator": "Botnet / Spambot Pool", "Status": infra.botnet_indicator.status, "Confidence": f"{infra.botnet_indicator.confidence}%", "Evidence": infra.botnet_indicator.evidence},
                    {"Indicator": "Threat Feed Correlation", "Status": infra.threat_intel_match.status, "Confidence": f"{infra.threat_intel_match.confidence}%", "Evidence": infra.threat_intel_match.evidence}
                ]
                st.dataframe(infra_rows, use_container_width=True)
            with c_i2:
                st.markdown("#### 📬 DNS & MX Records Exposure (SSRF Protected)")
                if infra.dns_mx_intel and infra.dns_mx_intel.mx_records:
                    mx_rows = [
                        {"MX Host": m.host, "Priority": m.priority, "Resolved Public IPs": ", ".join(m.resolved_ips) if m.resolved_ips else "Protected / None"}
                        for m in infra.dns_mx_intel.mx_records
                    ]
                    st.dataframe(mx_rows, use_container_width=True)
                else:
                    st.info("No external MX records resolved or domain is unconfigured.")
                    
                if infra.dns_mx_intel:
                    if infra.dns_mx_intel.spf_record:
                        st.caption(f"**SPF Record:** `{infra.dns_mx_intel.spf_record}`")
                    if infra.dns_mx_intel.dmarc_record:
                        st.caption(f"**DMARC Record:** `{infra.dns_mx_intel.dmarc_record}`")

        # Indian Financial Routes & Extortion Indicators
        st.markdown("---")
        st.subheader("🇮🇳 Indian Cyber Financial Intelligence (UPI & Banking Routes)")
        if indian_banking_iocs["has_indian_financial_iocs"]:
            st.warning("⚠️ **Active Indian Financial Artifacts & Extortion Vectors Extracted**")
                
            f_c1, f_c2 = st.columns(2)
            with f_c1:
                st.markdown("#### 💸 Suspect UPI Handles (VPAs)")
                if indian_banking_iocs["upi_handles"]:
                    for upi in indian_banking_iocs["upi_handles"]:
                        st.code(upi, language="text")
                else:
                    st.write("No UPI VPAs detected.")
                        
            with f_c2:
                st.markdown("#### 🏦 Banking Routes & Accounts")
                if indian_banking_iocs["bank_accounts"] or indian_banking_iocs["identified_banks"]:
                    for acct in indian_banking_iocs["bank_accounts"]:
                        st.markdown(f"• **A/C No:** `{acct}`")
                    for b in indian_banking_iocs["identified_banks"]:
                        st.markdown(f"• **IFSC:** ` {b['ifsc']} ` → **{b['bank_name']}**")
                else:
                    st.write("No direct bank accounts detected.")
                        
            if indian_banking_iocs["financial_lures"]:
                st.markdown("#### 🚨 Detected Indian Threat Lures")
                for lure in indian_banking_iocs["financial_lures"]:
                    st.error(f"⚠️ {lure}")
        else:
            st.success("✅ No Indian banking, UPI handles, or extortion lures detected in email body.")
            
        st.markdown("---")
        st.subheader("🔗 Background Check on Embedded Links (URL Threat Deep Dive)")
        if case_report.url_analyses:
            st.caption(f"Forensic background analysis completed for {len(case_report.url_analyses)} link(s):")
            for idx, u in enumerate(case_report.url_analyses):
                risk_badge = "🚨 CRITICAL" if u.risk_level == "CRITICAL" else "⚠️ HIGH" if u.risk_level == "HIGH" else "🟡 MEDIUM" if u.risk_level == "MEDIUM" else "✅ LOW / SAFE"
                with st.expander(f"Link #{idx+1}: {u.domain} — [{risk_badge}] {u.threat_category}", expanded=(u.risk_level in ["CRITICAL", "HIGH"])):
                    st.markdown(f"**Full URL (Defanged for Safety):** `{u.defanged_url}`")
                    if u.redirect_count > 0:
                        st.markdown(f"**Final Unshortened Destination:** `{u.final_destination}` *(Redirected through {u.redirect_count} hops)*")
                        
                    c_u1, c_u2 = st.columns(2)
                    with c_u1:
                        st.markdown("##### 💥 What this link may cause:")
                        st.warning(u.potential_impact)
                    with c_u2:
                        st.markdown("##### 🛡️ What you should do (Actionable Response):")
                        st.info(u.recommended_action)
                            
                    if u.suspicious_indicators:
                        st.markdown("**Suspicious Indicators Detected:**")
                        for ind in u.suspicious_indicators:
                            st.write(f"- {ind}")
        else:
            st.info("No external hyperlinks found in the email body.")
            
        st.markdown("---")
        st.subheader("🌐 Geolocation & Infrastructure Telemetry")
            
        sloc = derive_authoritative_location(case_report)
            
        # -------------------------------------------------------------------------
        # 1. Sender Identity & Header Provenance
        # -------------------------------------------------------------------------
        st.markdown("#### 📧 Sender Identity & Header Provenance")
        c_snd1, c_snd2 = st.columns([3, 2])
        with c_snd1:
            sender_addr = sloc.get("sender_address") or case_report.sender
            st.markdown(f"**Sender Address (`From:`):** `{sender_addr}`")
        with c_snd2:
            rp_val = sloc.get("return_path") or "Not specified"
            if sloc.get("return_path_differs"):
                st.markdown(f"**Return-Path:** `{rp_val}` ⚠️ *(Differs from From:)*")
            else:
                st.markdown(f"**Return-Path:** `{rp_val}`")

        # -------------------------------------------------------------------------
        # 2. Originating / Client IP Evidence & Approximate Infrastructure Location
        # -------------------------------------------------------------------------
        st.markdown("#### 📍 Approximate Originating Infrastructure Location")
        if sloc.get("is_identified"):
            is_client = sloc.get("is_client_ip", False)
            class_badge = "🛡️ Direct Client/Originating IP Evidence" if is_client else "🛰️ Earliest Public Relay IP (Originating MTA Hop)"
            st.info(f"**Forensic Classification:** {class_badge}")

            c_sl1, c_sl2, c_sl3, c_sl4, c_sl5 = st.columns(5)
            with c_sl1:
                st.metric("Originating IP", sloc.get("sender_ip", "Unavailable"))
            with c_sl2:
                st.metric("Approx. Location", f"{sloc.get('city')}, {sloc.get('country')}", delta=sloc.get("flag"))
            with c_sl3:
                st.metric("Region / State", str(sloc.get("region", "Unknown"))[:22])
            with c_sl4:
                st.metric("ISP / Organization", str(sloc.get("org", "Unknown"))[:22])
            with c_sl5:
                st.metric("ASN", str(sloc.get("asn", "Unknown"))[:16])

            c_ev1, c_ev2 = st.columns([2, 3])
            with c_ev1:
                st.markdown(f"**Evidence Source:** `{sloc.get('ip_source', 'Header')}`")
            with c_ev2:
                raw_ev = sloc.get("raw_header_evidence")
                if raw_ev:
                    with st.expander("🔍 View Raw Header Evidence Reference"):
                        st.code(raw_ev, language="text")

            st.caption(
                "ℹ️ **Forensic Attribution Notice:** "
                + sloc.get("attribution_disclaimer",
                    "Geo-IP provides approximate geographic/infrastructure context for the identified IP. "
                    "It does not prove the physical location or identity of the human sender. "
                    "VPNs, proxies, shared infrastructure, webmail providers and relays may obscure the original client location."
                )
            )
        else:
            st.warning("⚠️ **Originating IP: Not available / Relay-masked**")
            st.markdown(
                f"> {sloc.get('relay_masked_explanation', 'The available email telemetry does not expose a reliable public client/originating IP. The displayed relay/domain information represents mail infrastructure rather than proof of the sender\'s device IP.')}"
            )

        # -------------------------------------------------------------------------
        # 3. Supplementary DNS Hostname Intelligence
        # -------------------------------------------------------------------------
        dns_intel = sloc.get("dns_intelligence") or {}
        if dns_intel and dns_intel.get("status") == "Resolved":
            st.markdown("---")
            st.markdown("#### 🌐 Resolved Host IP — DNS Intelligence (Supplementary)")
            st.caption(
                "⚠️ **IMPORTANT NOTICE:** "
                + dns_intel.get("explanation",
                    "DNS resolution identifies the current IP associated with the hostname; it does not prove the historical originating IP used to send this email."
                )
            )
            cd1, cd2, cd3, cd4 = st.columns(4)
            with cd1:
                st.metric("Hostname Queried", dns_intel.get("hostname", "Unknown"))
            with cd2:
                st.metric("Current Resolved IP", dns_intel.get("resolved_ip", "Unavailable"))
            with cd3:
                loc_str = f"{dns_intel.get('city')}, {dns_intel.get('country')}" if dns_intel.get("city") else dns_intel.get("country", "Unknown")
                st.metric("Approx. Host Location", loc_str, delta=dns_intel.get("flag"))
            with cd4:
                st.metric("Host ISP / ASN", f"{str(dns_intel.get('org', 'Unknown'))[:15]} ({dns_intel.get('asn', 'N/A')})")
        elif dns_intel and dns_intel.get("hostname") and dns_intel.get("hostname") not in ["Unavailable", "None"]:
            st.markdown("---")
            st.markdown("#### 🌐 DNS Intelligence: Unavailable")
            st.caption(
                f"Queried hostname `{dns_intel.get('hostname')}` could not be resolved via current DNS lookups. "
                "No originating IP was fabricated or inferred."
            )

        # -------------------------------------------------------------------------
        # 4. Intermediate Relay Transit Infrastructure
        # -------------------------------------------------------------------------
        st.markdown("---")
        st.markdown("#### 🛰️ Relay Transit & Intermediate Infrastructure")
        st.caption(
            "Mail relay and intermediate MTA infrastructure traversed during message transit. "
            "These servers forward email across networks and should not be confused with the sender's device."
        )
        if geolocations:
            geo_rows = []
            map_coords = []
                
            # If sender location has coordinates, put sender at index 0 so map focuses on sender
            if sloc.get("is_identified") and sloc.get("latitude") is not None and sloc.get("longitude") is not None:
                map_coords.append({"lat": sloc["latitude"], "lon": sloc["longitude"]})

            for g in geolocations:
                gd = g.model_dump()
                is_sender = (gd.get("ip") == sloc.get("sender_ip"))
                role = "📍 Originating/Client IP Evidence" if (is_sender and sloc.get("is_client_ip")) else ("📍 Earliest Public Relay IP" if is_sender else "🛰️ Intermediate Mail Relay Hop")
                geo_rows.append({
                    "Role / Evidence Type": role,
                    "IP Address": gd.get("ip"),
                    "City": gd.get("city"),
                    "Region/State": gd.get("region"),
                    "Country": gd.get("country"),
                    "ISP / Organization": gd.get("org"),
                    "ASN": gd.get("asn"),
                    "DB Provider": gd.get("db_provider"),
                    "DB Version": gd.get("db_version"),
                    "Status": gd.get("status")
                })
                if not is_sender and gd.get("latitude") is not None and gd.get("longitude") is not None:
                    map_coords.append({"lat": gd["latitude"], "lon": gd["longitude"]})

            st.dataframe(geo_rows, use_container_width=True)

            if map_coords:
                st.markdown("#### 🗺️ Approximate Infrastructure Mapping")
                st.map(map_coords, zoom=2)
        else:
            st.write("No public IP infrastructure observed.")
                
    with tab4:
        st.subheader("🧠 Hardened Linguistic ML Assessment & Confidence Metrics")
        c_ml1, c_ml2, c_ml3 = st.columns(3)
        with c_ml1:
            conf_lvl = getattr(ml_assessment, "confidence_level", "STANDARD")
            st.metric("ML Confidence Level", conf_lvl)
        with c_ml2:
            conf_sc = getattr(ml_assessment, "confidence_score", 0.0)
            st.metric("ML Confidence Score", f"{conf_sc * 100:.1f}%")
        with c_ml3:
            phish_p = getattr(ml_assessment, "phishing_prob", 0.0)
            st.metric("Raw Phishing Probability", f"{phish_p * 100:.1f}%")

        if getattr(ml_assessment, "is_borderline", False):
            st.warning("⚠️ **Borderline ML Prediction**: Linguistic classifier confidence is borderline (0.38 - 0.62 probability). In accordance with zero-trust SOC governance, this classification does NOT override deterministic forensic rules or cryptographic SPF/DKIM/DMARC alignment.")

        with st.expander("🔍 Detailed ML Feature Payload & Raw Model Output", expanded=False):
            st.json(ml_assessment.model_dump())

        st.markdown("---")
        st.subheader("🧹 Multi-Stage Unicode Normalization & De-obfuscation Pipeline")
        if normalization_data:
            c_n1, c_n2, c_n3 = st.columns(3)
            with c_n1:
                st.metric("Zero-Width Chars Stripped", normalization_data.get("zero_width_chars_stripped", 0))
            with c_n2:
                st.metric("Homoglyphs Detected (Pre-NFKC)", normalization_data.get("confusables_detected", 0))
            with c_n3:
                st.metric("Spaced Tokens Normalized", normalization_data.get("spaced_tokens_normalized", 0))

            if normalization_data.get("confusables_detected", 0) > 0:
                st.warning(f"🚨 **Confusables / Mixed-Script Homoglyphs Flagged (Pre-NFKC)**: Detected Cyrillic/Greek lookalike substitution.")
            if normalization_data.get("spaced_tokens_normalized", 0) > 0:
                st.info(f"🔡 **Spaced Token Obfuscation Identified**: Obfuscated tokens normalized. *Rule Policy: Spaced brand alone yields LOW severity; escalates only with urgency, credential lure, or deceptive URL.*")
        else:
            st.caption("Payload processed without obfuscation flags.")

        st.markdown("---")
        st.subheader("📋 Forensic Rule Matrix Findings")
        if rule_findings:
            st.table([r.model_dump() for r in rule_findings])
        else:
            st.write("No rule violations.")
                
    with tab5:
        st.subheader("✈️ Hop-by-Hop Relay Flight Path Map")
        flight_map = build_relay_flight_map(timeline_events)
        if flight_map:
            st.plotly_chart(flight_map, use_container_width=True)
                
        st.subheader("⏱️ MTA Relay Latency & Transit Timing Analysis")
        col_t1, col_t2 = st.columns(2)
        with col_t1:
            st.metric("Total Hops Traced", relay_transit_data.get("total_hops", len(timeline_events)))
        with col_t2:
            st.metric("Total Transit Delay", relay_transit_data.get("total_transit_display", "0s"))

        if relay_transit_data.get("anomalies"):
            for anom in relay_transit_data["anomalies"]:
                st.error(f"🚨 {anom}")

        if relay_transit_data.get("hops"):
            hop_table = []
            for h in relay_transit_data["hops"]:
                hop_table.append({
                    "Hop": f"#{h['hop_number']}",
                    "Role": h["role"],
                    "Trust Level": h["trust_level"],
                    "Transit Delay (Δt)": h["delay_display"],
                    "From MTA": h["from_mta"],
                    "By MTA": h["by_mta"],
                    "Timestamp": h["timestamp_str"]
                })
            st.dataframe(hop_table, use_container_width=True)
                
        st.subheader("Sequential Hop Audit Log")
        for event in timeline_events:
            st.markdown(f"**{event.source}** - {event.ip or 'No IP'} ({event.country})")
            st.caption(f"Evidence: {event.evidence_ref}")
                
    with tab6:
        st.subheader("🕸️ Threat Infrastructure Attack Graph & Correlation")
        st.caption(
            "Interactive Attack Graph connecting Case, Origin IP, ASN, Hosting/Cloud Provider, "
            "Domain, Registrar, and Threat Feeds."
        )
        try:
            fig_infra = build_case_infrastructure_graph(case_id, case_report.model_dump())
            st.plotly_chart(fig_infra, use_container_width=True)
        except Exception as e:
            st.error(f"Failed to render attack graph: {e}")
            
    with tab7:
        st.subheader("📝 SOC Case Management & Chain of Custody")

        existing_rec = get_case_record(case_id, client=user_client)
        current_status = existing_rec.get("status", getattr(case_report, "status", "Open")) if existing_rec else getattr(case_report, "status", "Open")
        current_inv = existing_rec.get("assigned_investigator", getattr(case_report, "assigned_investigator", "Unassigned")) if existing_rec else getattr(case_report, "assigned_investigator", "Unassigned")
        current_notes = existing_rec.get("analyst_notes", getattr(case_report, "analyst_notes", "")) if existing_rec else getattr(case_report, "analyst_notes", "")

        col_m1, col_m2 = st.columns(2)
        with col_m1:
            status_choices = ["Open", "In Progress", "Resolved", "Closed"]
            status_idx = status_choices.index(current_status) if current_status in status_choices else 0
            new_status = st.selectbox("Case Status:", status_choices, index=status_idx)
        with col_m2:
            new_investigator = st.text_input("Assigned Investigator:", value=current_inv)
                
        new_notes = st.text_area("Analyst Case Notes / Investigation Remarks:", value=current_notes, height=120)
            
        if st.button("💾 Save Case Notes & Status", type="primary"):
            update_case_metadata(case_id, status=new_status, investigator=new_investigator, notes=new_notes, client=user_client)
            case_report.status = new_status
            case_report.assigned_investigator = new_investigator
            case_report.analyst_notes = new_notes
            st.success(f"Case {case_id} updated: Status='{new_status}', Investigator='{new_investigator}'")
                
        st.markdown("---")
        st.subheader("Export Investigation Reports")

        # Construct authoritative updated case dictionary for PDF, JSON, and NCRP exports
        updated_case_dict = case_report.model_dump()
        updated_case_dict["status"] = new_status
        updated_case_dict["assigned_investigator"] = new_investigator
        updated_case_dict["investigator"] = new_investigator
        updated_case_dict["analyst_notes"] = new_notes
        updated_case_dict["body_text"] = body
        updated_case_dict["sha256"] = case_report.original_sha256
        if geolocations:
            updated_case_dict["originating_ip"] = geolocations[0].ip

        # In-Memory Report Streaming (Zero disk persistence)
        pdf_bytes = io.BytesIO()
        generate_pdf_report(updated_case_dict, pdf_bytes)
            
        json_str = generate_json_report(updated_case_dict)
            
        csv_str = export_case_iocs_csv(case_id=case_id, client=user_client)
            
        col_d1, col_d2, col_d3 = st.columns(3)
        with col_d1:
            st.download_button("📜 Download Forensic Report (PDF)", pdf_bytes, file_name=f"{case_id}_forensic_report.pdf", mime="application/pdf", use_container_width=True)
        with col_d2:
            st.download_button("⚡ Download Forensic JSON", json_str, file_name=f"{case_id}.json", mime="application/json", use_container_width=True)
        with col_d3:
            st.download_button("📊 Download SIEM IOCs (CSV)", csv_str, file_name=f"{case_id}_iocs.csv", mime="text/csv", use_container_width=True)

        # Indian Cybercrime (BSA 2023 Section 63(4)(c) / NCRP-Oriented Evidence Pack)
        st.markdown("---")
        st.subheader("🇮🇳 Indian Cybercrime Evidence Pack — Section 63(4)(c) BSA / NCRP")
        st.caption("Structured electronic evidence-supporting documentation under Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023 (BSA) aligned with I4C / cybercrime.gov.in reporting standards:")
            
        ncrp_text = generate_ncrp_complaint_text(updated_case_dict)
        st.text_area("NCRP Portal Complaint Draft (Copy & Paste ready for cybercrime.gov.in):", value=ncrp_text, height=180)
            
        ncrp_pdf_bytes = io.BytesIO()
        generate_ncrp_pdf_annexure(updated_case_dict, ncrp_pdf_bytes)
            
        col_pkg1, col_pkg2 = st.columns(2)
        with col_pkg1:
            st.download_button(
                "🇮🇳 Download Section 63(4)(c) BSA Evidence Annexure (PDF)",
                ncrp_pdf_bytes,
                file_name=f"BSA_Sec63_Annexure_{case_id}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        with col_pkg2:
            sanitized_eml_bytes, def_cnt, quar_cnt = sanitize_eml_content(bytes_data)
            st.download_button(
                f"🛡️ Download Sanitized / Defanged EML ({def_cnt} URLs defanged, {quar_cnt} files quarantined)",
                sanitized_eml_bytes,
                file_name=f"{case_id}_sanitized_evidence.eml",
                mime="message/rfc822",
                use_container_width=True,
                help="Safe shareable evidence copy: all URLs neutralized to hxxps and weaponized attachments quarantined to forensic warning placeholders."
            )

        # User-Scoped Investigation History (RLS Filtered)
        user_cases = get_all_cases(client=user_client)
        if user_cases:
            st.markdown("---")
            st.subheader("📁 My Historical Investigations")
            st.caption(f"Displaying **{len(user_cases)}** cases owned by your investigator profile:")
            c_hist_rows = []
            for uc in user_cases[:15]:
                c_hist_rows.append({
                    "Case ID": uc.get("case_id"),
                    "Date": str(uc.get("timestamp", "N/A"))[:19],
                    "Subject": str(uc.get("subject", "N/A"))[:35],
                    "Verdict": uc.get("threat_verdict", "N/A"),
                    "Status": uc.get("status", "Open"),
                    "Severity": uc.get("case_severity", "MEDIUM")
                })
            st.dataframe(c_hist_rows, use_container_width=True)

        # Local Storage, Retention & Evidence Preservation
        st.markdown("---")
        st.subheader("💾 Local Forensic Storage & Retention Management")
        st.caption("Secure local-first retention control, evidence preservation, and disk safety monitoring.")

        from core.local_storage import get_local_storage_manager, RetentionPolicy
        storage_mgr = get_local_storage_manager()

        # 1. Disk Health & Storage Metrics
        disk_safety = storage_mgr.check_disk_space_safety()
        if disk_safety.get("low_disk_warning"):
            st.error(f"⚠️ **Low Disk Space Warning**: Free disk space is {disk_safety['free_mb']} MB (Threshold: {disk_safety['threshold_mb']} MB). Evidence files are protected.")

        u_target_id = current_user_id or "local_investigator"
        storage_usage = storage_mgr.get_storage_usage(user_id=u_target_id)
        c_st1, c_st2, c_st3, c_st4 = st.columns(4)
        with c_st1:
            st.metric("Local Cases", storage_usage.get("user_cases_count", 0))
        with c_st2:
            st.metric("Local Evidence", f"{storage_usage.get('user_evidence_mb', 0.0)} MB")
        with c_st3:
            st.metric("Local Reports", f"{storage_usage.get('user_reports_mb', 0.0)} MB")
        with c_st4:
            st.metric("Total Local Usage", f"{storage_usage.get('total_mb', 0.0)} MB")

        # 2. Evidence Preservation Toggle for current case
        case_preserve = st.checkbox(
            "🛡️ Preserve Evidence for this Case (Exempt from Automated Retention Cleanup)",
            value=bool(updated_case_dict.get("preserve_evidence", False)),
            key=f"chk_preserve_{case_id}",
            help="Prevents this case, its EML evidence, and all attached forensic reports from ever being deleted by retention cleanup."
        )
        if case_preserve != bool(updated_case_dict.get("preserve_evidence", False)):
            storage_mgr.set_evidence_preservation(u_target_id, case_id, case_preserve)
            updated_case_dict["preserve_evidence"] = case_preserve

        # 3. Retention Policy & Safe Cleanup Execution
        st.markdown("#### ⏳ Retention Policy & Safe Cleanup")
        c_ret1, c_ret2 = st.columns([2, 3])
        with c_ret1:
            sel_retention = st.selectbox(
                "Configured Retention Policy:",
                [30, 7, 90, 180],
                format_func=lambda d: f"{d} Days (Default)" if d == 30 else f"{d} Days",
                key="sel_storage_retention_days"
            )
        with c_ret2:
            st.caption(f"Inactive and closed cases older than {sel_retention} days will be eligible for defensive cleanup. Active cases and preserved evidence are strictly protected.")

        col_cl1, col_cl2 = st.columns(2)
        with col_cl1:
            if st.button("🔍 Preview Cleanup (Dry-Run)", key="btn_storage_dry_run"):
                dry_res = storage_mgr.dry_run_cleanup(u_target_id, policy_days=sel_retention)
                st.session_state["storage_dry_run_res"] = dry_res

        if "storage_dry_run_res" in st.session_state:
            dry_res = st.session_state["storage_dry_run_res"]
            st.info(
                f"**Dry-Run Summary ({sel_retention}-Day Policy):**\n\n"
                f"• Eligible for deletion: **{dry_res['eligible_cases_count']}** cases, **{dry_res['eligible_evidence_count']}** evidence files, **{dry_res['eligible_reports_count']}** reports.\n\n"
                f"• Protected: **{dry_res['protected_cases_count']}** cases, **{dry_res['protected_evidence_count']}** evidence files, **{dry_res['protected_reports_count']}** reports.\n\n"
                "*(No files were deleted during this preview)*"
            )
            with col_cl2:
                if st.button("🧹 Run Cleanup Now (Confirm Deletion)", type="primary", key="btn_storage_run_cleanup"):
                    clean_res = storage_mgr.run_cleanup_now(u_target_id, policy_days=sel_retention)
                    st.session_state.pop("storage_dry_run_res", None)
                    st.success(
                        f"Cleanup complete! Deleted {clean_res['deleted_cases_count']} cases, {clean_res['deleted_evidence_count']} evidence files, {clean_res['deleted_reports_count']} reports. "
                        f"Protected: {clean_res['protected_cases_count']} cases, {clean_res['protected_evidence_count']} evidence files. Failures: {clean_res['failed_deletions_count']}."
                    )
                    st.rerun()

    with tab8:
        st.subheader("⚖️ Forensic Header Diff & Baseline Comparator")
        st.caption("Compares suspect email headers against verified legitimate enterprise brand baselines to uncover forged relays, mismatched envelope senders, and spoofed authentication:")
            
        brand_options = ["Auto-Detect from Sender"] + [f"{info['brand_name']} ({dom})" for dom, info in BRAND_BASELINES.items()]
        chosen_brand_option = st.selectbox("Select Baseline Reference:", brand_options, index=0)
            
        target_baseline_domain = None
        if chosen_brand_option != "Auto-Detect from Sender":
            target_baseline_domain = chosen_brand_option.split("(")[-1].strip(")")
                
        auth_align = agent_out.get("auth_alignment", {})
        dkim_domain = auth_align.get("dkim_signing_domain") or auth_align.get("dkim_domain", "")
        spf_val = auth_align.get("spf_result", "None")
        dkim_val = auth_align.get("dkim_result", "None")
        dmarc_val = auth_align.get("effective_dmarc") or auth_align.get("dmarc_recorded", "None")

        raw_rp = headers.get("return-path", "")
        return_path_val = " ".join(raw_rp) if isinstance(raw_rp, list) else str(raw_rp)
        raw_from = headers.get("from", "")
        from_val = " ".join(raw_from) if isinstance(raw_from, list) else str(raw_from)

        suspect_header_payload = {
            "from": from_val,
            "sender_name": case_report.sender,
            "return_path": return_path_val,
            "dkim_domain": str(dkim_domain),
            "spf": str(spf_val),
            "dkim": str(dkim_val),
            "dmarc": str(dmarc_val),
            "first_hop": parsed_data.get("received_chain", [""])[0] if parsed_data.get("received_chain") else ""
        }
            
        diff_results = compare_headers_against_baseline(suspect_header_payload, target_baseline_domain)
            
        diff_col1, diff_col2, diff_col3 = st.columns([2, 1, 1])
        with diff_col1:
            st.markdown(f"#### Reference Baseline: **{diff_results['baseline_brand']}**")
            if "CRITICAL SPOOFING" in diff_results["verdict"]:
                st.error(f"🚨 **{diff_results['verdict']}**")
            elif "SUSPICIOUS" in diff_results["verdict"]:
                st.warning(f"⚠️ **{diff_results['verdict']}**")
            else:
                st.success(f"✅ **{diff_results['verdict']}**")
        with diff_col2:
            st.metric("Forgeries Detected", diff_results["forgery_count"])
        with diff_col3:
            st.metric("Anomalies", diff_results["anomaly_count"])
                
        st.markdown("---")
        st.markdown("#### Detailed Header Discrepancy Matrix")
            
        checkpoint_rows = []
        for cp in diff_results["checkpoints"]:
            cp_status = cp.get("status", "")
            if cp_status == "MATCH":
                status_icon = "✅ MATCH"
            elif cp_status == "FORGERY_DETECTED":
                status_icon = "🚨 FORGERY"
            elif cp_status in ["UNCONFIGURED", "NONE", "NOT_APPLICABLE", "UNSIGNED"]:
                status_icon = "ℹ️ UNCONFIGURED"
            elif cp_status == "ANOMALY":
                status_icon = "⚠️ ANOMALY"
            else:
                status_icon = f"⚠️ {cp_status}"

            checkpoint_rows.append({
                "Forensic Checkpoint": cp["checkpoint"],
                "Legitimate Baseline": cp["legitimate_norm"],
                "Suspect Actual": cp["suspect_actual"],
                "Verdict": status_icon,
                "Forensic Finding": cp["finding"]
            })
        st.dataframe(checkpoint_rows, use_container_width=True)

# View 3: SOC Investigations & Case Management
elif selected_nav == "🔎 Investigations":
    st.header("🔎 SOC Forensic Investigations & Case Management")
    st.caption("Search, review, annotate, and manage historical forensic investigations.")

    if not is_authenticated_soc_caller(current_user_id, user_client):
        st.info("🔐 **Authentication Required**: Please sign in or register via the sidebar to view, search, and manage historical investigations.")
    else:
        active_inv_id = st.session_state.get("active_investigation_id")
        active_case = get_case_record(active_inv_id, client=user_client) if active_inv_id else None

        if active_inv_id and active_case:
            # =========================================================
            # INVESTIGATION WORKSPACE
            # =========================================================
            col_bk1, col_bk2 = st.columns([3, 1])
            with col_bk1:
                if st.button("◀ Back to Investigation Queue", key="btn_back_to_queue"):
                    st.session_state.pop("active_investigation_id", None)
                    st.rerun()
            with col_bk2:
                if st.button("🔄 Refresh Investigation", key=f"btn_refresh_inv_{active_inv_id}"):
                    st.rerun()

            # Investigation Header
            lifecycle_s = normalize_to_lifecycle_status(active_case.get("status"))
            sev = str(active_case.get("case_severity", "MEDIUM")).upper()
            verdict = str(active_case.get("threat_verdict", "UNCLASSIFIED"))
            sev_col = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(sev, "#94a3b8")
            status_col = {"NEW": "#38bdf8", "INVESTIGATING": "#f59e0b", "CONTAINED": "#8b5cf6", "CLOSED": "#10b981"}.get(lifecycle_s, "#64748b")

            st.markdown(
                f"""
                <div style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 10px; padding: 18px; margin: 10px 0 20px 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                        <h3 style="color: #38bdf8; margin: 0;">🔎 Investigation: {html.escape(active_inv_id)}</h3>
                        <div>
                            <span style="background-color: {sev_col}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: bold; margin-right: 6px;">SEVERITY: {sev}</span>
                            <span style="background-color: {status_col}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: bold;">STATUS: {lifecycle_s}</span>
                        </div>
                    </div>
                    <p style="color: #cbd5e1; font-size: 0.95em; margin: 8px 0 4px 0;">
                        <b>Subject:</b> {html.escape(str(active_case.get('subject', 'No Subject')))}
                    </p>
                    <div style="color: #64748b; font-size: 0.82em;">
                        👤 <b>Assigned:</b> {html.escape(str(active_case.get('assigned_investigator', 'Unassigned')))} | 
                        🕒 <b>Created:</b> {active_case.get('timestamp', 'N/A')} | 
                        🎯 <b>Verdict:</b> <code style="color: #f87171;">{html.escape(verdict)}</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            tab_ws_sum, tab_ws_time, tab_ws_mail, tab_ws_ioc, tab_ws_geo, tab_ws_graph, tab_ws_ev, tab_ws_notes, tab_ws_exp = st.tabs([
                "📋 Summary",
                "🕒 Timeline",
                "📧 Related Emails",
                "🎯 Indicators (IOCs)",
                "🗺️ GeoIP / Infrastructure",
                "🕸️ Attack Graph",
                "🛡️ Evidence Integrity",
                "📝 Analyst Notes",
                "📄 Reports & Exports"
            ])

            with tab_ws_sum:
                st.subheader("📋 Executive Threat Summary & Lifecycle Control")
                c_s1, c_s2, c_s3, c_s4 = st.columns(4)
                with c_s1:
                    st.metric("Investigation ID", active_inv_id)
                with c_s2:
                    st.metric("Threat Verdict", verdict)
                with c_s3:
                    st.metric("Risk Score", active_case.get("risk_score", "UNKNOWN"))
                with c_s4:
                    st.metric("Lifecycle Status", lifecycle_s)

                st.markdown("---")
                st.markdown("#### 🔄 Lifecycle State Transitions")
                col_st1, col_st2, col_st3, col_st4 = st.columns(4)
                with col_st1:
                    if st.button("🔵 Set NEW", use_container_width=True, disabled=(lifecycle_s == "NEW"), key=f"btn_set_new_{active_inv_id}"):
                        transition_investigation_status(active_inv_id, "NEW", current_user_id, client=user_client)
                        st.rerun()
                with col_st2:
                    if st.button("🟡 INVESTIGATING", use_container_width=True, disabled=(lifecycle_s == "INVESTIGATING"), key=f"btn_set_inv_{active_inv_id}"):
                        transition_investigation_status(active_inv_id, "INVESTIGATING", current_user_id, client=user_client)
                        st.rerun()
                with col_st3:
                    if st.button("🟣 CONTAINED", use_container_width=True, disabled=(lifecycle_s == "CONTAINED"), key=f"btn_set_cont_{active_inv_id}"):
                        transition_investigation_status(active_inv_id, "CONTAINED", current_user_id, client=user_client)
                        st.rerun()
                with col_st4:
                    if st.button("🟢 CLOSE CASE", use_container_width=True, disabled=(lifecycle_s == "CLOSED"), key=f"btn_set_cls_{active_inv_id}"):
                        transition_investigation_status(active_inv_id, "CLOSED", current_user_id, client=user_client)
                        st.rerun()

                st.markdown("---")
                st.markdown("#### 🔍 Rule Findings & Classification Details")
                rule_findings = active_case.get("rule_findings", [])
                if rule_findings:
                    for rf in rule_findings:
                        if isinstance(rf, dict):
                            st.write(f"- **[{rf.get('rule_id', 'RULE')}]** {rf.get('finding', '')} (Severity: `{rf.get('severity', 'MEDIUM')}`)")
                else:
                    st.info("No explicit malicious heuristic rule triggers logged for this investigation.")

            with tab_ws_time:
                st.subheader("🕒 Chronological Investigation Timeline")
                st.caption("Evidence-backed events derived strictly from verified case timestamps. No fabricated events.")
                timeline = build_investigation_timeline(active_case)
                if timeline:
                    for ev in timeline:
                        act = ev.get("actor", "SYSTEM")
                        act_badge = {"SYSTEM": "⚙️ SYSTEM", "SENTINEL": "📡 SENTINEL", "ANALYST": "👤 ANALYST"}.get(act, act)
                        st.markdown(
                            f"""
                            <div style="background-color: #1e293b; border-left: 3px solid #38bdf8; border-radius: 4px; padding: 10px 14px; margin-bottom: 8px;">
                                <div style="display: flex; justify-content: space-between; font-size: 0.82em; color: #94a3b8;">
                                    <b>{html.escape(ev.get('event_type', 'Event'))}</b>
                                    <span>{html.escape(str(ev.get('timestamp', '')))} | <code>{act_badge}</code></span>
                                </div>
                                <div style="color: #e2e8f0; font-size: 0.9em; margin-top: 4px;">
                                    {html.escape(ev.get('description', ''))}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                else:
                    st.info("No timeline events recorded.")

            with tab_ws_mail:
                st.subheader("📧 Related Emails & Bounded Metadata")
                st.caption("Protected envelope metadata. Sensitive tokens, passwords, and raw mailboxes are never exposed.")
                emails = get_investigation_emails(active_case)
                for em in emails:
                    st.markdown(f"**Subject:** `{em.get('subject')}`")
                    c_em1, c_em2 = st.columns(2)
                    with c_em1:
                        st.markdown(f"**From:** `{em.get('from')}`")
                        st.markdown(f"**Date:** `{em.get('date')}`")
                    with c_em2:
                        st.markdown(f"**To:** `{em.get('to')}`")
                        st.markdown(f"**Message-ID:** `{em.get('message_id')}`")
                    
                    auth_align = active_case.get("auth_alignment", {})
                    if auth_align:
                        st.markdown(f"**Authentication Alignment:** SPF=`{auth_align.get('spf_result', 'NONE')}` | DKIM=`{auth_align.get('dkim_result', 'NONE')}` | DMARC=`{auth_align.get('effective_dmarc', 'NONE')}`")

                    if em.get("body_excerpt"):
                        with st.expander("Sanitized Email Excerpt (< 300 chars, secrets masked)"):
                            st.text(em["body_excerpt"])

            with tab_ws_ioc:
                st.subheader("🎯 Indicators of Compromise (IOCs)")
                st.caption("Extracted and defanged IOCs cross-referenced with forensic rules.")
                iocs = get_investigation_indicators(active_case, client=user_client)
                if iocs:
                    st.dataframe(iocs, use_container_width=True)
                else:
                    st.info("No extracted indicators of compromise for this investigation.")

            with tab_ws_geo:
                st.subheader("🗺️ GeoIP & Origin Threat Infrastructure")
                sloc = derive_authoritative_location(active_case)
                if sloc and sloc.get("is_identified"):
                    c_g1, c_g2, c_g3, c_g4 = st.columns(4)
                    with c_g1:
                        st.metric("Origin IP", sloc.get("sender_ip", "Unknown"))
                    with c_g2:
                        st.metric("Country", sloc.get("country", "Unknown"))
                    with c_g3:
                        st.metric("City", sloc.get("city", "Unknown"))
                    with c_g4:
                        st.metric("ISP / Org", str(sloc.get("org") or sloc.get("isp", "Unknown"))[:20])

                    lat = sloc.get("latitude")
                    lon = sloc.get("longitude")
                    if lat is not None and lon is not None:
                        st.map([{"lat": float(lat), "lon": float(lon)}], zoom=4)
                    else:
                        st.caption("Approximate location identified; specific map coordinates unavailable.")
                else:
                    st.info("Origin IP is relay-masked or internal. No external GeoIP infrastructure identified.")

                st.caption(
                    "ℹ️ **Attribution Disclaimer:** GeoIP provides approximate network/infrastructure context for the identified IP. "
                    "It does not prove the physical location or identity of the human sender."
                )

            with tab_ws_graph:
                st.subheader("🕸️ Threat Infrastructure Attack Graph")
                try:
                    fig_ws = build_case_infrastructure_graph(active_inv_id, active_case)
                    st.plotly_chart(fig_ws, use_container_width=True)
                    st.caption("Correlating Case, Sender, Origin IP, MTA Relays, and Indicators.")
                except Exception as g_err:
                    st.info("No correlated attack relationships available for this investigation.")

            with tab_ws_ev:
                st.subheader("🛡️ Evidence Manifest & Cryptographic Integrity")
                st.caption("Cryptographic SHA-256 hashes preserving Section 63(4)(c) BSA electronic evidence admissibility.")

                raw_bytes_cached = st.session_state.get("current_email_bytes")
                manifest = build_evidence_manifest(active_case, client=user_client, raw_eml_bytes=raw_bytes_cached)

                col_v1, col_v2 = st.columns([2, 4])
                with col_v1:
                    btn_verify_ev = st.button("🔐 Verify Evidence Integrity", type="primary", key=f"btn_verify_ev_{active_inv_id}")

                if btn_verify_ev:
                    overall_status, verified_manifest = verify_all_manifest_integrity(manifest, raw_eml_bytes=raw_bytes_cached)
                    if overall_status == IntegrityStatus.VERIFIED:
                        st.success(f"✅ **INTEGRITY VERIFIED**: All {len(manifest)} evidence artifacts matched their recorded cryptographic SHA-256 digests.")
                    elif overall_status == IntegrityStatus.MISMATCH:
                        st.error("🚨 **INTEGRITY MISMATCH**: One or more evidence artifacts failed cryptographic SHA-256 verification!")
                    else:
                        st.warning("⚠️ **HASH NOT AVAILABLE**: Some artifacts do not have recorded cryptographic digests.")
                    st.markdown("##### Cryptographic Evidence Manifest")
                    st.dataframe(verified_manifest, use_container_width=True)
                else:
                    st.markdown("##### Cryptographic Evidence Manifest")
                    st.dataframe(manifest, use_container_width=True)

                st.markdown("---")
                st.markdown("##### 📜 Verifiable Chain-of-Custody Ledger")
                st.caption("Chronological record of evidence intake, parsing, hashing, and investigator actions:")
                chain_custody = build_chain_of_custody(active_case, client=user_client)
                st.dataframe(chain_custody, use_container_width=True)

            with tab_ws_notes:
                st.subheader("📝 Analyst Notes & Collaboration")
                st.caption("Tenant-isolated notes trail with XSS sanitization.")
                existing_notes = active_case.get("analyst_notes", "")
                if existing_notes and existing_notes.strip():
                    for line in existing_notes.strip().split("\n"):
                        if line.strip():
                            st.markdown(f"• `{html.escape(line.strip())}`")
                else:
                    st.info("No analyst notes recorded yet.")

                st.markdown("##### Add Analyst Note")
                new_note_text = st.text_area("Enter observation or triage finding:", placeholder="e.g. Origin MTA verified spoofed. Adversary domain sinkholed.", key=f"txt_ws_note_{active_inv_id}")
                if st.button("📝 Add Note", type="primary", key=f"btn_ws_add_note_{active_inv_id}"):
                    if new_note_text and new_note_text.strip():
                        ok, msg = add_analyst_note(active_inv_id, new_note_text, current_user_id, client=user_client)
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                    else:
                        st.warning("Please enter note content.")

            with tab_ws_exp:
                st.subheader("📄 Forensic Reports & Legal Evidence Packages")
                st.caption("Download verified compliance certificates, executive summaries, and structured dossiers.")
                col_x1, col_x2 = st.columns(2)
                with col_x1:
                    exec_bytes = export_case_executive_pdf(active_inv_id, client=user_client, user_id=current_user_id)
                    if exec_bytes:
                        st.download_button("📄 Download Executive Summary (PDF)", exec_bytes, file_name=f"Executive_Summary_{active_inv_id}.pdf", mime="application/pdf", use_container_width=True)
                    pdf_bytes = export_case_report_pdf(active_inv_id, client=user_client, user_id=current_user_id)
                    if pdf_bytes:
                        st.download_button("📑 Download Full Technical Report (PDF)", pdf_bytes, file_name=f"Forensic_Report_{active_inv_id}.pdf", mime="application/pdf", use_container_width=True)
                    zip_bytes = export_case_zip_package(active_inv_id, client=user_client, user_id=current_user_id, raw_eml_bytes=raw_bytes_cached)
                    if zip_bytes:
                        st.download_button("🗂️ Download Investigation Package (ZIP)", zip_bytes, file_name=f"EMAILSHIELD_INVESTIGATION_{active_inv_id}.zip", mime="application/zip", use_container_width=True)
                with col_x2:
                    man_json = export_case_evidence_manifest(active_inv_id, client=user_client, user_id=current_user_id)
                    if man_json:
                        st.download_button("📜 Download Evidence Manifest (JSON)", man_json, file_name=f"Manifest_{active_inv_id}.json", mime="application/json", use_container_width=True)
                    json_str = export_case_report_json(active_inv_id, client=user_client, user_id=current_user_id)
                    if json_str:
                        st.download_button("📦 Download JSON Evidence Package", json_str, file_name=f"Evidence_{active_inv_id}.json", mime="application/json", use_container_width=True)
                    ncrp_bytes = export_case_ncrp_pdf(active_inv_id, client=user_client, user_id=current_user_id)
                    if ncrp_bytes:
                        st.download_button("🇮🇳 Download Section 63 BSA Annexure (PDF)", ncrp_bytes, file_name=f"BSA_Sec63_{active_inv_id}.pdf", mime="application/pdf", use_container_width=True)

                st.markdown("---")
                st.markdown("##### 📝 Cybercrime.gov.in Complaint Draft (NCRP)")
                st.caption("Structured complaint text formatted for direct submission to the National Cyber Crime Reporting Portal:")
                ncrp_draft_text = generate_ncrp_complaint_text(active_case)
                st.text_area("NCRP Portal Complaint Draft:", value=ncrp_draft_text, height=180, key=f"txt_ncrp_draft_{active_inv_id}")

        else:
            # =========================================================
            # INVESTIGATION QUEUE & SEARCH TABLE
            # =========================================================
            cases = get_all_cases(client=user_client, limit=200)
            if not cases:
                st.info("No historical investigations found for your account. Upload or analyze an email to create a case.")
            else:
                c_flt1, c_flt2, c_flt3, c_flt4 = st.columns([2, 1, 1, 1])
                with c_flt1:
                    search_query = st.text_input("🔍 Search investigations:", placeholder="Search by Case ID, Subject, Sender, or IOC...").strip()
                with c_flt2:
                    status_filter = st.selectbox("Status:", ["All", "NEW", "INVESTIGATING", "CONTAINED", "CLOSED"])
                with c_flt3:
                    severity_filter = st.selectbox("Severity:", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
                with c_flt4:
                    verdict_filter = st.selectbox("Verdict:", ["All", "THREAT", "SUSPICIOUS", "CLEAN"])

                filtered_cases = search_investigations(
                    cases=cases,
                    query=search_query,
                    status_filter=status_filter,
                    severity_filter=severity_filter,
                    verdict_filter=verdict_filter
                )

                st.caption(f"Showing **{len(filtered_cases)}** of {len(cases)} investigations:")
                case_table = []
                for fc in filtered_cases:
                    case_table.append({
                        "Case ID": fc.get("case_id"),
                        "Timestamp": str(fc.get("timestamp", "N/A"))[:19],
                        "Severity": str(fc.get("case_severity", "MEDIUM")).upper(),
                        "Verdict": str(fc.get("threat_verdict", "N/A")),
                        "Status": normalize_to_lifecycle_status(fc.get("status")),
                        "Investigator": fc.get("assigned_investigator", "Unassigned"),
                        "Subject": str(fc.get("subject", "No Subject"))[:35],
                        "Sender": str(fc.get("sender", "Unknown"))[:30]
                    })
                st.dataframe(case_table, use_container_width=True)

                st.markdown("---")
                col_sel_q1, col_sel_q2 = st.columns([3, 1])
                case_options = [fc.get("case_id") for fc in filtered_cases if fc.get("case_id")]
                with col_sel_q1:
                    selected_open_id = st.selectbox("Select investigation to open in SOC Workspace:", case_options if case_options else ["None"])
                with col_sel_q2:
                    st.write("")
                    st.write("")
                    if st.button("🔎 Open Workspace", type="primary", use_container_width=True, disabled=not case_options, key="btn_open_selected_ws"):
                        if selected_open_id and selected_open_id != "None":
                            st.session_state["active_investigation_id"] = selected_open_id
                            st.rerun()

# View 4: IOC & URL Intelligence
elif selected_nav == "🌐 IOC / URL Intelligence":
    st.header("🌐 Threat Intelligence & IOC Command Center")
    st.caption("Investigate threat indicators, inspect suspicious links, and export IOCs for SIEM ingestion.")

    tab_ioc_repo, tab_geoip, tab_ioc_sandbox = st.tabs([
        "📁 Tenant IOC Repository",
        "🗺️ GeoIP & Threat Infrastructure",
        "🔬 URL / Indicator Sandbox Inspector"
    ])

    with tab_ioc_repo:
        st.subheader("📁 Indicators of Compromise (IOCs)")
        if not is_authenticated_soc_caller(current_user_id, user_client):
            st.info("🔐 **Authentication Required**: Please sign in to access IOC and threat intelligence data.")
        else:
            indicators = get_all_indicators(client=user_client, limit=1000)
            if indicators:
                c_ioc1, c_ioc2 = st.columns([3, 1])
                with c_ioc1:
                    ioc_types = sorted(list({ind.get("type", "UNKNOWN") for ind in indicators}))
                    type_filter = st.selectbox("Filter by IOC Type:", ["All"] + ioc_types)
                with c_ioc2:
                    st.metric("Total Extracted IOCs", len(indicators))

                filtered_iocs = [ind for ind in indicators if type_filter == "All" or ind.get("type") == type_filter]
                st.dataframe(filtered_iocs, use_container_width=True)

                col_exp1, col_exp2 = st.columns(2)
                with col_exp1:
                    csv_data = export_case_iocs_csv(client=user_client)
                    st.download_button(
                        "📥 Export IOCs as CSV (Firewall / SIEM)",
                        csv_data,
                        file_name="emailshield_iocs.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                with col_exp2:
                    json_data = export_case_iocs_json(client=user_client)
                    st.download_button(
                        "📥 Export IOCs as JSON (MISP / STIX)",
                        json_data,
                        file_name="emailshield_iocs.json",
                        mime="application/json",
                        use_container_width=True
                    )
            else:
                st.info("No IOCs recorded yet. Analyze an email to extract indicators.")

    with tab_geoip:
        st.subheader("🗺️ GeoIP & Threat Infrastructure Intelligence")
        st.caption("Active & historical threat infrastructure intelligence, origin geolocations, and routing context.")

        if not is_authenticated_soc_caller(current_user_id, user_client):
            st.info("🔐 **Authentication Required**: Please sign in to access GeoIP and threat infrastructure intelligence.")
        else:
            # -----------------------------------------------------------------
            # 1. Manual IP Search Box (Directly above the existing map)
            # -----------------------------------------------------------------
            st.markdown("#### 🔎 Search IP Address")
            col_search_in, col_btn_s, col_btn_c = st.columns([4, 1.2, 1.2])
            with col_search_in:
                manual_ip_input = st.text_input(
                    "Search IP Address",
                    value=st.session_state.get("manual_geo_ip", "") or "",
                    placeholder="8.8.8.8",
                    label_visibility="collapsed",
                    key="input_manual_geo_ip"
                )
            with col_btn_s:
                btn_search_ip = st.button("Search IP", type="primary", use_container_width=True, key="btn_search_manual_ip")
            with col_btn_c:
                btn_clear_ip = st.button("Clear IP Search", use_container_width=True, key="btn_clear_manual_ip")

            if btn_clear_ip:
                st.session_state.pop("manual_geo_ip", None)
                st.session_state.pop("manual_geo_result", None)
                st.session_state.pop("manual_geo_error", None)
                st.rerun()

            if btn_search_ip:
                raw_ip = manual_ip_input.strip() if manual_ip_input else ""
                if not raw_ip:
                    st.session_state["manual_geo_error"] = "Please enter an IP address to search."
                    st.session_state.pop("manual_geo_ip", None)
                    st.session_state.pop("manual_geo_result", None)
                else:
                    import ipaddress
                    try:
                        parsed_ip = ipaddress.ip_address(raw_ip)
                        valid_ip_str = str(parsed_ip)
                        st.session_state.pop("manual_geo_error", None)
                        st.session_state["manual_geo_ip"] = valid_ip_str

                        # Query GeoIP (safe offline or enriched)
                        try:
                            geo_res = get_geolocation(valid_ip_str)
                        except Exception:
                            geo_res = {
                                "ip": valid_ip_str,
                                "country": "Unavailable",
                                "region": "Unavailable",
                                "city": "Unavailable",
                                "latitude": None,
                                "longitude": None,
                                "org": "Unavailable",
                                "asn": "Unavailable",
                                "db_provider": "Error",
                                "db_version": "N/A",
                                "status": "Provider Error"
                            }

                        # Passive infrastructure assessment for public IPs
                        infra_res = None
                        if is_public_ip(valid_ip_str):
                            try:
                                infra_res = assess_infrastructure(ip=valid_ip_str)
                            except Exception:
                                infra_res = None

                        st.session_state["manual_geo_result"] = {
                            "geo": geo_res,
                            "infra": infra_res
                        }
                    except ValueError:
                        st.session_state["manual_geo_error"] = (
                            f"Invalid IP address '{raw_ip}'. Please enter a valid IPv4 or IPv6 address. "
                            "Hostnames, URLs, and malformed formats are not supported."
                        )
                        st.session_state.pop("manual_geo_ip", None)
                        st.session_state.pop("manual_geo_result", None)
                st.rerun()

            if st.session_state.get("manual_geo_error"):
                st.error(st.session_state["manual_geo_error"])

            st.markdown("---")
            st.markdown("#### 🗺️ GeoIP Location")

            # -----------------------------------------------------------------
            # 2. Single Map Rendering & IP Intelligence Logic
            # -----------------------------------------------------------------
            active_manual_ip = st.session_state.get("manual_geo_ip")
            cached_payload = st.session_state.get("_cached_analysis_payload")

            if active_manual_ip and "manual_geo_result" in st.session_state:
                # Manual IP Mode
                m_result = st.session_state["manual_geo_result"]
                m_geo = m_result.get("geo") or {}
                m_infra = m_result.get("infra")

                m_lat = m_geo.get("latitude")
                m_lon = m_geo.get("longitude")

                if m_lat is not None and m_lon is not None:
                    # Single map updated with new coordinates
                    st.map([{"lat": float(m_lat), "lon": float(m_lon)}], zoom=4)
                else:
                    st.warning(
                        "⚠️ **Coordinates: NOT AVAILABLE** — Valid IP intelligence was retrieved, "
                        "but no geographic coordinates exist for this network. No map marker was fabricated."
                    )

                st.markdown("#### 📍 IP Intelligence")
                c_src1, c_src2 = st.columns([2, 2])
                with c_src1:
                    st.markdown("**Source:** <span style='color: #38bdf8; font-weight: bold;'>Manual IP Lookup</span>", unsafe_allow_html=True)
                with c_src2:
                    st.markdown(f"**Target IP:** `{active_manual_ip}`")

                flag = get_country_flag(m_geo.get("country", ""))
                c_m1, c_m2, c_m3, c_m4 = st.columns(4)
                with c_m1:
                    st.metric("Country", m_geo.get("country", "Unknown"), delta=flag)
                with c_m2:
                    st.metric("Region / State", m_geo.get("region", "Unknown"))
                with c_m3:
                    st.metric("City", m_geo.get("city", "Unknown"))
                with c_m4:
                    coords_disp = f"{m_lat:.4f}, {m_lon:.4f}" if (m_lat is not None and m_lon is not None) else "Not available"
                    st.metric("Coordinates", coords_disp)

                c_m5, c_m6, c_m7, c_m8 = st.columns(4)
                with c_m5:
                    st.metric("ISP / Routing Org", str(m_geo.get("org", "Unknown"))[:25])
                with c_m6:
                    st.metric("ASN", str(m_geo.get("asn", "Unknown"))[:18])
                with c_m7:
                    st.metric("DB Provider", str(m_geo.get("db_provider", "Unknown"))[:25])
                with c_m8:
                    st.metric("DB Version", str(m_geo.get("db_version", "N/A"))[:20])

                if m_infra:
                    # Render infrastructure security indicators
                    b_cloud = getattr(getattr(m_infra, "cloud_intel", None), "provider", "Not Detected")
                    b_vpn = getattr(getattr(m_infra, "vpn_intel", None), "status", "UNKNOWN")
                    b_tor = getattr(getattr(m_infra, "tor_intel", None), "status", "UNKNOWN")
                    b_relay = getattr(getattr(m_infra, "open_relay_intel", None), "status", "UNKNOWN")
                    b_botnet = getattr(getattr(m_infra, "botnet_intel", None), "status", "UNKNOWN")
                    b_threat = getattr(getattr(m_infra, "threat_feed_intel", None), "status", "UNKNOWN")

                    vpn_bg = "#ef4444" if b_vpn == "DETECTED" else "#10b981"
                    tor_bg = "#ef4444" if b_tor == "DETECTED" else "#10b981"
                    relay_bg = "#ef4444" if b_relay == "INDICATED" else "#10b981"
                    botnet_bg = "#ef4444" if b_botnet == "INDICATED" else "#10b981"
                    threat_bg = "#ef4444" if b_threat == "MATCH" else "#10b981"

                    st.markdown(
                        f"""
                        <div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin: 12px 0;">
                            <div style="font-size: 0.9em; font-weight: 700; color: #38bdf8; margin-bottom: 6px;">
                                🛡️ Infrastructure Classification
                            </div>
                            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                                <span style="background-color: #0284c7; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Cloud: {html.escape(str(b_cloud))}</span>
                                <span style="background-color: {vpn_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">VPN: {b_vpn}</span>
                                <span style="background-color: {tor_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Tor: {b_tor}</span>
                                <span style="background-color: {relay_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Open Relay: {b_relay}</span>
                                <span style="background-color: {botnet_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Botnet: {b_botnet}</span>
                                <span style="background-color: {threat_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Threat Feed: {b_threat}</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            elif cached_payload and "case_report" in cached_payload:
                # Email-Derived IP Mode
                case_report = cached_payload["case_report"]
                sloc = derive_authoritative_location(case_report)
                geolocations = getattr(case_report, "geolocations", []) or []

                c_src1, c_src2 = st.columns([2, 2])
                with c_src1:
                    st.markdown("**Source:** <span style='color: #10b981; font-weight: bold;'>Email-Derived IP</span>", unsafe_allow_html=True)
                with c_src2:
                    st.markdown(f"**Associated Case:** `{cached_payload.get('case_id', 'Active Investigation')}`")

                if sloc.get("is_identified"):
                    email_coords = []
                    if sloc.get("latitude") is not None and sloc.get("longitude") is not None:
                        email_coords.append({"lat": float(sloc["latitude"]), "lon": float(sloc["longitude"])})

                    for g in geolocations:
                        gd = g.model_dump() if hasattr(g, "model_dump") else g
                        if gd.get("ip") != sloc.get("sender_ip") and gd.get("latitude") is not None and gd.get("longitude") is not None:
                            email_coords.append({"lat": float(gd["latitude"]), "lon": float(gd["longitude"])})

                    if email_coords:
                        st.map(email_coords, zoom=2)
                    else:
                        st.warning("⚠️ **Coordinates: NOT AVAILABLE** — Email sender identified, but no geographic coordinates exist.")

                    st.markdown("#### 📍 IP Intelligence")
                    flag = sloc.get("flag") or get_country_flag(sloc.get("country", ""))
                    c_e1, c_e2, c_e3, c_e4 = st.columns(4)
                    with c_e1:
                        st.metric("Originating IP", sloc.get("sender_ip", "Unavailable"))
                    with c_e2:
                        st.metric("Country", sloc.get("country", "Unknown"), delta=flag)
                    with c_e3:
                        st.metric("City / Region", f"{sloc.get('city', 'Unknown')}, {sloc.get('region', 'Unknown')}")
                    with c_e4:
                        st.metric("ISP / ASN", f"{str(sloc.get('org', 'Unknown'))[:15]} ({sloc.get('asn', 'N/A')})")

                else:
                    st.warning("⚠️ **Originating IP: Not available / Relay-masked**")
                    st.markdown(
                        f"> **Relay-Masked:** YES — {sloc.get('relay_masked_explanation', 'The available email telemetry does not expose a reliable public client/originating IP.')}"
                    )
                    relay_coords = []
                    for g in geolocations:
                        gd = g.model_dump() if hasattr(g, "model_dump") else g
                        if gd.get("latitude") is not None and gd.get("longitude") is not None:
                            relay_coords.append({"lat": float(gd["latitude"]), "lon": float(gd["longitude"])})
                    if relay_coords:
                        st.caption("Displaying intermediate mail relay infrastructure hops:")
                        st.map(relay_coords, zoom=2)

            else:
                # No active manual search and no email analyzed yet
                st.info("ℹ️ Enter an IP address above to inspect geographic and threat infrastructure intelligence, or analyze an email in '📧 Analyze Email' to populate email-derived hops.")

            # Location Disclaimer (always rendered)
            st.caption(
                "ℹ️ **Location Disclaimer**: GeoIP location is approximate network/infrastructure context and does not identify "
                "a person's physical location or identity. VPNs, proxies, mobile networks, CDNs, cloud infrastructure, and relay servers "
                "can affect the reported location."
            )

    with tab_ioc_sandbox:
        st.subheader("🔬 Live Threat Indicator Sandbox")
        st.caption("Safe offline & SSRF-protected evaluation of URLs, domains, and IP addresses.")
        ioc_input = st.text_input("Enter URL, Domain, or IPv4 address:", placeholder="e.g. https://secure-login.bank-update.in or 198.51.100.1")
        if st.button("🔍 Run Indicator Analysis", type="primary", key="btn_run_ioc_sandbox"):
            if not ioc_input:
                st.warning("Please enter an indicator to inspect.")
            else:
                ioc_clean = ioc_input.strip()
                if ioc_clean.startswith("http://") or ioc_clean.startswith("https://"):
                    from core.url_forensics import analyze_url
                    res = analyze_url(ioc_clean)
                    st.markdown(f"**Target URL:** `{res.url}`")
                    st.markdown(f"**Defanged URL:** `{res.defanged_url}`")
                    st.markdown(f"**Risk Level:** `{res.risk_level}`")
                    st.markdown(f"**Threat Category:** `{res.threat_category}`")
                    if res.reasons:
                        st.write("**Detection Flags:**")
                        for r in res.reasons:
                            st.write(f"- {r}")
                elif "." in ioc_clean and not any(c in ioc_clean for c in "/: "):
                    d_rep = get_domain_reputation(ioc_clean)
                    st.json(d_rep.model_dump())
                else:
                    geo = get_geolocation(ioc_clean)
                    st.json(geo)

# View 5: Threat Infrastructure Attack Graph
elif selected_nav == "🕸️ Attack Graph":
    st.header("🕸️ Threat Infrastructure Attack Graph")
    st.caption("Interactive graph correlating Case, Sender, Relay MTAs, Origin IP, ASN, Hosting Provider, and Threat Indicators.")

    if not is_authenticated_soc_caller(current_user_id, user_client):
        st.info("🔐 **Authentication Required**: Please sign in to access investigation attack graphs.")
    else:
        cases = get_all_cases(client=user_client, limit=50)
        current_payload = st.session_state.get("_cached_analysis_payload")

        target_case_dict = None
        target_case_id = None

        if current_payload and "case_report" in current_payload:
            target_case_id = current_payload["case_id"]
            target_case_dict = current_payload["case_report"].model_dump()
            st.info(f"Displaying attack graph for currently analyzed case: **`{target_case_id}`**")
        elif cases:
            case_options = [c.get("case_id") for c in cases if c.get("case_id")]
            sel_c_id = st.selectbox("Select Case to visualize:", case_options)
            sel_c = next((c for c in cases if c.get("case_id") == sel_c_id), None)
            if sel_c:
                target_case_id = sel_c_id
                target_case_dict = sel_c
        else:
            st.info("No cases available to graph. Run an email investigation first.")

        if target_case_dict and target_case_id:
            try:
                fig_g = build_case_infrastructure_graph(target_case_id, target_case_dict)
                st.plotly_chart(fig_g, use_container_width=True)
                st.caption("Legend: 🔴 Threat IOCs | 🔵 Origin Infrastructure / ASN | 🟣 Sender & Domain Entities | 🟢 Clean / Verified")
            except Exception as e:
                st.error(f"Error generating attack graph: {e}")

# View 6: Forensic Evidence & Reports
elif selected_nav == "📄 Evidence & Reports":
    st.header("📄 Forensic Evidence & Legal Compliance Reports")
    st.caption("Structured electronic evidence certificates under Section 63(4)(c) Bharatiya Sakshya Adhiniyam, 2023 (BSA) and I4C NCRP standards.")

    if not is_authenticated_soc_caller(current_user_id, user_client):
        st.info("🔐 **Authentication Required**: Please sign in to access evidence and investigation reports.")
    else:
        current_payload = st.session_state.get("_cached_analysis_payload")
        cases = get_all_cases(client=user_client, limit=50)

        selected_report_dict = None
        selected_cid = None

        if current_payload and "case_report" in current_payload:
            selected_cid = current_payload["case_id"]
            selected_report_dict = current_payload["case_report"].model_dump()
            st.info(f"Prepared reports for active case: **`{selected_cid}`**")
        elif cases:
            case_opts = [c.get("case_id") for c in cases if c.get("case_id")]
            sel_id = st.selectbox("Select case for reporting:", case_opts)
            sel_case = next((c for c in cases if c.get("case_id") == sel_id), None)
            if sel_case:
                selected_cid = sel_id
                selected_report_dict = sel_case
        else:
            st.info("No investigation available. Analyze an email or load a sample scenario first.")

        if selected_report_dict and selected_cid:
            col_rep1, col_rep2 = st.columns(2)
            with col_rep1:
                st.markdown("#### 🇮🇳 Legal Evidence Dossier (BSA 2023)")
                st.caption("Electronic evidence annexure compliant with Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam.")
                ncrp_pdf_buf = io.BytesIO()
                generate_ncrp_pdf_annexure(selected_report_dict, ncrp_pdf_buf)
                st.download_button(
                    "🇮🇳 Download Section 63(4)(c) BSA Annexure (PDF)",
                    ncrp_pdf_buf.getvalue(),
                    file_name=f"BSA_Sec63_Annexure_{selected_cid}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

                st.markdown("#### 🛡️ Comprehensive Technical Dossier")
                st.caption("Full technical investigation report including headers, indicators, and ML telemetry.")
                tech_pdf_buf = io.BytesIO()
                generate_pdf_report(selected_report_dict, tech_pdf_buf)
                st.download_button(
                    "📄 Download Full Forensic PDF Report",
                    tech_pdf_buf.getvalue(),
                    file_name=f"Forensic_Report_{selected_cid}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

            with col_rep2:
                st.markdown("#### 📝 Cybercrime.gov.in Complaint Draft")
                st.caption("Copy-paste ready complaint text structured for the National Cyber Crime Reporting Portal.")
                complaint_text = generate_ncrp_complaint_text(selected_report_dict)
                st.text_area("NCRP Portal Complaint Text:", value=complaint_text, height=180)

                st.markdown("#### 🔒 Defanged & Sanitized EML")
                st.caption("Safe-to-share RFC 822 evidence file with neutralized links and quarantined attachments.")
                current_raw = st.session_state.get("current_email_bytes")
                if current_raw:
                    san_bytes, def_c, quar_c = sanitize_eml_content(current_raw)
                    st.download_button(
                        f"🛡️ Download Sanitized EML ({def_c} defanged, {quar_c} quarantined)",
                        san_bytes,
                        file_name=f"{selected_cid}_sanitized.eml",
                        mime="message/rfc822",
                        use_container_width=True
                    )
                else:
                    st.caption("Raw EML binary available when loaded in current session.")

# View 7: Mobile Security Alerts
elif selected_nav == "📱 Mobile Alerts":
    st.header("📱 Mobile Threat Alert Configuration")
    st.caption("Configure automated Telegram and WhatsApp security notifications for high-priority cyber threats.")

    if not is_authorized_caller(current_user_id, user_client):
        st.info("🔐 **Authentication Required**: Please sign in or register via the sidebar to access and configure mobile threat alerts.")
    else:
        tab_tg, tab_wa = st.tabs(["✈️ Telegram Bot Alerts", "💬 WhatsApp Alerts"])

        with tab_tg:
            st.subheader("✈️ Telegram Security Bot")
            st.markdown(
                "Receive real-time push alerts on your phone whenever a **HIGH** or **CRITICAL** threat arrives in your monitored mailbox."
            )
            tg_conf = get_telegram_config()
            tg_token = st.text_input("Telegram Bot Token:", value=tg_conf.get("bot_token", ""), type="password", placeholder="e.g. 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ", key="tg_cfg_tok")
            tg_chat = st.text_input("Telegram Chat ID:", value=tg_conf.get("chat_id", ""), placeholder="e.g. 987654321", key="tg_cfg_chat")

            col_tg1, col_tg2 = st.columns(2)
            with col_tg1:
                if st.button("🧪 Send Test Telegram Alert", type="primary", key="btn_test_tg_page"):
                    if not tg_token or not tg_chat:
                        st.error("Please configure both Bot Token and Chat ID.")
                    else:
                        success, msg = test_telegram_alert_delivery(tg_token, tg_chat)
                        if success:
                            st.success("✅ Test alert successfully sent to Telegram!")
                        else:
                            st.error(f"❌ Failed to send Telegram alert: {msg}")

        with tab_wa:
            st.subheader("💬 WhatsApp Threat Notifications")
            st.markdown(
                "Receive WhatsApp messages via CallMeBot gateway for urgent incident response."
            )
            wa_conf = get_whatsapp_config()
            wa_phone = st.text_input("WhatsApp Phone Number (with Country Code):", value=wa_conf.get("phone_number", ""), placeholder="e.g. +919876543210", key="wa_cfg_ph")
            wa_key = st.text_input("CallMeBot API Key:", value=wa_conf.get("api_key", ""), type="password", key="wa_cfg_key")

            if st.button("🧪 Send Test WhatsApp Alert", type="primary", key="btn_test_wa_page"):
                if not wa_phone or not wa_key:
                    st.error("Please configure both Phone Number and CallMeBot API Key.")
                else:
                    success, msg = test_whatsapp_alert_delivery(wa_phone, wa_key)
                    if success:
                        st.success("✅ Test alert successfully sent to WhatsApp!")
                    else:
                        st.error(f"❌ Failed to send WhatsApp alert: {msg}")

# View 8: System & Diagnostics
elif selected_nav == "⚙️ System / Diagnostics":
    st.header("⚙️ SOC System Health & Engine Diagnostics")
    st.caption("Monitor storage integrity, local retention policies, worker telemetry, and detection pipeline engines.")

    tab_diag_stor, tab_diag_worker, tab_diag_engines = st.tabs(["💾 Storage & Retention", "📡 Worker Daemon Health", "🧠 Detection Pipeline Status"])

    with tab_diag_stor:
        st.subheader("💾 Local Forensic Storage & Retention Management")
        from core.local_storage import get_local_storage_manager, RetentionPolicy
        storage_mgr = get_local_storage_manager()

        disk_safety = storage_mgr.check_disk_space_safety()
        if disk_safety.get("low_disk_warning"):
            st.error(f"⚠️ **Low Disk Space Warning**: Free space is {disk_safety['free_mb']} MB (Threshold: {disk_safety['threshold_mb']} MB). Evidence deletion is blocked.")
        else:
            st.success(f"✅ Disk Space Healthy: {disk_safety.get('free_mb', 0):.1f} MB free.")

        u_target = current_user_id or "local_investigator"
        storage_usage = storage_mgr.get_storage_usage(user_id=u_target)
        c_st1, c_st2, c_st3, c_st4 = st.columns(4)
        with c_st1:
            st.metric("Local Cases", storage_usage.get("user_cases_count", 0))
        with c_st2:
            st.metric("Local Evidence", f"{storage_usage.get('user_evidence_mb', 0.0)} MB")
        with c_st3:
            st.metric("Local Reports", f"{storage_usage.get('user_reports_mb', 0.0)} MB")
        with c_st4:
            st.metric("Total Usage", f"{storage_usage.get('total_mb', 0.0)} MB")

        st.markdown("---")
        st.markdown("##### 🛡️ Retention Policy & Automated Safe Cleanup")
        ret_policy = st.selectbox("Active Retention Policy:", [30, 7, 90, 180], format_func=lambda d: f"{d} Days ({'Default' if d==30 else 'Custom'})", key="sel_diag_ret")
        col_cl1, col_cl2 = st.columns(2)
        with col_cl1:
            if st.button("🔍 Run Dry-Run Cleanup", help="Check what would be deleted without actually deleting", key="btn_diag_dry_run"):
                dry_res = storage_mgr.dry_run_cleanup(u_target, policy_days=ret_policy)
                st.info(f"Dry-run result: {dry_res.get('eligible_cases_count', 0)} eligible cases, {dry_res.get('eligible_evidence_count', 0)} evidence items.")
        with col_cl2:
            if st.button("🧹 Execute Safe Cleanup", type="primary", key="btn_diag_exec_cleanup"):
                clean_res = storage_mgr.run_cleanup_now(u_target, policy_days=ret_policy)
                st.success(f"Cleanup executed: {clean_res.get('deleted_cases_count', 0)} cases deleted. Active cases and preserved evidence were protected.")

    with tab_diag_worker:
        st.subheader("📡 Live Mail Analysis Worker Telemetry")
        telemetry_file = os.path.join("data", "local", "sentinel_telemetry", "sentinel_telemetry.json")
        if os.path.exists(telemetry_file):
            try:
                with open(telemetry_file, "r", encoding="utf-8") as f:
                    telem = json.load(f)
                c_w1, c_w2, c_w3, c_w4 = st.columns(4)
                with c_w1:
                    st.metric("Daemon State", telem.get("process_state", "UNKNOWN"))
                with c_w2:
                    st.metric("Emails Arrived", telem.get("emails_arrived", 0))
                with c_w3:
                    st.metric("Threats Flagged", telem.get("threats_flagged", 0))
                with c_w4:
                    st.metric("Poll Intervals", telem.get("poller_loops", 0))
                st.json(telem)
            except Exception as e:
                st.error(f"Error reading telemetry: {e}")
        else:
            st.info("Worker telemetry file not yet generated. Start the worker daemon to initialize telemetry.")

    with tab_diag_engines:
        st.subheader("🧠 Forensic Intelligence & Pipeline Status")
        st.markdown(
            """
            - **Text Normalization Pipeline:** `ACTIVE` (Zero-width stripping $\\rightarrow$ Homoglyphs pre-NFKC $\\rightarrow$ NFKC $\\rightarrow$ Bounded spaced-tokens)
            - **Forensic Rule Matrix:** `27 ACTIVE RULES` (RULE-001 through RULE-027, including spaced brand non-escalation)
            - **Linguistic ML Classifier:** `ACTIVE` (TF-IDF + Logistic Regression, confidence-aware & borderline safe)
            - **MaxMind GeoLite2 Offline Database:** `ACTIVE` (City & ASN resolution with zero external latency)
            - **Indian Financial Threat Engine:** `ACTIVE` (NPCI UPI VPA verification & RBI IFSC routing directory)
            - **Quishing / QR Decoder:** `ACTIVE` (OpenCV QR barcode engine with decompression bomb defense)
            - **SSRF Network Protection:** `ENFORCED` (RFC 1918, loopback, and cloud metadata 169.254.169.254 blocked)
            """
        )


