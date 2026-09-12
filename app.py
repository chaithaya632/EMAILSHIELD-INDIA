import streamlit as st
import uuid
import datetime
import os
from core.parser import SecureEmailParser
from core.indicators import extract_all_indicators
from core.auth_claims import parse_auth_results, evaluate_auth_and_alignment
from core.geolocation import get_geolocation
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.classifier import MLClassifier
from core.case_store import save_case, get_all_cases, update_case_metadata, get_case_record, export_case_iocs_csv, export_case_iocs_json
from core.correlation import build_correlation_graph, get_campaign_clusters
from core.report import generate_pdf_report, generate_json_report
from core.schemas import (
    CaseReport, Indicator, GeolocationInfo, AuthEvidence, RuleFinding,
    MLAssessment, EventTimeline, AttachmentAnalysisResult, LookalikeAnalysis,
    BECTelemetry, AuthAlignmentResult
)
from core.attachments import analyze_all_attachments
from core.lookalike import detect_lookalike_domain
from core.bec_detector import detect_bec_and_impersonation
from core.gmail_integration import fetch_recent_emails, fetch_raw_email
from core.batch_scanner import scan_mailbox_batch
from core.mailbox_connector import test_imap_connection, fetch_imap_emails, fetch_imap_raw_email, PROVIDER_CONFIGS, get_provider_host
from core.domain_reputation import get_domain_reputation
from core.relay_tracer import build_relay_flight_map, analyze_relay_transit
from core.ai_reasoning import generate_forensic_reasoning
from core.agent import AutonomousForensicAgent
from core.session_vault import (
    load_session_credentials,
    save_session_credentials,
    save_account_credentials,
    list_saved_accounts,
    get_account_credentials,
    switch_active_account,
    forget_account,
    clear_session_credentials
)
from core.indian_banking import extract_indian_financial_indicators
from core.quishing import scan_for_quishing
from core.eml_sanitizer import sanitize_eml_content
from core.header_diff import compare_headers_against_baseline, BRAND_BASELINES
from core.ncrp_packager import generate_ncrp_complaint_text, generate_ncrp_pdf_annexure
import plotly.express as px
from core.sentinel import sentinel_manager, send_test_alert

st.set_page_config(page_title="EMAILSHIELD INDIA", layout="wide")

# Initialize models
@st.cache_resource
def load_ml_classifier():
    return MLClassifier()

ml_classifier = load_ml_classifier()
forensic_agent = AutonomousForensicAgent(ml_classifier)

# Automatically restore saved 14-day hardware-bound encrypted session vault
if "mailbox_connected" not in st.session_state:
    saved_session = get_account_credentials()
    if saved_session:
        st.session_state["mailbox_connected"] = True
        st.session_state["mailbox_type"] = "IMAP"
        st.session_state["mailbox_creds"] = {
            "email": saved_session["email"],
            "pwd": saved_session["pwd"],
            "host": saved_session["host"],
            "provider": saved_session.get("provider", "Gmail")
        }
        st.session_state["session_days_left"] = saved_session.get("days_remaining", 14)

st.title("🛡️ EMAILSHIELD INDIA")
st.subheader("AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform")

st.sidebar.header("📬 Connect Mailbox")
st.sidebar.write("Inspect live inboxes directly without cloud console setup.")

if not st.session_state.get("mailbox_connected", False):
    saved_accounts = list_saved_accounts()
    show_new_account_form = True
    
    if saved_accounts:
        st.sidebar.markdown("### 🔒 Saved Mailboxes")
        st.sidebar.caption("Hardware-bound AES-256 encrypted vault (14-day TTL)")
        
        acc_labels = [f"📧 {a['email']} ({a['provider']})" for a in saved_accounts]
        acc_labels.append("➕ Connect New Account")
        
        sel_idx = len(acc_labels) - 1 if st.session_state.get("add_new_account_mode", False) else 0
        selected_option = st.sidebar.radio("Select Account:", acc_labels, index=sel_idx, key="saved_acc_radio")
        
        if selected_option != "➕ Connect New Account":
            show_new_account_form = False
            chosen_idx = acc_labels.index(selected_option)
            chosen_acc = saved_accounts[chosen_idx]
            
            st.sidebar.markdown(
                f"""
<div style="background-color: #0f172a; border-left: 4px solid #10b981; padding: 10px; border-radius: 6px; font-size: 0.85em; margin: 8px 0 12px 0;">
<b>Provider:</b> {chosen_acc['provider']}<br>
<b>Host:</b> <code>{chosen_acc['host']}</code><br>
<b>Vault Status:</b> 🔒 Active ({chosen_acc['days_remaining']} days left)
</div>
""",
                unsafe_allow_html=True
            )
            
            col_act1, col_act2 = st.sidebar.columns([3, 2])
            with col_act1:
                if col_act1.button("🚀 Connect Inbox", type="primary", key="btn_connect_saved"):
                    creds = switch_active_account(chosen_acc["email"])
                    if creds:
                        st.session_state["mailbox_connected"] = True
                        st.session_state["mailbox_type"] = "IMAP"
                        st.session_state["mailbox_creds"] = {
                            "email": creds["email"], "pwd": creds["pwd"], "host": creds["host"], "provider": creds.get("provider", "Gmail")
                        }
                        st.session_state["session_days_left"] = creds.get("days_remaining", 14)
                        st.session_state.pop("recent_emails", None)
                        st.session_state["add_new_account_mode"] = False
                        st.rerun()
            with col_act2:
                if col_act2.button("🗑️ Forget", key="btn_forget_saved", help="Shred credentials for this account"):
                    forget_account(chosen_acc["email"])
                    st.rerun()
        else:
            show_new_account_form = True

    if show_new_account_form:
        if saved_accounts:
            st.sidebar.markdown("---")
            st.sidebar.markdown("#### ➕ Connect Another Mailbox")
            
        provider_name = st.sidebar.selectbox("Email Service:", ["Gmail", "Outlook / Office 365", "Yahoo Mail", "Zoho Mail", "Custom / Corporate"])
        
        # Dynamic 30-Second Setup Guide with direct links
        if provider_name == "Gmail":
            st.sidebar.markdown(
                """
<div style="background-color: #0f172a; border-left: 4px solid #38bdf8; padding: 10px; border-radius: 6px; font-size: 0.85em; margin: 8px 0 12px 0;">
<b>⚡ Quick 30s Setup for Gmail:</b><br>
1️⃣ <a href="https://myaccount.google.com/apppasswords" target="_blank" style="color: #38bdf8; font-weight: bold; text-decoration: underline;">👉 Click here to open Google App Passwords ↗</a><br>
2️⃣ In "App name", type <b>EMAILSHIELD</b> & click <b>Create</b>.<br>
3️⃣ Copy the <b>16-letter code</b> & paste it below!
<br><br>
<span style="color: #94a3b8; font-size: 0.9em;">🔒 <b>100% Free &amp; Safe:</b> Requires 2-Step Verification ON. Your real password is never entered or shared.</span>
</div>
""",
                unsafe_allow_html=True
            )
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
        u_pass = st.sidebar.text_input("App Password:", type="password", help="16-character code created above. Spaces are automatically removed.")
        
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
            
        remember_me = st.sidebar.checkbox(
            "🔒 Remember this account for 2 weeks",
            value=True,
            help="Encrypted with hardware-bound AES-256 (600,000 PBKDF2 rounds). Automatically expires and shreds after 14 days."
        )
            
        if st.sidebar.button("Connect Mailbox", type="primary"):
            if u_email and u_pass:
                target_host = c_host if provider_name == "Custom / Corporate" else get_provider_host(provider_name, u_email)
                with st.spinner("Authenticating with mail server..."):
                    ok, conn_msg = test_imap_connection(u_email, u_pass, target_host)
                if ok:
                    if remember_me:
                        save_account_credentials(u_email, u_pass, target_host, provider_name, days=14)
                        st.session_state["session_days_left"] = 14
                    else:
                        st.session_state.pop("session_days_left", None)
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
    disp_email = creds.get("email", "Google OAuth User") if m_type == "IMAP" else "Google Account"
    
    col_mb1, col_mb2 = st.sidebar.columns([3, 1])
    with col_mb1:
        st.sidebar.write(f"📬 **Connected:** `{disp_email[:20]}`")
        if st.session_state.get("session_days_left"):
            days_left = st.session_state["session_days_left"]
            st.sidebar.caption(f"🔒 Encrypted Vault: **{days_left}d remaining**")
    with col_mb2:
        if st.sidebar.button("Disconnect", help="Log out of current view (account stays in saved vault)"):
            st.session_state["mailbox_connected"] = False
            st.session_state.pop("recent_emails", None)
            st.session_state.pop("mailbox_creds", None)
            st.session_state.pop("session_days_left", None)
            st.rerun()

    # Multi-Account Fast Switcher in Sidebar
    all_saved = list_saved_accounts()
    other_accounts = [a for a in all_saved if a["email"] != creds.get("email")]
    
    if other_accounts or len(all_saved) > 1:
        with st.sidebar.expander("🔄 Switch Mailbox Account", expanded=False):
            if other_accounts:
                switch_opts = [f"{a['email']} ({a['provider']} - {a['days_remaining']}d left)" for a in other_accounts]
                target_choice = st.selectbox("Switch to saved inbox:", switch_opts, key="sw_account_select")
                
                col_sw1, col_sw2 = st.columns([3, 2])
                with col_sw1:
                    if col_sw1.button("🚀 Switch", key="btn_do_switch"):
                        target_email = target_choice.split(" ")[0]
                        new_creds = switch_active_account(target_email)
                        if new_creds:
                            st.session_state["mailbox_connected"] = True
                            st.session_state["mailbox_type"] = "IMAP"
                            st.session_state["mailbox_creds"] = {
                                "email": new_creds["email"], "pwd": new_creds["pwd"], "host": new_creds["host"], "provider": new_creds.get("provider", "Gmail")
                            }
                            st.session_state["session_days_left"] = new_creds.get("days_remaining", 14)
                            st.session_state.pop("recent_emails", None)
                            st.rerun()
                with col_sw2:
                    if col_sw2.button("🗑️ Forget", key="btn_forget_current", help="Shred this account from vault"):
                        forget_account(disp_email)
                        st.session_state["mailbox_connected"] = False
                        st.session_state.pop("recent_emails", None)
                        st.session_state.pop("mailbox_creds", None)
                        st.session_state.pop("session_days_left", None)
                        st.rerun()
            else:
                if st.button("🗑️ Forget This Account", key="btn_forget_only", help="Shred credentials from vault"):
                    forget_account(disp_email)
                    st.session_state["mailbox_connected"] = False
                    st.session_state.pop("recent_emails", None)
                    st.session_state.pop("mailbox_creds", None)
                    st.session_state.pop("session_days_left", None)
                    st.rerun()
                    
            if st.button("➕ Connect Another Account", key="btn_add_another_connected"):
                st.session_state["mailbox_connected"] = False
                st.session_state["add_new_account_mode"] = True
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
                        fetched = fetch_recent_emails(max_results=limit_val, query=query_val)
                        if not fetched and query_val:
                            fetched = fetch_recent_emails(max_results=limit_val)
                        st.session_state["recent_emails"] = fetched
                except Exception as fetch_err:
                    st.sidebar.error(f"Fetch error: {str(fetch_err)}")
                    st.session_state["recent_emails"] = []
            st.rerun()

        recent_emails = st.session_state.get("recent_emails", [])
        
        if st.sidebar.button(f"Scan Loaded Emails ({len(recent_emails)}) [Batch]"):
            st.session_state["current_email_bytes"] = None 
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
                st.session_state["batch_results"] = scan_mailbox_batch(
                    ml_classifier, max_emails=len(recent_emails), query=query_val, progress_callback=scan_progress,
                    custom_emails=recent_emails
                )
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
                    msg['id']: f"{msg.get('date', '')[:16]} | {msg.get('sender', '')[:20]} | {msg.get('subject', '')[:30]}"
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
                            bytes_data = fetch_raw_email(selected_msg_id)
                    st.session_state["batch_results"] = None
                    st.session_state["current_email_bytes"] = bytes_data
                    st.session_state["active_view_idx"] = 0
                    st.rerun()
            else:
                st.sidebar.warning(f"No emails matching '{filter_kw}'.")
        else:
            st.sidebar.info("No emails found in this mailbox.")
    except Exception as e:
        st.sidebar.error(f"Mailbox Error: {str(e)}")

# Sidebar Navigation
st.sidebar.markdown("---")
st.sidebar.subheader("🛡️ Platform Modes")
nav_options = [
    "🔍 Single Case Investigation",
    "📊 Today's Mailbox Analytics",
    "📡 Live Mailbox Sentinel (50s Auto-Defense)"
]
current_idx = min(st.session_state.get("active_view_idx", 0), len(nav_options) - 1)
selected_nav = st.sidebar.radio("Active View:", nav_options, index=current_idx)

# View 1: Mailbox Batch Analytics
if selected_nav == "📊 Today's Mailbox Analytics":
    batch_data = st.session_state.get("batch_results")
    if batch_data:
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
    else:
        st.info("No batch scan results available yet. Click 'Scan Today's Emails (Batch)' in the sidebar to run a scan!")

# View 2: Live Mailbox Sentinel
elif selected_nav == "📡 Live Mailbox Sentinel (50s Auto-Defense)":
    st.header("📡 Live Mailbox Sentinel (50s Auto-Defense)")
    st.markdown(
        "**Autonomous continuous mailbox monitoring:** Keeps track of the last analyzed email checkpoint, "
        "detects newly arriving emails every 50 seconds, runs deep multi-tier forensic inspection, "
        "and dispatches instant mobile alerts via WhatsApp and Telegram when threats are uncovered."
    )

    is_connected = st.session_state.get("mailbox_connected", False)
    m_type = st.session_state.get("mailbox_type", "IMAP")
    creds = st.session_state.get("mailbox_creds", {})

    state_dict = sentinel_manager.get_state_summary()
    is_active = state_dict["is_running"]

    # Top Status Bar
    if is_active:
        st.success(
            f"🟢 **LIVE SHIELD ACTIVE** — Polling `{creds.get('email', 'Mailbox')}` every "
            f"**{state_dict['poll_interval']}s**. Next checkpoint check in **{state_dict['next_check_countdown']}s**."
        )
    else:
        st.info("⚪ **LIVE SHIELD STANDBY** — Configure alert credentials below and click 'Start Live Protection'.")

    # High-level Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Sentinel Status", "🟢 Active" if is_active else "⚪ Standby")
    m2.metric("Total Analyzed", state_dict["total_scanned"])
    m3.metric("Phishing Blocked", state_dict["phishing_count"])
    m4.metric("Mobile Alerts Sent", state_dict["alerts_sent"])

    st.markdown("---")

    col_ctrl, col_notify = st.columns([1, 1])

    with col_ctrl:
        st.subheader("🛡️ Sentinel Control Center")
        if not is_connected:
            st.warning("⚠️ No mailbox connected. Please connect your Gmail, Outlook, Yahoo, or IMAP account using the sidebar to enable Live Sentinel.")
        else:
            st.write(f"**Connected Mailbox:** `{creds.get('email')}` ({m_type})")

            # Checkpoint Info Card
            st.markdown(
                f"""
<div style="background-color: #1e293b; border-left: 4px solid #38bdf8; padding: 12px; border-radius: 6px; margin-bottom: 15px;">
<div style="font-size: 0.8em; color: #94a3b8; font-weight: 600; text-transform: uppercase;">Last Analyzed Checkpoint</div>
<div style="font-size: 1.05em; font-weight: 700; color: #f8fafc; margin-top: 4px;">{state_dict['checkpoint_subject'][:50]}</div>
<div style="font-size: 0.85em; color: #cbd5e1; margin-top: 4px;"><b>Sender:</b> {state_dict['checkpoint_sender'][:40]}</div>
<div style="font-size: 0.8em; color: #64748b; margin-top: 4px;"><b>Time:</b> {state_dict['checkpoint_date']} | <b>Last Check:</b> {state_dict['last_checked_time']}</div>
</div>
""",
                unsafe_allow_html=True
            )

            poll_sec = st.slider("Polling Frequency (seconds):", min_value=30, max_value=120, value=50, step=10, key="sentinel_poll_slider")

            c_btn1, c_btn2 = st.columns(2)
            with c_btn1:
                if not is_active:
                    if st.button("🟢 Start Live Protection", type="primary", use_container_width=True, key="btn_start_sentinel"):
                        alert_cfg = {
                            "whatsapp_enabled": st.session_state.get("sentinel_wa_enabled", False),
                            "whatsapp_phone": st.session_state.get("sentinel_wa_phone", ""),
                            "whatsapp_apikey": st.session_state.get("sentinel_wa_key", ""),
                            "telegram_enabled": st.session_state.get("sentinel_tg_enabled", False),
                            "telegram_token": st.session_state.get("sentinel_tg_token", ""),
                            "telegram_chat_id": st.session_state.get("sentinel_tg_cid", "")
                        }
                        ok, msg = sentinel_manager.start(
                            mailbox_type=m_type,
                            mailbox_creds=creds,
                            alert_config=alert_cfg,
                            ml_classifier=ml_classifier,
                            poll_interval=poll_sec
                        )
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                else:
                    if st.button("🔴 Stop Live Protection", use_container_width=True, key="btn_stop_sentinel"):
                        ok, msg = sentinel_manager.stop()
                        st.warning(msg)
                        st.rerun()
            with c_btn2:
                if st.button("🔄 Refresh Status", use_container_width=True, key="btn_refresh_sentinel"):
                    st.rerun()

    with col_notify:
        st.subheader("📱 Mobile Threat Alerts (Free)")
        st.caption("Receive instant notifications directly on your phone when HIGH / MALICIOUS risks are detected.")

        # WhatsApp Setup
        wa_enabled = st.checkbox("💬 Enable WhatsApp Alerts (CallMeBot API - ₹0 Free)", value=st.session_state.get("sentinel_wa_enabled", False), key="sentinel_wa_enabled")
        if wa_enabled:
            with st.expander("⚡ How to get your Free CallMeBot API Key (30 Seconds)", expanded=True):
                st.markdown(
                    """
<div style="background-color: #0f172a; border-left: 4px solid #22c55e; padding: 12px; border-radius: 6px; font-size: 0.9em; margin-bottom: 12px;">
<b style="color: #22c55e;">Quick 3-Step Setup (100% Free Forever):</b><br>
<b>1. Click Direct Link:</b> 👉 <a href="https://wa.me/34941872320?text=I%20allow%20callmebot%20to%20send%20me%20messages" target="_blank" style="color: #38bdf8; font-weight: bold; text-decoration: underline;">Click Here to Open WhatsApp with Bot</a><br>
<span style="color: #94a3b8; font-size: 0.85em;">(Or message <code>+34 941 87 23 20</code> on WhatsApp)</span><br><br>
<b>2. Send Message:</b> Send this text to the bot: <code>I allow callmebot to send me messages</code><br><br>
<b>3. Copy API Key:</b> The bot will reply within 5 seconds with: <i>"API Key generated: <b>123456</b>"</i>.<br>
Copy that number and paste it below!
</div>
""",
                    unsafe_allow_html=True
                )
            wa_phone = st.text_input("WhatsApp Phone (+country code):", value=st.session_state.get("sentinel_wa_phone", ""), placeholder="+919876543210", key="sentinel_wa_phone")
            wa_key = st.text_input("CallMeBot API Key:", value=st.session_state.get("sentinel_wa_key", ""), type="password", placeholder="e.g. 123456", key="sentinel_wa_key")
            
            if st.button("🧪 Send Test WhatsApp Alert", key="btn_test_wa"):
                if not wa_phone or not wa_key:
                    st.error("Please enter your phone number and CallMeBot API key first.")
                else:
                    with st.spinner("Sending test ping to WhatsApp..."):
                        t_ok, t_msg = send_test_alert("whatsapp", {"whatsapp_phone": wa_phone, "whatsapp_apikey": wa_key})
                    if t_ok:
                        st.success("✅ WhatsApp test message delivered! Check your phone.")
                    else:
                        st.error(f"Dispatch failed: {t_msg}")

        # Telegram Setup
        st.markdown("---")
        tg_enabled = st.checkbox("✈️ Enable Telegram Alerts (Telegram Bot - ₹0 Free)", value=st.session_state.get("sentinel_tg_enabled", False), key="sentinel_tg_enabled")
        if tg_enabled:
            tg_token = st.text_input("Telegram Bot Token:", value=st.session_state.get("sentinel_tg_token", ""), type="password", placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ", key="sentinel_tg_token")
            tg_cid = st.text_input("Telegram Chat ID:", value=st.session_state.get("sentinel_tg_cid", ""), placeholder="e.g. 987654321", key="sentinel_tg_cid")
            st.caption("💡 **Free Telegram Setup**: Message `@BotFather` and send `/newbot` to get your token. Get your Chat ID from `@userinfobot`.")
            
            if st.button("🧪 Send Test Telegram Alert", key="btn_test_tg"):
                if not tg_token or not tg_cid:
                    st.error("Please enter both your Bot Token and Chat ID first.")
                else:
                    with st.spinner("Sending test ping to Telegram..."):
                        t_ok, t_msg = send_test_alert("telegram", {"telegram_token": tg_token, "telegram_chat_id": tg_cid})
                    if t_ok:
                        st.success("✅ Telegram test message delivered! Check your phone.")
                    else:
                        st.error(f"Dispatch failed: {t_msg}")

    # Inbound Activity Stream & Audit Log
    st.markdown("---")
    st.subheader("📋 Inbound Activity Stream & Threat Audit Log")

    recent_act = state_dict.get("recent_activity", [])
    if recent_act:
        formatted_table = []
        for a in recent_act:
            v_badge = "🟢 SAFE"
            if a["verdict"] == "HIGH":
                v_badge = "🔴 HIGH RISK"
            elif a["verdict"] == "SUSPICIOUS":
                v_badge = "🟡 SUSPICIOUS"
            
            alert_str = "—"
            if a.get("alert_sent"):
                alert_str = f"🔔 Sent ({a.get('alert_channel', '')})"
            elif a.get("verdict") == "HIGH":
                alert_str = "⚠️ Failed / Disabled"

            formatted_table.append({
                "Time": a["timestamp"],
                "Verdict": v_badge,
                "Threat Score": f"{a['score']}/100",
                "Sender": a["sender"][:30],
                "Subject": a["subject"][:40],
                "Mobile Alert": alert_str
            })
        st.dataframe(formatted_table, use_container_width=True)
    else:
        st.info("No new emails evaluated during this session yet. As incoming mail arrives, each item will appear here with its threat score and alert delivery status.")

    if state_dict.get("error_log"):
        with st.expander("⚠️ Sentinel Warning / Diagnostics Log"):
            for err in state_dict["error_log"]:
                st.code(err)

# View 3: Single Case Investigation
elif selected_nav == "🔍 Single Case Investigation":
    col_up1, col_up2 = st.columns([3, 1])
    with col_up1:
        uploaded_file = st.file_uploader("Upload .eml file locally", type=["eml"])
        if uploaded_file is not None:
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
                
        # 4. Geolocation
        geolocations = []
        for ip in raw_iocs["ipv4"]:
            geo = get_geolocation(ip)
            geolocations.append(GeolocationInfo(**geo))
            
        # 5. Autonomous ReAct Forensic Investigation
        subject = str(headers.get("subject", ""))
        sender_val = str(headers.get("from", "Unknown"))
        
        agent_out = forensic_agent.run_investigation(parsed_data, raw_iocs)
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

        # Restore existing case management notes/status if case was already opened
        existing_rec = get_case_record(case_id)
        current_status = existing_rec.get("status", "Open") if existing_rec else "Open"
        current_inv = existing_rec.get("assigned_investigator", "Unassigned") if existing_rec else "Unassigned"
        current_notes = existing_rec.get("analyst_notes", "") if existing_rec else ""

        threat_v = bec_obj.verdict if bec_obj else ("Standard / Legitimate" if risk_score == "LOW" else risk_score)
        if risk_score == "LOW" and threat_v in ["Business Email Compromise (BEC / Wire Fraud)", "Executive Impersonation", "Credential Harvesting", "Malware Delivery"]:
            threat_v = "Standard / Legitimate"
        verdict_c = bec_obj.confidence_pct if bec_obj else (90 if risk_score == "HIGH" else 85)

        case_report = CaseReport(
            case_id=case_id,
            timestamp=datetime.datetime.utcnow(),
            original_sha256=parsed_data["sha256"],
            subject=subject,
            sender=sender_val,
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
            risk_score=risk_score,
            risk_reasons=reasons
        )
        
        # Save to SQLite
        save_case(case_report.model_dump())
        
        col_succ, col_rst = st.columns([3, 1])
        with col_succ:
            st.success(f"Analysis Complete: {case_id} — SHA-256: {parsed_data['sha256'][:16]}...")
        with col_rst:
            if st.button("🔄 Reset / Test Another", help="Clear current email and load another sample or file", key="btn_reset_analysis"):
                st.session_state["current_email_bytes"] = None
                st.rerun()
        
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
                    st.caption(f"Case ID: `{case_id}` | Source: `{case_report.ingestion_source}`")
                with col_safe2:
                    st.metric("Safety Confidence", f"{case_report.verdict_confidence}%")
                with col_safe3:
                    st.metric("Risk Level", "LOW", delta="SAFE", delta_color="normal")
                    
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
                        
                    c_meta1, c_meta2, c_meta3 = st.columns(3)
                    with c_meta1:
                        st.metric("SHA-256", f"{parsed_data['sha256'][:16]}...", help=parsed_data['sha256'])
                    with c_meta2:
                        st.metric("Sender", case_report.sender[:25])
                    with c_meta3:
                        st.metric("Subject", case_report.subject[:25])
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
                    st.caption(f"Case ID: `{case_id}` | Source: `{case_report.ingestion_source}`")
                with col_verdict2:
                    st.metric("Confidence", f"{case_report.verdict_confidence}%")
                with col_verdict3:
                    st.metric("Risk Score", risk_score, delta="MALICIOUS" if risk_score == "HIGH" else "SUSPICIOUS", delta_color="inverse")

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
                            
                    c_meta1, c_meta2, c_meta3 = st.columns(3)
                    with c_meta1:
                        st.metric("SHA-256", f"{parsed_data['sha256'][:16]}...", help=parsed_data['sha256'])
                    with c_meta2:
                        st.metric("Sender", case_report.sender[:25])
                    with c_meta3:
                        st.metric("Subject", case_report.subject[:25])
            
        with tab2:
            st.subheader("🔐 Cryptographic Authentication & DMARC Alignment Matrix (RFC 7489)")
            if case_report.auth_alignment:
                aa = case_report.auth_alignment
                dmarc_badge = "✅ PASS" if "PASS" in aa.effective_dmarc else "🚨 " + aa.effective_dmarc
                
                c_a1, c_a2, c_a3, c_a4 = st.columns(4)
                c_a1.metric("Effective DMARC", dmarc_badge)
                c_a2.metric("SPF Result", f"{aa.spf_result} ({'Aligned' if aa.spf_aligned else 'Unaligned'})")
                c_a3.metric("DKIM Result", f"{aa.dkim_result} ({'Aligned' if aa.dkim_aligned else 'Unaligned'})")
                c_a4.metric("DMARC Claim", aa.dmarc_recorded)

                st.markdown(
                    f"""
                    | Attribute | Inspected Domain | Alignment Status |
                    | :--- | :--- | :--- |
                    | **Visible Header-From** | `{aa.header_from_domain or 'N/A'}` | Target Visible Identity |
                    | **Envelope-From (Return-Path)** | `{aa.envelope_from_domain or 'N/A'}` | {'✅ Aligned with Header-From' if aa.spf_aligned else '⚠️ Unaligned (Bypass Risk)'} |
                    | **DKIM Signing Domain (d=)** | `{aa.dkim_signing_domain or 'N/A'}` | {'✅ Aligned with Header-From' if aa.dkim_aligned else '⚠️ Unaligned (Bypass Risk)'} |
                    """
                )
                
                if aa.advisories:
                    for adv in aa.advisories:
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
            col_exp1, col_exp2, col_exp3 = st.columns(3)
            with col_exp1:
                st.download_button(
                    "📄 Export Case IOCs (CSV)",
                    export_case_iocs_csv(case_id),
                    file_name=f"{case_id}_iocs.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with col_exp2:
                st.download_button(
                    "⚡ Export Case IOCs (JSON)",
                    export_case_iocs_json(case_id),
                    file_name=f"{case_id}_iocs.json",
                    mime="application/json",
                    use_container_width=True
                )
            with col_exp3:
                st.download_button(
                    "🌐 Export All Cases (CSV)",
                    export_case_iocs_csv(),
                    file_name="all_cases_iocs.csv",
                    mime="text/csv",
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
            st.subheader("🌐 Infrastructure Geolocation & Physical Location")
            if geolocations:
                geo_rows = []
                map_coords = []
                for g in geolocations:
                    gd = g.model_dump()
                    geo_rows.append({
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
                    if gd.get("latitude") is not None and gd.get("longitude") is not None:
                        map_coords.append({"lat": gd["latitude"], "lon": gd["longitude"]})

                st.dataframe(geo_rows, use_container_width=True)

                if map_coords:
                    st.markdown("#### 🗺️ Physical Infrastructure Mapping")
                    st.map(map_coords, zoom=2)
            else:
                st.write("No public IP infrastructure observed.")
                
        with tab4:
            st.subheader("🧠 Linguistic Machine Learning Model Assessment")
            st.json(ml_assessment.model_dump())
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
            st.subheader("🕸️ Investigation Correlation Graph & Campaign Clustering")
            clusters = get_campaign_clusters()
            
            cluster_opts = ["All Infrastructure Links"]
            for c in clusters:
                cluster_opts.append(f"{c['campaign_id']} ({c['summary']})")
                
            selected_cluster = st.selectbox("Select Campaign Cluster:", cluster_opts)
            filter_id = None
            if selected_cluster != "All Infrastructure Links":
                filter_id = selected_cluster.split()[0]
                
            if clusters:
                st.markdown("#### 🎯 Active Threat Campaigns Identified Across Database")
                c_rows = []
                for c in clusters:
                    c_rows.append({
                        "Campaign ID": c["campaign_id"],
                        "Linked Cases": c["case_count"],
                        "Associated IOCs": c["ioc_count"],
                        "Shared Vectors": c["summary"]
                    })
                st.dataframe(c_rows, use_container_width=True)
                
            fig = build_correlation_graph(current_case_id=case_id, campaign_filter=filter_id)
            st.plotly_chart(fig, use_container_width=True)
            
        with tab7:
            st.subheader("📝 SOC Case Management & Chain of Custody")
            
            col_m1, col_m2 = st.columns(2)
            with col_m1:
                status_choices = ["Open", "In Progress", "Resolved", "Closed"]
                status_idx = status_choices.index(current_status) if current_status in status_choices else 0
                new_status = st.selectbox("Case Status:", status_choices, index=status_idx)
            with col_m2:
                new_investigator = st.text_input("Assigned Investigator:", value=current_inv)
                
            new_notes = st.text_area("Analyst Case Notes / Investigation Remarks:", value=current_notes, height=120)
            
            if st.button("💾 Save Case Notes & Status", type="primary"):
                update_case_metadata(case_id, status=new_status, investigator=new_investigator, notes=new_notes)
                st.success(f"Case {case_id} updated: Status='{new_status}', Investigator='{new_investigator}'")
                
            st.markdown("---")
            st.subheader("Export Investigation Reports")

            os.makedirs("data/reports", exist_ok=True)
            pdf_path = f"data/reports/{case_id}.pdf"
            json_path = f"data/reports/{case_id}.json"
            
            # Re-fetch updated metadata for PDF & NCRP packager
            updated_case_dict = case_report.model_dump()
            updated_case_dict["status"] = new_status
            updated_case_dict["assigned_investigator"] = new_investigator
            updated_case_dict["investigator"] = new_investigator
            updated_case_dict["analyst_notes"] = new_notes
            updated_case_dict["body_text"] = full_email_body
            updated_case_dict["sha256"] = case_report.original_sha256
            if geolocations:
                updated_case_dict["originating_ip"] = geolocations[0].ip
            
            generate_pdf_report(updated_case_dict, pdf_path)
            generate_json_report(updated_case_dict, json_path)
            
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                with open(pdf_path, "rb") as f:
                    st.download_button("📜 Download Court-Admissible PDF Report", f, file_name=f"{case_id}_forensic_report.pdf", mime="application/pdf", use_container_width=True)
            with col_d2:
                with open(json_path, "rb") as f:
                    st.download_button("⚡ Download Full Forensic JSON", f, file_name=f"{case_id}.json", mime="application/json", use_container_width=True)

            # Indian Cybercrime (I4C / NCRP) Formal Complaint Packager
            st.markdown("---")
            st.subheader("🇮🇳 Indian Cybercrime (I4C / NCRP) Formal Complaint Packager")
            st.caption("Official law enforcement reporting structure ready for submission to cybercrime.gov.in:")
            
            ncrp_text = generate_ncrp_complaint_text(updated_case_dict)
            st.text_area("NCRP Portal Complaint Draft (Copy & Paste ready for cybercrime.gov.in):", value=ncrp_text, height=180)
            
            ncrp_pdf_path = f"data/reports/NCRP_{case_id}.pdf"
            generate_ncrp_pdf_annexure(updated_case_dict, ncrp_pdf_path)
            
            col_pkg1, col_pkg2 = st.columns(2)
            with col_pkg1:
                with open(ncrp_pdf_path, "rb") as nf:
                    st.download_button(
                        "🇮🇳 Download Official NCRP Evidence Annexure (PDF)",
                        nf,
                        file_name=f"I4C_NCRP_Annexure_{case_id}.pdf",
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

        with tab8:
            st.subheader("⚖️ Forensic Header Diff & Baseline Comparator")
            st.caption("Compares suspect email headers against verified legitimate enterprise brand baselines to uncover forged relays, mismatched envelope senders, and spoofed authentication:")
            
            brand_options = ["Auto-Detect from Sender"] + [f"{info['brand_name']} ({dom})" for dom, info in BRAND_BASELINES.items()]
            chosen_brand_option = st.selectbox("Select Baseline Reference:", brand_options, index=0)
            
            target_baseline_domain = None
            if chosen_brand_option != "Auto-Detect from Sender":
                target_baseline_domain = chosen_brand_option.split("(")[-1].strip(")")
                
            suspect_header_payload = {
                "from": str(headers.get("from", "")),
                "sender_name": case_report.sender,
                "return_path": str(headers.get("return-path", "")),
                "dkim_domain": str(agent_out.get("auth_alignment", {}).get("dkim_domain", "")),
                "spf": str(agent_out.get("auth_alignment", {}).get("spf_result", "None")),
                "dkim": str(agent_out.get("auth_alignment", {}).get("dkim_result", "None")),
                "dmarc": str(agent_out.get("auth_alignment", {}).get("dmarc_result", "None")),
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
                status_icon = "✅ MATCH" if cp["status"] == "MATCH" else ("🚨 FORGERY" if cp["status"] == "FORGERY_DETECTED" else "⚠️ ANOMALY")
                checkpoint_rows.append({
                    "Forensic Checkpoint": cp["checkpoint"],
                    "Legitimate Baseline": cp["legitimate_norm"],
                    "Suspect Actual": cp["suspect_actual"],
                    "Verdict": status_icon,
                    "Forensic Finding": cp["finding"]
                })
            st.dataframe(checkpoint_rows, use_container_width=True)


