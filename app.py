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
from core.session_vault import load_session_credentials, save_session_credentials, clear_session_credentials
import plotly.express as px

st.set_page_config(page_title="EMAILSHIELD INDIA", layout="wide")

# Initialize models
@st.cache_resource
def load_ml_classifier():
    return MLClassifier()

ml_classifier = load_ml_classifier()
forensic_agent = AutonomousForensicAgent(ml_classifier)

# Automatically restore saved 14-day hardware-bound encrypted session vault
if "mailbox_connected" not in st.session_state:
    saved_session = load_session_credentials()
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
        "🔒 Keep me logged in for 2 weeks",
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
                    save_session_credentials(u_email, u_pass, target_host, provider_name, days=14)
                    st.session_state["session_days_left"] = 14
                else:
                    clear_session_credentials()
                    st.session_state.pop("session_days_left", None)
                st.session_state["mailbox_connected"] = True
                st.session_state["mailbox_type"] = "IMAP"
                st.session_state["mailbox_creds"] = {
                    "email": u_email, "pwd": u_pass, "host": target_host, "provider": provider_name
                }
                st.session_state.pop("recent_emails", None)
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
        if st.sidebar.button("Disconnect"):
            clear_session_credentials()
            st.session_state["mailbox_connected"] = False
            st.session_state.pop("recent_emails", None)
            st.session_state.pop("mailbox_creds", None)
            st.session_state.pop("session_days_left", None)
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
nav_options = ["🔍 Single Case Investigation", "📊 Today's Mailbox Analytics"]
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

# View 3: Single Case Investigation
elif selected_nav == "🔍 Single Case Investigation":
    col_up1, col_up2 = st.columns([3, 1])
    with col_up1:
        uploaded_file = st.file_uploader("Upload .eml file locally", type=["eml"])
        if uploaded_file is not None:
            st.session_state["batch_results"] = None
            st.session_state["current_email_bytes"] = uploaded_file.getvalue()
    with col_up2:
        st.write("Or quick test:")
        if st.button("🧪 Load Sample Phishing"):
            with open("samples/phishing.eml", "rb") as f:
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
<h4 style="margin-top: 0; color: #38bdf8;">🧪 1-Click Instant Demo</h4>
<p style="color: #cbd5e1; font-size: 0.9em;">
Instantly run full AI forensics on a pre-packaged multi-stage financial phishing attack sample (.eml):
</p>
<ul style="color: #94a3b8; font-size: 0.85em;">
<li>Autonomous ReAct agent reasoning trace</li>
<li>Hop-by-hop relay flight path visualization</li>
<li>Domain reputation &amp; ICANN RDAP analysis</li>
<li>Court-admissible tamper-proof PDF generation</li>
</ul>
</div>
""",
                unsafe_allow_html=True
            )
            if st.button("🚀 Analyze Sample Phishing Email (.eml)", type="primary", use_container_width=True):
                with open("samples/phishing.eml", "rb") as f:
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

        threat_v = bec_obj.verdict if bec_obj else risk_score
        verdict_c = bec_obj.confidence_pct if bec_obj else (90 if risk_score == "HIGH" else 75)

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
        
        st.success(f"Analysis Complete: {case_id} — SHA-256: {parsed_data['sha256'][:16]}...")
        
        # Render Dashboard
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "Overview", "Evidence & Auth", "IOCs & Threat Intel", "Detection & Rules",
            "Relay Timeline & Delays", "Investigation Graph & Campaigns", "Reports & Case Management"
        ])
        
        with tab1:
            col_verdict1, col_verdict2, col_verdict3 = st.columns([2, 1, 1])
            with col_verdict1:
                st.markdown(f"### 🎯 Threat Verdict: **{case_report.threat_verdict}**")
                st.caption(f"Case ID: `{case_id}` | Source: `{case_report.ingestion_source}`")
            with col_verdict2:
                st.metric("Confidence", f"{case_report.verdict_confidence}%")
            with col_verdict3:
                st.metric("Risk Score", risk_score)

            # BEC & Display-Name Spoofing Alert Card
            if case_report.bec_telemetry and (case_report.bec_telemetry.is_display_name_spoof or case_report.bec_telemetry.is_financial_lure):
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
            critical_or_high_urls = [u for u in case_report.url_analyses if u.risk_level in ["CRITICAL", "HIGH"]]
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

            if case_report.ai_reasoning:
                st.markdown(case_report.ai_reasoning)
                st.markdown("---")
                
            # Autonomous AI Agent ReAct Trace
            if case_report.agent_trace:
                with st.expander(f"🤖 Autonomous AI Forensic Agent ({len(case_report.agent_trace)} Step ReAct Trail)", expanded=True):
                    st.caption("The Autonomous AI Agent coordinated multi-source telemetry tools to reconstruct the adversary's attack chain:")
                    for step in case_report.agent_trace:
                        st.markdown(f"**Step {step.step_num}:** `{step.tool_used}`")
                        st.markdown(f"💭 **Thought:** *{step.thought}*")
                        st.markdown(f"🛠️ **Action:** `{step.action}`")
                        st.markdown(f"👁️ **Observation:** {step.observation}")
                        st.markdown("---")
                        
            st.write("### Detection Reasons")
            for r in reasons:
                st.write(f"- {r}")
            if case_report.forwarded_by:
                st.info(f"📬 **Forwarded for Verification by User:** `{case_report.forwarded_by}`")
            
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
                dcol2.metric("Domain Age", f"{dr.domain_age_days} days" if dr.domain_age_days is not None else "Unknown")
                dcol3.metric("Registrar", (dr.registrar or "Unknown")[:25])
                dcol4.metric("NRD Flag (< 30d)", "🚨 YES (High Threat)" if dr.is_nrd else "✅ NO (Established)")
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
            
            # Re-fetch updated metadata for PDF
            updated_case_dict = case_report.model_dump()
            updated_case_dict["status"] = new_status
            updated_case_dict["assigned_investigator"] = new_investigator
            updated_case_dict["analyst_notes"] = new_notes
            
            generate_pdf_report(updated_case_dict, pdf_path)
            generate_json_report(updated_case_dict, json_path)
            
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                with open(pdf_path, "rb") as f:
                    st.download_button("📜 Download Court-Admissible PDF Report", f, file_name=f"{case_id}_forensic_report.pdf", mime="application/pdf", use_container_width=True)
            with col_d2:
                with open(json_path, "rb") as f:
                    st.download_button("⚡ Download Full Forensic JSON", f, file_name=f"{case_id}.json", mime="application/json", use_container_width=True)

