import streamlit as st
import uuid
import datetime
import io
import html
import hashlib
import math
import plotly.express as px
from typing import Tuple, Dict, Any, List, Optional

from views._theme import (
    inject_theme, page_header, metric_card, status_badge_html, 
    empty_state, section_divider, detail_row, error_card, 
    info_card, success_card, COLORS
)


import json
import pandas as pd
from core.classifier import MLClassifier
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.attachments import analyze_all_attachments

from core.rate_limiter import check_sliding_window_rate_limit
from core.parser import SecureEmailParser
from core.indicators import extract_all_indicators
from core.auth_claims import parse_auth_results, evaluate_auth_and_alignment
from core.geolocation import (
    get_geolocation, get_sender_location, is_public_ip, 
    derive_authoritative_location
)
from core.relay_tracer import analyze_relay_transit, build_relay_flight_map
from core.schemas import (
    CaseReport, Indicator, GeolocationInfo, AuthEvidence, RuleFinding,
    MLAssessment, EventTimeline, AttachmentAnalysisResult, LookalikeAnalysis,
    BECTelemetry, AuthAlignmentResult
)
from core.quishing import scan_for_quishing
from core.indian_banking import extract_indian_financial_indicators
from core.header_diff import compare_headers_against_baseline, BRAND_BASELINES
from core.report import (
    generate_pdf_report, generate_json_report, generate_batch_pdf_report
)
from core.ncrp_packager import generate_ncrp_complaint_text, generate_ncrp_pdf_annexure
from core.eml_sanitizer import sanitize_eml_content
from core.correlation import build_case_infrastructure_graph
from core.batch_scanner import categorize_content
from core.case_store import (
    save_case, get_case_record, get_all_cases, update_case_metadata,
    export_case_iocs_csv, export_case_iocs_json, is_authorized_caller
)
from core.live_mail_adapter import (
    get_authorized_live_mail_messages,
    convert_live_message_to_rfc822_bytes,
    DEFAULT_LIVE_MAIL_LIMIT,
    LIVE_MAIL_LIMIT_OPTIONS,
)
from core.sentinel_control import get_user_mailbox
import core.sentinel_control as _sc

def list_user_mailboxes(user_id: str, client: Any = None) -> List[Dict[str, Any]]:
    mb = get_user_mailbox(user_id, client)
    return [mb] if mb else []

if not hasattr(_sc, "list_user_mailboxes"):
    _sc.list_user_mailboxes = list_user_mailboxes

from core.local_storage import get_local_storage_manager, RetentionPolicy

def check_rate_limit(action: str, max_requests: int = 10, window_seconds: int = 60) -> Tuple[bool, int]:
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

        b_vpn = getattr(getattr(infra, "vpn_indicator", None), "status", "UNKNOWN") if infra else "UNKNOWN"
        b_tor = getattr(getattr(infra, "tor_indicator", None), "status", "UNKNOWN") if infra else "UNKNOWN"
        b_relay = getattr(getattr(infra, "open_relay_indicator", None), "status", "UNKNOWN") if infra else "UNKNOWN"
        b_botnet = getattr(getattr(infra, "botnet_indicator", None), "status", "UNKNOWN") if infra else "UNKNOWN"
        c_ind = getattr(infra, "cloud_indicator", None) if infra else None
        b_cloud = c_ind.provider if (c_ind and c_ind.is_cloud_hosted) else "Dedicated / Non-Cloud"
        b_threat = getattr(getattr(infra, "threat_intel_match", None), "status", "NO_MATCH") if infra else "NO_MATCH"

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
        reg_intel = getattr(infra, "registrar_intel", None) if infra else None
        dns_intel = getattr(infra, "dns_mx_intel", None) if infra else None
        
        dom_val = (getattr(infra, "domain", None) if infra else (getattr(d_rep, "domain", "Unknown") if d_rep else "Unknown"))
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

def render_single_email(current_user_id=None, user_client=None, **ctx):
    """Render upload options or forensic results for a single email."""
    bytes_data = st.session_state.get("current_email_bytes")
    if bytes_data:
        render_forensic_results(bytes_data, current_user_id, user_client, **ctx)
        return

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
                    st.session_state["_cached_analysis_payload"] = None
                    st.rerun()
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
            try:
                with open(target_path, "rb") as f:
                    st.session_state["batch_results"] = None
                    st.session_state["current_email_bytes"] = f.read()
                    st.session_state["_cached_analysis_payload"] = None
                st.rerun()
            except Exception as e:
                st.error(f"Failed to load sample: {e}")

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
            try:
                with open(target_path, "rb") as f:
                    st.session_state["batch_results"] = None
                    st.session_state["current_email_bytes"] = f.read()
                    st.session_state["_cached_analysis_payload"] = None
                st.rerun()
            except Exception as e:
                st.error(f"Failed to load scenario: {e}")

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


def render_forensic_results(bytes_data: bytes, current_user_id: Any = None, user_client: Any = None, **ctx):
    forensic_agent = ctx.get('forensic_agent')
    if forensic_agent is None:
        try:
            from core.classifier import MLClassifier
            from core.agent import AutonomousForensicAgent
            forensic_agent = AutonomousForensicAgent(MLClassifier())
        except Exception:
            pass

    
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
        
    analyzed_uid = st.session_state.get("selected_live_mail_uid")
    if analyzed_uid:
        clean_verdict = "SAFE" if risk_score in ("LOW", "CLEAN", "SAFE") else risk_score
        st.session_state.setdefault("live_mail_analysis_status", {})[analyzed_uid] = clean_verdict

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
            if aa.effective_dmarc == "PASS":
                dmarc_badge = "✅ PASS"
            elif aa.effective_dmarc == "PASS (Delegated ESP)":
                dmarc_badge = "✅ PASS (Delegated ESP)"
            elif "Unverified" in aa.effective_dmarc or "NONE" in aa.effective_dmarc or "UNCONFIGURED" in aa.effective_dmarc:
                dmarc_badge = "ℹ️ " + aa.effective_dmarc
            else:
                dmarc_badge = "🚨 " + aa.effective_dmarc

            if not aa.envelope_from_domain or getattr(aa, 'spf_alignment_status', '') == 'NOT_DETERMINABLE':
                spf_status = "Not determinable"
                envelope_from_dom = "Not available"
                spf_alignment_txt = "Not determinable"
            elif aa.spf_aligned:
                spf_status = "Aligned"
                envelope_from_dom = f"`{aa.envelope_from_domain}`"
                spf_alignment_txt = "✅ Aligned with Header-From"
            else:
                spf_status = "Unaligned"
                envelope_from_dom = f"`{aa.envelope_from_domain}`"
                spf_alignment_txt = "⚠️ Unaligned (Bypass Risk)"

            if not aa.dkim_signing_domain or getattr(aa, 'dkim_alignment_status', '') == 'NOT_DETERMINABLE':
                dkim_status = "Not determinable"
                dkim_signing_dom = "Not available"
                dkim_status_txt = "Not determinable"
            elif aa.dkim_aligned:
                dkim_status = "Aligned"
                dkim_signing_dom = f"`{aa.dkim_signing_domain}`"
                dkim_status_txt = "✅ Aligned with Header-From"
            elif aa.effective_dmarc in ["PASS", "PASS (Delegated ESP)"] or aa.spf_aligned:
                dkim_status = "Unaligned"
                dkim_signing_dom = f"`{aa.dkim_signing_domain}`"
                dkim_status_txt = "ℹ️ Provider / ESP Signed (DMARC Satisfied)"
            else:
                dkim_status = "Unaligned"
                dkim_signing_dom = f"`{aa.dkim_signing_domain}`"
                dkim_status_txt = "⚠️ Unaligned (Bypass Risk)"

            c_a1, c_a2, c_a3, c_a4 = st.columns(4)
            c_a1.metric("Effective DMARC", dmarc_badge)
            c_a2.metric("SPF Result", f"{aa.spf_result} ({spf_status})")
            c_a3.metric("DKIM Result", f"{aa.dkim_result} ({dkim_status})")
            c_a4.metric("DMARC Claim", aa.dmarc_recorded)

            st.markdown(
                f"""
                | Attribute | Inspected Domain | Alignment Status |
                | :--- | :--- | :--- |
                | **Header-From** | `{aa.header_from_domain or 'Not available'}` | Target Visible Identity |
                | **Envelope-From (Return-Path)** | {envelope_from_dom} | {spf_alignment_txt} |
                | **DKIM Signing Domain (d=)** | {dkim_signing_dom} | {dkim_status_txt} |
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
            relay_msg = sloc.get('relay_masked_explanation', "The available email telemetry does not expose a reliable public client/originating IP. The displayed relay/domain information represents mail infrastructure rather than proof of the sender's device IP.")
            st.markdown(f"> {relay_msg}")

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

            st.markdown("#### 🗺️ Approximate Infrastructure Mapping")
            st.info("ℹ️ GeoIP is approximate network-level intelligence. Location is inferred from the public IP address and may represent an ISP, relay, VPN, proxy, hosting provider, or other network endpoint. It does not identify a person's exact physical location.")

            originating_points = []
            relay_points = []
            seen_ips = set()

            for g in geolocations:
                gd = g.model_dump()
                ip = gd.get("ip")
                if not ip or ip in seen_ips:
                    continue
                lat = gd.get("latitude")
                lon = gd.get("longitude")
                if lat is None or lon is None:
                    continue

                seen_ips.add(ip)
                is_sender = (ip == sloc.get("sender_ip"))
                is_originating = (is_sender and sloc.get("is_client_ip", False))
                role = "Originating IP" if is_originating else "Relay IP"
                city = gd.get("city") or "Unknown"
                region = gd.get("region") or "Unknown"
                country = gd.get("country") or "Unknown"
                asn = gd.get("asn") or "Unknown"
                org = gd.get("org") or "Unknown"
                accuracy_radius_km = gd.get("accuracy_radius_km")

                hover_html = (
                    f"<b>{html.escape(str(role))}</b><br>"
                    f"IP: {html.escape(str(ip))}<br>"
                    f"Location: {html.escape(str(city))}, {html.escape(str(region))}, {html.escape(str(country))}<br>"
                    f"ASN: {html.escape(str(asn))}<br>"
                    f"Org: {html.escape(str(org))}<br>"
                    f"Accuracy Radius: {accuracy_radius_km} km"
                )

                pt = {
                    "ip": ip,
                    "lat": lat,
                    "lon": lon,
                    "hover": hover_html
                }
                if is_originating:
                    originating_points.append(pt)
                else:
                    relay_points.append(pt)

            if sloc.get("is_identified") and sloc.get("sender_ip") and sloc.get("latitude") is not None and sloc.get("longitude") is not None:
                ip = sloc["sender_ip"]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    is_originating = sloc.get("is_client_ip", False)
                    role = "Originating IP" if is_originating else "Relay IP"
                    city = sloc.get("city") or "Unknown"
                    region = sloc.get("region") or "Unknown"
                    country = sloc.get("country") or "Unknown"
                    asn = sloc.get("asn") or "Unknown"
                    org = sloc.get("org") or "Unknown"
                    accuracy_radius_km = sloc.get("accuracy_radius_km")

                    hover_html = (
                        f"<b>{html.escape(str(role))}</b><br>"
                        f"IP: {html.escape(str(ip))}<br>"
                        f"Location: {html.escape(str(city))}, {html.escape(str(region))}, {html.escape(str(country))}<br>"
                        f"ASN: {html.escape(str(asn))}<br>"
                        f"Org: {html.escape(str(org))}<br>"
                        f"Accuracy Radius: {accuracy_radius_km} km"
                    )

                    pt = {
                        "ip": ip,
                        "lat": sloc["latitude"],
                        "lon": sloc["longitude"],
                        "hover": hover_html
                    }
                    if is_originating:
                        originating_points.append(pt)
                    else:
                        relay_points.append(pt)

            if not originating_points and not relay_points:
                st.info("No geolocatable public IP coordinates available.")
            else:
                fig_map = go.Figure()

                if originating_points:
                    fig_map.add_trace(go.Scattergeo(
                        lat=[p["lat"] for p in originating_points],
                        lon=[p["lon"] for p in originating_points],
                        mode="markers",
                        name="🟢 Originating IP",
                        marker=dict(
                            size=14,
                            color="#00CC96",
                            line=dict(width=1.5, color="#ffffff")
                        ),
                        hoverinfo="text",
                        hovertext=[p["hover"] for p in originating_points]
                    ))

                if relay_points:
                    fig_map.add_trace(go.Scattergeo(
                        lat=[p["lat"] for p in relay_points],
                        lon=[p["lon"] for p in relay_points],
                        mode="markers",
                        name="🔵 Relay IP",
                        marker=dict(
                            size=10,
                            color="#636EFA",
                            line=dict(width=1, color="#ffffff")
                        ),
                        hoverinfo="text",
                        hovertext=[p["hover"] for p in relay_points]
                    ))

                fig_map.update_geos(
                    showocean=True, oceancolor="#0e1117",
                    showland=True, landcolor="#1e293b",
                    showcountries=True, countrycolor="#334155",
                    showcoastlines=True, coastlinecolor="#334155",
                    showframe=False,
                    bgcolor="#0e1117"
                )
                fig_map.update_layout(
                    paper_bgcolor="#0e1117",
                    plot_bgcolor="#0e1117",
                    margin=dict(l=0, r=0, t=10, b=0),
                    height=480,
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=1.02,
                        xanchor="right",
                        x=1,
                        font=dict(color="#f1f5f9"),
                        bgcolor="rgba(14, 17, 23, 0.8)",
                        bordercolor="#334155"
                    )
                )
                st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("No geolocatable public IP coordinates available.")
                
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



def _process_email_for_batch(
    filename: str,
    file_bytes: bytes,
    ml_classifier: Any,
    fallback_subject: str = "No Subject",
    fallback_sender: str = "Unknown Sender"
) -> Tuple[Dict[str, Any], str]:
    """Helper to parse and evaluate an RFC 822 email for batch analysis in-memory."""
    try:
        parser = SecureEmailParser(file_bytes)
        parsed_data = parser.parse()
        
        headers = parsed_data.get("headers", {})
        subject = str(headers.get("subject", fallback_subject))
        sender = str(headers.get("from", fallback_sender))
        body = parsed_data.get("body", "")
        
        content_type = categorize_content(subject, body, sender, headers)
        auth_res = evaluate_auth_and_alignment(headers)
        
        ml_pred = ml_classifier.predict(subject, body)
        rule_results = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type=content_type)
        risk_score, reasons = calculate_hybrid_risk(rule_results, ml_pred["probability"], auth_alignment=auth_res, content_type=content_type)
        
        iocs = extract_all_indicators(body + " " + str(headers))
        ioc_count = len(iocs.get("ipv4", [])) + len(iocs.get("urls", [])) + len(iocs.get("emails", []))
        
        atts = analyze_all_attachments(parsed_data.get("attachments", []))
        
        return {
            "Filename": filename,
            "Sender": sender,
            "Subject": subject,
            "Risk": risk_score,
            "Score": risk_score, 
            "IOCs": ioc_count,
            "Attachments": len(atts),
            "Indicators": iocs,
            "FileBytes": file_bytes
        }, risk_score
    except Exception as e:
        return {
            "Filename": filename,
            "Sender": "Error",
            "Subject": f"Failed to parse: {str(e)}",
            "Risk": "ERROR",
            "Score": "ERROR",
            "IOCs": 0,
            "Attachments": 0,
            "Indicators": {},
            "FileBytes": file_bytes
        }, "ERROR"


def render_batch_analysis(current_user_id, user_client, **ctx):
    st.markdown("### 📦 Batch Forensic Analysis")
    st.write("Select emails directly from monitored Live Mail to analyze them concurrently. This runs entirely in-memory and does not emit telemetry or trigger alerts.")

    if not is_authorized_caller(current_user_id, user_client):
        error_card(
            title="Authentication Required",
            message="Please sign in or register via the sidebar to access Live Mail analysis."
        )
        return

    primary_mailbox = get_user_mailbox(current_user_id, user_client)
    mailboxes = list_user_mailboxes(current_user_id, user_client)
    if not mailboxes and primary_mailbox:
        mailboxes = [primary_mailbox]

    active_mailboxes = [m for m in mailboxes if m and m.get("is_active", False)]
    if primary_mailbox and primary_mailbox.get("is_active", False) and not any(m.get("id") == primary_mailbox.get("id") for m in active_mailboxes):
        active_mailboxes.insert(0, primary_mailbox)

    if not active_mailboxes:
        empty_state(
            icon="📬",
            title="No mailbox connected",
            body="Connect a mailbox from Mailbox & Settings to analyze Live Mail messages."
        )
    else:
        if len(active_mailboxes) > 1:
            mb_map = {}
            for m in active_mailboxes:
                m_id = str(m.get("id") or m.get("mailbox_id") or "")
                m_email = m.get("email_address", "Mailbox")
                m_prov = str(m.get("provider", "Custom")).capitalize()
                label = f"{m_email} ({m_prov}) [{m_id[:8]}]"
                mb_map[label] = (m_id, m)

            selected_label = st.selectbox("Select Mailbox", list(mb_map.keys()), key="live_batch_mailbox_switcher")
            selected_mb_id, selected_mailbox = mb_map[selected_label]
        else:
            selected_mailbox = active_mailboxes[0]
            selected_mb_id = selected_mailbox.get("id") or selected_mailbox.get("mailbox_id")
            m_email = selected_mailbox.get("email_address", "Mailbox")
            m_prov = str(selected_mailbox.get("provider", "Custom")).capitalize()
            st.caption(f"📬 Connected Mailbox: **{m_email}** ({m_prov})")

        # Clear selection if mailbox changed
        prev_mb_id = st.session_state.get("last_live_batch_mailbox_id")
        if prev_mb_id is not None and prev_mb_id != selected_mb_id:
            st.session_state["last_live_batch_mailbox_id"] = selected_mb_id
            if "selected_live_mail_ids" in st.session_state:
                for mid in list(st.session_state["selected_live_mail_ids"]):
                    st.session_state[f"chk_live_{mid}"] = False
                st.session_state["selected_live_mail_ids"].clear()
        else:
            st.session_state["last_live_batch_mailbox_id"] = selected_mb_id

        messages = get_authorized_live_mail_messages(
            current_user_id,
            user_client,
            mailbox_id=selected_mb_id
        )

        if not messages:
            empty_state(
                icon="📭",
                title="No Live Mail messages available yet.",
                body="Waiting for inbound emails to arrive in your monitored mailbox."
            )
        else:
            # Provide Search input: "Search Live Mail" (matches case-insensitively in subject, sender, message-id)
            search_query = st.text_input("Search Live Mail", placeholder="Search by subject, sender, or message ID...", key="live_mail_search_input")

            # Provide Filters in 3 columns:
            col_f1, col_f2, col_f3 = st.columns(3)
            with col_f1:
                risk_filter = st.selectbox("Risk", ["All", "Clean", "Suspicious", "High", "Critical"], key="live_batch_filter_risk")
            with col_f2:
                att_filter = st.selectbox("Attachments", ["All", "Has Attachment", "No Attachment"], key="live_batch_filter_att")
            with col_f3:
                ioc_filter = st.selectbox("Indicators (IOCs)", ["All", "Has IOC", "No IOC"], key="live_batch_filter_ioc")

            # Filter messages based on search and filters
            filtered_messages = []
            for m in messages:
                if search_query:
                    sq = search_query.strip().lower()
                    subj = str(m.get("subject", "")).lower()
                    sndr = str(m.get("sender", "")).lower()
                    mid = str(m.get("message_id", "") or m.get("message-id", "")).lower()
                    if sq not in subj and sq not in sndr and sq not in mid:
                        continue

                m_risk = str(m.get("risk", "LOW")).upper()
                if risk_filter == "Clean" and m_risk != "LOW":
                    continue
                elif risk_filter == "Suspicious" and m_risk != "SUSPICIOUS":
                    continue
                elif risk_filter == "High" and m_risk != "HIGH":
                    continue
                elif risk_filter == "Critical" and m_risk != "CRITICAL":
                    continue

                has_att = bool(m.get("has_attachment") or m.get("attachment_count", 0) > 0)
                if att_filter == "Has Attachment" and not has_att:
                    continue
                elif att_filter == "No Attachment" and has_att:
                    continue

                has_ioc = bool(m.get("has_ioc") or m.get("ioc_count", 0) > 0)
                if ioc_filter == "Has IOC" and not has_ioc:
                    continue
                elif ioc_filter == "No IOC" and has_ioc:
                    continue

                filtered_messages.append(m)

            # Manage selection set in st.session_state.setdefault("selected_live_mail_ids", set())
            if not isinstance(st.session_state.get("selected_live_mail_ids"), set):
                st.session_state["selected_live_mail_ids"] = set(st.session_state.get("selected_live_mail_ids") or [])
            selected_set = st.session_state.setdefault("selected_live_mail_ids", set())

            # Provide action row with buttons:
            col_act1, col_act2, col_act3 = st.columns([1.5, 1.5, 3])
            with col_act1:
                if st.button("Select All Visible", key="btn_select_all_live_batch"):
                    for fm in filtered_messages:
                        fmid = str(fm.get("id"))
                        selected_set.add(fmid)
                        st.session_state[f"chk_live_{fmid}"] = True
                    st.rerun()

            with col_act2:
                if st.button("Clear Selection", key="btn_clear_selection_live_batch"):
                    for mid in list(selected_set):
                        st.session_state[f"chk_live_{mid}"] = False
                    selected_set.clear()
                    st.rerun()

            with col_act3:
                st.markdown(f"**Selected: {len(st.session_state['selected_live_mail_ids'])} emails**")

            # Render selectable message items
            if not filtered_messages:
                empty_state(
                    icon="🔍",
                    title="No Matching Emails",
                    body="No Live Mail messages match the current search query or filter criteria."
                )
            else:
                def _on_live_chk_change(mid: str):
                    if st.session_state.get(f"chk_live_{mid}"):
                        st.session_state["selected_live_mail_ids"].add(mid)
                    else:
                        st.session_state["selected_live_mail_ids"].discard(mid)

                for m in filtered_messages:
                    mid = str(m.get("id"))
                    if f"chk_live_{mid}" not in st.session_state:
                        st.session_state[f"chk_live_{mid}"] = mid in selected_set

                    c_chk, c_card = st.columns([0.4, 9.6])
                    with c_chk:
                        st.checkbox(
                            f"Select {mid}",
                            key=f"chk_live_{mid}",
                            on_change=_on_live_chk_change,
                            args=(mid,),
                            label_visibility="collapsed"
                        )
                    with c_card:
                        r_val = str(m.get("risk", "LOW")).upper()
                        if r_val == "LOW":
                            b_html = status_badge_html("safe", "CLEAN")
                        elif r_val == "SUSPICIOUS":
                            b_html = status_badge_html("warning", "SUSPICIOUS")
                        elif r_val == "HIGH":
                            b_html = status_badge_html("danger", "HIGH")
                        elif r_val == "CRITICAL":
                            b_html = status_badge_html("danger", "CRITICAL")
                        else:
                            b_html = status_badge_html("neutral", r_val)

                        att_cnt = m.get("attachment_count", 0)
                        if m.get("has_attachment") or att_cnt > 0:
                            att_badge = f'<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:0.75rem;background:#1e293b;color:#38bdf8;border:1px solid #334155;">📎 {att_cnt}</span>'
                        else:
                            att_badge = '<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:0.75rem;background:#18181b;color:#71717a;border:1px solid #27272a;">📎 0</span>'

                        ioc_cnt = m.get("ioc_count", 0)
                        if m.get("has_ioc") or ioc_cnt > 0:
                            ioc_badge = f'<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:0.75rem;background:#311b92;color:#c084fc;border:1px solid #4c1d95;">🛡️ {ioc_cnt} IOC(s)</span>'
                        else:
                            ioc_badge = '<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:0.75rem;background:#18181b;color:#71717a;border:1px solid #27272a;">🛡️ 0 IOCs</span>'

                        subj_esc = html.escape(str(m.get("subject", "No Subject")))
                        sndr_esc = html.escape(str(m.get("sender", "Unknown Sender")))
                        dt_esc = html.escape(str(m.get("date", "")))

                        st.markdown(
                            f"""
                            <div style="background-color: #141414; border: 1px solid #262626; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                    <div style="font-weight: 600; color: #ededed; font-size: 0.95rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 65%;">
                                        {subj_esc}
                                    </div>
                                    <div style="display: flex; gap: 8px; align-items: center;">
                                        {b_html}
                                        {att_badge}
                                        {ioc_badge}
                                    </div>
                                </div>
                                <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: #a1a1a1;">
                                    <div>From: <span style="color: #cbd5e1;">{sndr_esc}</span></div>
                                    <div style="color: #71717a;">{dt_esc}</div>
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

            # Render analysis trigger button
            st.markdown("")
            if st.button(
                f"🚀 Analyze {len(selected_set)} Selected Email(s)",
                type="primary",
                disabled=len(selected_set) == 0,
                key="btn_analyze_live_batch"
            ):
                ml_classifier = ctx.get("ml_classifier") or MLClassifier()
                results = []
                metrics = {"Processed": 0, "Clean": 0, "Suspicious": 0, "High Risk": 0, "Critical": 0, "Errors": 0}

                msg_map = {str(m.get("id")): m for m in messages}
                selected_messages = [msg_map[mid] for mid in selected_set if mid in msg_map]

                with st.spinner(f"Analyzing {len(selected_messages)} Live Mail emails..."):
                    for msg_rec in selected_messages:
                        metrics["Processed"] += 1
                        fname = f"LiveMail_{msg_rec.get('id', 'msg')}.eml"
                        file_bytes = b""
                        try:
                            fname, file_bytes = convert_live_message_to_rfc822_bytes(msg_rec, user_id=current_user_id)
                            res_item, risk_score = _process_email_for_batch(
                                filename=fname,
                                file_bytes=file_bytes,
                                ml_classifier=ml_classifier,
                                fallback_subject=msg_rec.get("subject", "No Subject"),
                                fallback_sender=msg_rec.get("sender", "Unknown Sender")
                            )
                            if risk_score == "LOW":
                                metrics["Clean"] += 1
                            elif risk_score == "SUSPICIOUS":
                                metrics["Suspicious"] += 1
                            elif risk_score == "HIGH":
                                metrics["High Risk"] += 1
                            elif risk_score == "CRITICAL":
                                metrics["Critical"] += 1
                            elif risk_score == "ERROR":
                                metrics["Errors"] += 1
                            results.append(res_item)
                        except Exception as e:
                            metrics["Errors"] += 1
                            results.append({
                                "Filename": fname,
                                "Sender": "Error",
                                "Subject": f"Failed to parse: {str(e)}",
                                "Risk": "ERROR",
                                "Score": "ERROR",
                                "IOCs": 0,
                                "Attachments": 0,
                                "Indicators": {},
                                "FileBytes": file_bytes
                            })

                st.session_state["batch_analysis_results"] = results
                st.session_state["batch_analysis_metrics"] = metrics
                st.rerun()

    # Preserved Shared Results Section
    results = st.session_state.get("batch_analysis_results")
    metrics = st.session_state.get("batch_analysis_metrics")

    if results and metrics:
        st.markdown("---")
        st.subheader("📊 Batch Summary")
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Processed", metrics["Processed"])
        m2.metric("Clean", metrics["Clean"])
        m3.metric("Suspicious", metrics["Suspicious"])
        m4.metric("High Risk", metrics["High Risk"])
        m5.metric("Critical", metrics["Critical"])
        m6.metric("Errors", metrics["Errors"])
        
        st.markdown("---")
        st.subheader("📋 Results Details")
        
        # Filtering
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            risk_filter = st.selectbox("Filter by Risk:", ["All", "Clean", "Suspicious", "High", "Critical", "ERROR"])
        with f_col2:
            ioc_filter = st.selectbox("Filter by IOCs:", ["All", "With Indicators (>0)", "No Indicators (0)"])
        with f_col3:
            sort_by = st.selectbox("Sort by:", ["Filename", "Sender", "Risk", "IOCs", "Attachments"])
            
        filtered_results = []
        for r in results:
            match = False
            if risk_filter == "All":
                match = True
            elif risk_filter == "Clean" and r["Risk"] == "LOW":
                match = True
            elif risk_filter == "Suspicious" and r["Risk"] == "SUSPICIOUS":
                match = True
            elif risk_filter == "High" and r["Risk"] == "HIGH":
                match = True
            elif risk_filter == "Critical" and r["Risk"] == "CRITICAL":
                match = True
            elif risk_filter == "ERROR" and r["Risk"] == "ERROR":
                match = True
            if not match:
                continue

            if ioc_filter == "With Indicators (>0)" and r.get("IOCs", 0) == 0:
                continue
            elif ioc_filter == "No Indicators (0)" and r.get("IOCs", 0) > 0:
                continue

            filtered_results.append(r)
                
        # Sorting
        if sort_by == "Filename":
            filtered_results.sort(key=lambda x: x["Filename"])
        elif sort_by == "Sender":
            filtered_results.sort(key=lambda x: x["Sender"])
        elif sort_by == "Risk":
            risk_order = {"CRITICAL": 0, "HIGH": 1, "SUSPICIOUS": 2, "LOW": 3, "ERROR": 4}
            filtered_results.sort(key=lambda x: risk_order.get(x["Risk"], 5))
        elif sort_by == "IOCs":
            filtered_results.sort(key=lambda x: x["IOCs"], reverse=True)
        elif sort_by == "Attachments":
            filtered_results.sort(key=lambda x: x.get("Attachments", 0), reverse=True)
            
        # Interactive Table (Dataframe view)
        df_view = []
        for r in filtered_results:
            df_view.append({
                "Filename": r["Filename"],
                "Sender": r["Sender"][:30],
                "Subject": r["Subject"][:40],
                "Risk": r["Risk"],
                "IOCs": r["IOCs"],
                "Attachments": r["Attachments"]
            })
        if df_view:
            st.dataframe(pd.DataFrame(df_view), use_container_width=True)
            
        st.markdown("---")
        # Expandable Cards
        for idx, r in enumerate(filtered_results):
            risk_color = "green" if r["Risk"] == "LOW" else "orange" if r["Risk"] == "SUSPICIOUS" else "red" if r["Risk"] in ["HIGH", "CRITICAL"] else "gray"
            with st.expander(f"{r['Filename']} - {r['Risk']} - {r['Sender'][:30]}"):
                st.markdown(f"**Subject:** {r['Subject']}")
                st.markdown(f"**Risk Level:** :{risk_color}[{r['Risk']}]")
                st.markdown(f"**IOC Count:** {r['IOCs']} | **Attachments:** {r['Attachments']}")
                if r["Risk"] != "ERROR":
                    if st.button(f"🔎 View Full Analysis", key=f"view_{r['Filename']}_{idx}"):
                        st.session_state["batch_inspect_email_bytes"] = r["FileBytes"]
                        st.session_state["analysis_mode_selector"] = "🔍 Single Email"
                        st.rerun()
                        
        # Exports
        st.markdown("---")
        st.subheader("💾 Export Results")
        export_df = pd.DataFrame(df_view)
        csv = export_df.to_csv(index=False).encode('utf-8')
        
        json_export = []
        for r in results:
            d = dict(r)
            d.pop("FileBytes", None)
            json_export.append(d)
        json_data = json.dumps(json_export, indent=2).encode('utf-8')
        
        e1, e2, e3 = st.columns(3)
        with e1:
            st.download_button("Download CSV", data=csv, file_name="batch_analysis.csv", mime="text/csv", use_container_width=True)
        with e2:
            st.download_button("Download JSON", data=json_data, file_name="batch_analysis.json", mime="application/json", use_container_width=True)
        with e3:
            try:
                pdf_data = generate_batch_pdf_report(metrics, results)
                st.download_button("Download PDF", data=pdf_data, file_name="batch_analysis_report.pdf", mime="application/pdf", use_container_width=True)
            except Exception as e:
                st.caption(f"PDF generation unavailable: {e}")

        st.markdown("")
        if st.button("🧹 Clear Batch Results", key="btn_clear_batch_results"):
            st.session_state.pop("batch_analysis_results", None)
            st.session_state.pop("batch_analysis_metrics", None)
            st.rerun()


def render(current_user_id, user_client, **ctx):
    inject_theme()
    page_header('Analyze Email', 'Analyze an email for threats, IOCs and forensic evidence')

    if st.session_state.get("batch_inspect_email_bytes"):
        st.session_state["current_email_bytes"] = st.session_state.pop("batch_inspect_email_bytes")
        st.session_state["_cached_analysis_payload"] = None

    # If show_batch was flagged from dashboard, reset current email and default to Live Mail
    if st.session_state.pop("show_batch", False):
        st.session_state["email_analysis_source"] = "📬 Select from Live Mail"
        st.session_state.pop("current_email_bytes", None)
        st.session_state.pop("_cached_analysis_payload", None)

    bytes_data = st.session_state.get("current_email_bytes")

    if bytes_data:
        if st.button("← Choose Another Email", key="btn_choose_another_email"):
            st.session_state["current_email_bytes"] = None
            st.session_state["_cached_analysis_payload"] = None
            st.session_state.pop("selected_live_mail_id", None)
            st.rerun()

        render_forensic_results(bytes_data, current_user_id, user_client, **ctx)
        return

    st.write("Choose an email to analyze:")
    source_options = ["📤 Upload Email", "📬 Select from Live Mail"]
    default_source_idx = 1 if st.session_state.get("email_analysis_source") == "📬 Select from Live Mail" else 0
    selected_source = st.radio(
        "Choose an email",
        options=source_options,
        index=default_source_idx,
        horizontal=True,
        label_visibility="collapsed",
        key="email_analysis_source"
    )

    if selected_source == "📤 Upload Email":
        render_single_email(current_user_id, user_client, **ctx)
    else:
        if not is_authorized_caller(current_user_id, user_client):
            error_card(
                title="Authentication Required",
                message="Please sign in or register via the sidebar to access Live Mail analysis."
            )
            return

        primary_mailbox = ctx.get("mailbox_rec") or get_user_mailbox(current_user_id, user_client)
        mailboxes = list_user_mailboxes(current_user_id, user_client)
        if not mailboxes and primary_mailbox:
            mailboxes = [primary_mailbox]

        active_mailboxes = [m for m in mailboxes if m and m.get("is_active", False)]
        if primary_mailbox and primary_mailbox.get("is_active", False) and not any(m.get("id") == primary_mailbox.get("id") for m in active_mailboxes):
            active_mailboxes.insert(0, primary_mailbox)

        if not active_mailboxes:
            empty_state(
                icon="📬",
                title="No mailbox connected",
                body="Connect a mailbox from Mailbox & Settings to analyze Live Mail messages."
            )
            return

        limit_options = LIVE_MAIL_LIMIT_OPTIONS
        current_limit = st.session_state.get("live_mail_fetch_limit", DEFAULT_LIVE_MAIL_LIMIT)
        if current_limit not in limit_options:
            current_limit = DEFAULT_LIVE_MAIL_LIMIT

        col_mb_sel, col_lim_sel = st.columns([3, 1])
        with col_mb_sel:
            if len(active_mailboxes) > 1:
                mb_map = {}
                for m in active_mailboxes:
                    m_id = str(m.get("id") or m.get("mailbox_id") or "")
                    m_email = m.get("email_address", "Mailbox")
                    m_prov = str(m.get("provider", "Custom")).capitalize()
                    label = f"{m_email} ({m_prov}) [{m_id[:8]}]"
                    mb_map[label] = (m_id, m)

                selected_label = st.selectbox("Select Mailbox", list(mb_map.keys()), key="live_unified_mailbox_switcher")
                selected_mb_id, selected_mailbox = mb_map[selected_label]
            else:
                selected_mailbox = active_mailboxes[0]
                selected_mb_id = selected_mailbox.get("id") or selected_mailbox.get("mailbox_id")
                m_email = selected_mailbox.get("email_address", "Mailbox")
                m_prov = str(selected_mailbox.get("provider", "Custom")).capitalize()
                st.caption(f"📬 Connected Mailbox: **{m_email}** ({m_prov})")

        with col_lim_sel:
            selected_limit = st.selectbox(
                "Messages to load (Fetch Limit)",
                options=LIVE_MAIL_LIMIT_OPTIONS,
                index=LIVE_MAIL_LIMIT_OPTIONS.index(current_limit) if current_limit in LIVE_MAIL_LIMIT_OPTIONS else 0,
                key="live_mail_fetch_limit_select"
            )

        if selected_limit not in limit_options:
            selected_limit = current_limit
        elif selected_limit != current_limit:
            st.session_state["live_mail_fetch_limit"] = selected_limit
            st.session_state["selected_live_mail_index"] = 0
            st.rerun()

        messages = get_authorized_live_mail_messages(
            current_user_id,
            user_client,
            mailbox_id=selected_mb_id,
            limit=selected_limit
        )

        # Deduplicate messages by UID
        deduped_messages = []
        seen_uids = set()
        for m in messages:
            uid = str(m.get("id") or m.get("case_id") or "")
            if not uid or uid in seen_uids:
                continue
            seen_uids.add(uid)
            deduped_messages.append(m)
        messages = deduped_messages

        if not messages:
            empty_state(
                icon="📭",
                title="No Live Mail emails available yet.",
                body="Waiting for inbound emails to arrive in your monitored mailbox."
            )
            return

        # Selection state tracking
        selected_uid = st.session_state.get("selected_live_mail_uid")
        selected_msg = None
        selected_idx = 0

        if selected_uid:
            for i, m in enumerate(messages):
                m_uid = str(m.get("id") or m.get("case_id") or "")
                if m_uid == str(selected_uid):
                    selected_msg = m
                    selected_idx = i
                    break

        if selected_msg is None:
            # Fallback to index if provided in session state
            fallback_idx = st.session_state.get("selected_live_mail_index")
            if fallback_idx is None:
                fallback_idx = st.session_state.get("current_live_mail_index")
            if fallback_idx is not None:
                try:
                    fallback_idx = max(0, min(int(fallback_idx), len(messages) - 1))
                    selected_idx = fallback_idx
                    selected_msg = messages[selected_idx]
                except (ValueError, TypeError):
                    selected_msg = messages[0]
                    selected_idx = 0
            else:
                selected_msg = messages[0]
                selected_idx = 0

        st.session_state["selected_live_mail_uid"] = str(selected_msg.get("id") or selected_msg.get("case_id") or "")
        st.session_state["selected_live_mail_message_id"] = selected_msg.get("message_id")
        st.session_state["selected_live_mail_index"] = selected_idx
        st.session_state["current_live_mail_index"] = selected_idx
        st.session_state["selected_live_mail_id"] = str(selected_msg.get("id") or selected_msg.get("case_id") or "")

        # Dedicated "Selected Email" Action Card
        sel_subj = html.escape(str(selected_msg.get("subject", "No Subject")))
        sel_sender = html.escape(str(selected_msg.get("sender", "Unknown Sender")))
        sel_date = html.escape(str(selected_msg.get("received_at") or selected_msg.get("date") or selected_msg.get("timestamp") or "Unknown Date"))
        sel_uid = html.escape(str(selected_msg.get("id") or selected_msg.get("case_id") or ""))

        st.markdown(
            f"""
            <div style="background-color: #172554; border: 2px solid #3b82f6; border-radius: 8px; padding: 16px; margin: 16px 0 12px 0;">
                <div style="font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em; color: #93c5fd; font-weight: 700; margin-bottom: 6px;">
                    🎯 Currently Selected Email
                </div>
                <div style="font-size: 1.15em; font-weight: 700; color: #f8fafc; margin-bottom: 6px; word-break: break-word;">
                    {sel_subj}
                </div>
                <div style="font-size: 0.9em; color: #cbd5e1; margin-bottom: 4px;">
                    <span style="color: #94a3b8; font-weight: 600;">From:</span> {sel_sender}
                </div>
                <div style="font-size: 0.85em; color: #cbd5e1; margin-bottom: 4px;">
                    <span style="color: #94a3b8; font-weight: 600;">Date:</span> {sel_date} &nbsp;|&nbsp; <span style="color: #94a3b8; font-weight: 600;">UID:</span> <code style="color: #93c5fd;">{sel_uid}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if st.button("🔍 Analyze This Email", key="btn_analyze_selected_live_email", type="primary", use_container_width=True):
            fname, file_bytes = convert_live_message_to_rfc822_bytes(selected_msg, user_id=current_user_id)
            if not file_bytes:
                st.error("Unable to load this email for analysis.")
            else:
                st.session_state["current_email_bytes"] = file_bytes
                st.session_state["_cached_analysis_payload"] = None
                st.session_state["selected_live_mail_uid"] = str(selected_msg.get("id"))
                st.session_state["selected_live_mail_id"] = str(selected_msg.get("id"))
                st.rerun()

        # Render vertical email cards list
        st.markdown(f"<div style='font-size: 1.05em; font-weight: 600; color: #cbd5e1; margin: 16px 0 8px 0;'>Inbox Messages ({len(messages)} loaded)</div>", unsafe_allow_html=True)

        for idx, msg in enumerate(messages):
            msg_uid = str(msg.get("id"))
            is_selected = (msg_uid == str(selected_msg.get("id")))

            analysis_status = st.session_state.get("live_mail_analysis_status", {}).get(msg_uid)
            if analysis_status:
                if str(analysis_status).upper() in ("SAFE", "LOW", "CLEAN"):
                    badge_html = status_badge_html("safe", "SAFE")
                elif str(analysis_status).upper() in ("SUSPICIOUS", "MEDIUM"):
                    badge_html = status_badge_html("warning", str(analysis_status).upper())
                else:
                    badge_html = status_badge_html("danger", str(analysis_status).upper())
            else:
                badge_html = status_badge_html("neutral", "Not analyzed")

            msg_subject = html.escape(str(msg.get("subject", "No Subject")))
            msg_sender = html.escape(str(msg.get("sender", "Unknown")))
            msg_recipient = html.escape(str(msg.get("recipient") or msg.get("to") or selected_mailbox.get("email_address", "Monitored Mailbox")))
            msg_date = html.escape(str(msg.get("received_at") or msg.get("date") or msg.get("timestamp") or "Unknown Date"))

            msg_body_raw = msg.get("body_preview") or msg.get("snippet") or msg.get("body_text") or msg.get("body") or "No preview content available."
            msg_snippet_text = msg_body_raw.strip()[:250]
            if len(msg_body_raw.strip()) > 250:
                msg_snippet_text += "..."
            msg_snippet = html.escape(msg_snippet_text)

            att_count = msg.get("attachment_count", 0)
            if not att_count and msg.get("has_attachment"):
                att_count = 1
            ioc_count = msg.get("ioc_count", 0)
            if not ioc_count and msg.get("has_ioc"):
                ioc_count = 1

            border_color = "2px solid #3b82f6" if is_selected else "1px solid #334155"
            bg_color = "#172554" if is_selected else "#0f172a"

            st.markdown(
                f"""
                <div class="es-card" style="padding: 16px; margin: 12px 0 6px 0; border: {border_color}; border-radius: 8px; background-color: {bg_color};">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                        <div style="font-size: 1.05em; font-weight: 700; color: #f8fafc; word-break: break-word; max-width: 75%;">
                            {msg_subject}
                        </div>
                        <div>
                            {badge_html}
                        </div>
                    </div>
                    <div style="font-size: 0.9em; color: #cbd5e1; margin-bottom: 4px;">
                        <span style="color: #94a3b8; font-weight: 600;">From:</span> {msg_sender}
                    </div>
                    <div style="font-size: 0.9em; color: #cbd5e1; margin-bottom: 4px;">
                        <span style="color: #94a3b8; font-weight: 600;">To:</span> {msg_recipient}
                    </div>
                    <div style="font-size: 0.85em; color: #94a3b8; margin-bottom: 10px;">
                        <span style="font-weight: 600;">Date:</span> {msg_date}
                    </div>
                    <div style="font-size: 0.86em; color: #cbd5e1; line-height: 1.45; margin-bottom: 12px; background-color: #020617; padding: 10px; border-radius: 6px; font-family: sans-serif; white-space: pre-wrap;">{msg_snippet}</div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="es-badge" style="color: #94a3b8; background: #1e293b; padding: 3px 8px; border-radius: 4px; font-size: 0.8em;">
                            📎 {att_count} Attachment{'s' if att_count != 1 else ''}
                        </span>
                        <span class="es-badge" style="color: #f59e0b; background: #451a03; padding: 3px 8px; border-radius: 4px; font-size: 0.8em;">
                            ⚠️ {ioc_count} Indicator{'s' if ioc_count != 1 else ''}
                        </span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            if is_selected:
                st.button("✓ Selected", key=f"btn_select_live_{msg_uid}_{idx}", disabled=True)
            else:
                if st.button("Select", key=f"btn_select_live_{msg_uid}_{idx}"):
                    st.session_state["selected_live_mail_uid"] = msg_uid
                    st.session_state["selected_live_mail_message_id"] = msg.get("message_id")
                    st.session_state["selected_live_mail_index"] = idx
                    st.session_state["current_live_mail_index"] = idx
                    st.session_state["selected_live_mail_id"] = msg_uid
                    st.rerun()

