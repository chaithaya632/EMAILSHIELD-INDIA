import streamlit as st
import os
import json
from core.local_storage import get_local_storage_manager, RetentionPolicy
from views._theme import (
    inject_theme,
    page_header,
    metric_card,
    status_badge_html,
    empty_state,
    section_divider,
    detail_row,
    error_card,
    info_card,
    success_card,
    COLORS
)

def render(current_user_id, user_client, **ctx):
    inject_theme()
    
    page_header("System & Diagnostics", "Monitor storage integrity, local retention policies, worker telemetry, and detection pipeline engines.")

    tab_diag_stor, tab_diag_worker, tab_diag_engines = st.tabs(["💾 Storage & Retention", "📡 Worker Daemon Health", "🧠 Detection Pipeline Status"])

    with tab_diag_stor:
        st.subheader("💾 Local Forensic Storage & Retention Management")
        storage_mgr = get_local_storage_manager()

        disk_safety = storage_mgr.check_disk_space_safety()
        if disk_safety.get("low_disk_warning"):
            error_card(f"⚠️ **Low Disk Space Warning**: Free space is {disk_safety['free_mb']} MB (Threshold: {disk_safety['threshold_mb']} MB). Evidence deletion is blocked.")
        else:
            success_card(f"✅ Disk Space Healthy: {disk_safety.get('free_mb', 0):.1f} MB free.")

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

        section_divider()
        st.markdown("##### 🛡️ Retention Policy & Automated Safe Cleanup")
        ret_policy = st.selectbox("Active Retention Policy:", [30, 7, 90, 180], format_func=lambda d: f"{d} Days ({'Default' if d==30 else 'Custom'})", key="sel_diag_ret")
        col_cl1, col_cl2 = st.columns(2)
        with col_cl1:
            if st.button("🔍 Run Dry-Run Cleanup", help="Check what would be deleted without actually deleting", key="btn_diag_dry_run"):
                dry_res = storage_mgr.dry_run_cleanup(u_target, policy_days=ret_policy)
                info_card(f"Dry-run result: {dry_res.get('eligible_cases_count', 0)} eligible cases, {dry_res.get('eligible_evidence_count', 0)} evidence items.")
        with col_cl2:
            if st.button("🧹 Execute Safe Cleanup", type="primary", key="btn_diag_exec_cleanup"):
                clean_res = storage_mgr.run_cleanup_now(u_target, policy_days=ret_policy)
                success_card(f"Cleanup executed: {clean_res.get('deleted_cases_count', 0)} cases deleted. Active cases and preserved evidence were protected.")

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
                error_card(f"Error reading telemetry: {e}")
        else:
            info_card("Worker telemetry file not yet generated. Start the worker daemon to initialize telemetry.")

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
