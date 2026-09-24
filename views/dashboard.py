import streamlit as st
import html
import re
import uuid
import plotly.express as px

from views._theme import (
    inject_theme, 
    page_header, 
    metric_card, 
    status_badge_html, 
    empty_state, 
    section_divider, 
    error_card,
    info_card,
    success_card,
    COLORS
)
from core.case_store import (
    is_authenticated_soc_caller, 
    get_soc_kpi_metrics, 
    get_soc_threat_distribution, 
    get_soc_threat_activity, 
    get_soc_investigation_queue,
    close_case,
    close_all_open_cases,
    clear_threat_activity,
    cleanup_demo_cases
)
from core.sentinel_control import (
    get_user_mailbox,
    connect_user_sentinel_mailbox,
    mask_email_address,
    get_user_worker,
    upsert_user_worker,
    set_worker_desired_state,
    disconnect_user_sentinel_mailbox,
    get_user_checkpoint,
    get_user_sentinel_activity_stats
)


@st.fragment(run_every=2)
def render_soc_live_telemetry(current_user_id, user_client):
    # 3. Retain SOC KPI cards, Threat Distribution, and Incident Triage Queue
    metrics = get_soc_kpi_metrics(current_user_id, user_client)
    col_k1, col_k2, col_k3, col_k4 = st.columns(4)
    with col_k1:
        metric_card("Emails Analysed", metrics["emails_analysed"])
    with col_k2:
        metric_card("Threats Detected", metrics["threats_detected"])
    with col_k3:
        metric_card("High / Critical", metrics["high_critical"])
    with col_k4:
        metric_card("Open Investigations", metrics["open_investigations"])

    section_divider()

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
                    "Clean": COLORS['success'],
                    "Suspicious": COLORS['warning'],
                    "High": "#ef4444",
                    "Critical": COLORS['danger']
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
            empty_state("No threat metrics recorded yet. Analyze an email or load a sample scenario to populate threat distribution.")

    with col_dash2:
        col_act_hdr, col_act_clear = st.columns([2.5, 1.5])
        with col_act_hdr:
            st.subheader("⚡ Recent Threat Activity")
        with col_act_clear:
            st.write("")
            if st.button("🧹 Clear Activity", use_container_width=True, key="btn_clear_threat_act"):
                st.session_state["_pending_clear_threat_act"] = True

        if st.session_state.get("_pending_clear_threat_act"):
            st.warning(
                "**Clear all active threat activity?**\n\n"
                "This will mark open threat cases as closed while preserving all underlying forensic evidence."
            )
            col_c_conf, col_c_cancel = st.columns(2)
            with col_c_conf:
                if st.button("✓ Confirm Clear", type="primary", use_container_width=True, key="btn_confirm_clear_act"):
                    res = clear_threat_activity(user_id=current_user_id, client=user_client)
                    del st.session_state["_pending_clear_threat_act"]
                    if res.get("success"):
                        cnt = res.get("cleared_count", 0)
                        st.success(f"Threat activity cleared ({cnt} cases closed).")
                        st.rerun(scope="fragment")
                    else:
                        error_card(f"Failed to clear threat activity: {res.get('error', 'Unknown error')}")
            with col_c_cancel:
                if st.button("Cancel", use_container_width=True, key="btn_cancel_clear_act"):
                    del st.session_state["_pending_clear_threat_act"]
                    st.rerun(scope="fragment")

        activity = get_soc_threat_activity(current_user_id, user_client, limit=5)
        if activity:
            for act in activity:
                case_severity = act["case_severity"]
                badge_col = COLORS['danger'] if case_severity in ("HIGH", "CRITICAL") else COLORS['warning'] if case_severity in ("MEDIUM", "SUSPICIOUS") else COLORS['success']
                st.markdown(
                    f"""
                    <div class="es-card" style="border-left: 4px solid {badge_col}; padding: 8px 12px; margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <b style="color: {COLORS['text']}; font-size: 0.9em;">{html.escape(act['case_id'])}</b>
                            {status_badge_html(case_severity)}
                        </div>
                        <div style="color: {COLORS['text_muted']}; font-size: 0.82em; margin-top: 2px;">
                            <b>Sender:</b> {html.escape(act['sender'][:35])}
                        </div>
                        <div style="color: {COLORS['text_muted']}; font-size: 0.84em; margin-top: 2px;">
                            <b>Subject:</b> {html.escape(act['subject'][:45])}
                        </div>
                        <div style="color: {COLORS['text_muted']}; font-size: 0.75em; margin-top: 4px;">
                            🕒 {act['timestamp']} | 🎯 IOC: <code>{html.escape(act['primary_ioc'][:30])}</code>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            empty_state("No threat activity logged yet.")

    section_divider()
    col_triage_hdr, col_close_all_btn, col_purge_btn = st.columns([2.5, 1.2, 1.2])
    with col_triage_hdr:
        st.subheader("📋 Active Incident Triage Queue")
        st.caption("Prioritised by severity (Critical → High → Medium → Low).")
    with col_close_all_btn:
        st.write("")
        if st.button("✅ Close All", use_container_width=True, key="btn_soc_dash_close_all"):
            st.session_state["_pending_close_all_cases"] = True
    with col_purge_btn:
        st.write("")
        if st.button("🧹 Purge Demo Cases", use_container_width=True, key="btn_soc_dash_purge_demo"):
            st.session_state["_pending_purge_demo"] = True

    # Close All confirmation dialog
    if st.session_state.get("_pending_close_all_cases"):
        st.warning(
            "**Close all open cases in the triage queue?**\n\n"
            "This will close all active open cases. All forensic evidence, audit trails, and SHA-256 hashes will be strictly preserved."
        )
        col_ca_confirm, col_ca_cancel = st.columns(2)
        with col_ca_confirm:
            if st.button("✓ Confirm Close All", type="primary", use_container_width=True, key="btn_confirm_close_all"):
                res = close_all_open_cases(user_id=current_user_id, client=user_client)
                del st.session_state["_pending_close_all_cases"]
                if res.get("success"):
                    cnt = res.get("closed_count", 0)
                    st.success(f"All open cases closed successfully ({cnt} closed).")
                    st.rerun(scope="fragment")
                else:
                    error_card(f"Failed to close all cases: {res.get('error', 'Unknown error')}")
        with col_ca_cancel:
            if st.button("Cancel", use_container_width=True, key="btn_cancel_close_all"):
                del st.session_state["_pending_close_all_cases"]
                st.rerun(scope="fragment")

    # Demo Case Purge confirmation dialog
    if st.session_state.get("_pending_purge_demo"):
        st.warning(
            "**Purge all demo / test cases?**\n\n"
            "This will safely remove generated demo/test cases (`CASE-ISO-*`, `CASE-DEMO-*`, `CASE-TEST-*`, `TEST-*`). "
            "All real cases, forensic evidence, and production investigations will be strictly preserved."
        )
        col_p_confirm, col_p_cancel = st.columns(2)
        with col_p_confirm:
            if st.button("✓ Confirm Purge", type="primary", use_container_width=True, key="btn_confirm_purge_demo"):
                res = cleanup_demo_cases(user_id=current_user_id, client=user_client)
                del st.session_state["_pending_purge_demo"]
                if res.get("success"):
                    del_cnt = res.get("deleted_count", 0)
                    st.success(f"Demo cases purged successfully ({del_cnt} removed).")
                    st.rerun(scope="fragment")
                else:
                    error_card(f"Failed to purge demo cases: {res.get('error', 'Unknown error')}")
        with col_p_cancel:
            if st.button("Cancel", use_container_width=True, key="btn_cancel_purge_demo"):
                del st.session_state["_pending_purge_demo"]
                st.rerun(scope="fragment")

    queue_data = get_soc_investigation_queue(current_user_id, user_client, limit=10)
    demo_prefixes = ("CASE-ISO-", "CASE-DEMO-", "CASE-TEST-", "TEST-")
    # Automatically exclude demo cases from active queue display
    display_queue = [
        q for q in (queue_data or [])
        if not any(str(q.get("case_id", "")).startswith(p) for p in demo_prefixes)
    ]

    if display_queue:
        st.dataframe(display_queue, use_container_width=True)
        col_q_sel, col_q_act, col_q_close = st.columns([3, 1, 1])
        with col_q_sel:
            q_case_ids = [q.get("case_id") or q.get("Case ID") for q in display_queue if q.get("case_id") or q.get("Case ID")]
            selected_q_cid = st.selectbox("Select case from queue to open:", q_case_ids, key="sb_soc_dash_q_sel")
        with col_q_act:
            st.write("")
            st.write("")
            if st.button("🔎 Open Investigation", type="primary", use_container_width=True, key="btn_soc_dash_open_inv"):
                if selected_q_cid:
                    st.session_state["active_investigation_id"] = selected_q_cid
                    st.session_state["active_view_idx"] = 3
                    st.rerun()
        with col_q_close:
            st.write("")
            st.write("")
            if st.button("✓ Close Case", use_container_width=True, key="btn_soc_dash_close_case"):
                if selected_q_cid:
                    st.session_state["_pending_close_case_id"] = selected_q_cid

        # Close Case confirmation dialog
        pending_close = st.session_state.get("_pending_close_case_id")
        if pending_close:
            st.warning(
                f"**Close case {pending_close}?**\n\n"
                "This will remove it from the Active Incident Triage Queue. "
                "The underlying forensic evidence will be preserved."
            )
            col_confirm, col_cancel = st.columns(2)
            with col_confirm:
                if st.button("✓ Confirm Close", type="primary", use_container_width=True, key="btn_confirm_close"):
                    success, err = close_case(
                        case_id=pending_close,
                        user_id=current_user_id,
                        client=user_client
                    )
                    del st.session_state["_pending_close_case_id"]
                    if success:
                        st.success(f"Case {pending_close} closed successfully.")
                        st.rerun(scope="fragment")
                    else:
                        error_card(f"Failed to close case: {err}")
            with col_cancel:
                if st.button("Cancel", use_container_width=True, key="btn_cancel_close"):
                    del st.session_state["_pending_close_case_id"]
                    st.rerun(scope="fragment")
    else:
        empty_state("No pending cases in the triage queue.")


def render(current_user_id, user_client, **ctx):
    inject_theme()
    page_header("🛡️ SOC Operations Dashboard", "Live operational intelligence, threat telemetry, and active incident response queue.")

    if not is_authenticated_soc_caller(current_user_id, user_client):
        # Public Landing / Marketing Experience for Unauthenticated Visitors
        st.info("🔐 **Authentication Required**: Please sign in or create an account via the sidebar on the left to access your private SOC dashboard, live operational telemetry, threat intelligence, and triage queue.")
        
        st.markdown(
            f"""
            <div class="es-card" style="padding: 20px; margin: 15px 0 20px 0;">
                <h3 style="color: {COLORS['primary']}; margin-top: 0;">🛡️ EMAILSHIELD INDIA — Security Operations Console</h3>
                <p style="color: {COLORS['text_muted']}; font-size: 0.95em; line-height: 1.6;">
                    Professional email threat operations and automated forensic triage platform engineered for enterprise SOC analysts, CERT/CSIRT responders, and security teams across India.
                </p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-top: 15px;">
                    <div style="background-color: {COLORS['background']}; border-left: 3px solid {COLORS['primary']}; padding: 12px; border-radius: 6px;">
                        <b style="color: {COLORS['text']}; font-size: 0.9em;">🔬 Deterministic Forensics & ML</b>
                        <div style="color: {COLORS['text_muted']}; font-size: 0.82em; margin-top: 4px;">RFC822 header parsing, DKIM/SPF/DMARC alignment, Received-hop tracing, TF-IDF + LR classification.</div>
                    </div>
                    <div style="background-color: {COLORS['background']}; border-left: 3px solid {COLORS['success']}; padding: 12px; border-radius: 6px;">
                        <b style="color: {COLORS['text']}; font-size: 0.9em;">⚡ 1-Second Live Mail Sentinel</b>
                        <div style="color: {COLORS['text_muted']}; font-size: 0.82em; margin-top: 4px;">Automated IMAP monitoring, duplicate prevention, and zero-cost cloudless operations.</div>
                    </div>
                    <div style="background-color: {COLORS['background']}; border-left: 3px solid {COLORS['warning']}; padding: 12px; border-radius: 6px;">
                        <b style="color: {COLORS['text']}; font-size: 0.9em;">🇮🇳 India Threat Intelligence</b>
                        <div style="color: {COLORS['text_muted']}; font-size: 0.82em; margin-top: 4px;">UPI QR fraud, banking impersonation, and one-click NCRP police evidence packager.</div>
                    </div>
                    <div style="background-color: {COLORS['background']}; border-left: 3px solid {COLORS['danger']}; padding: 12px; border-radius: 6px;">
                        <b style="color: {COLORS['text']}; font-size: 0.9em;">🔒 Private Multi-Tenant Isolation</b>
                        <div style="color: {COLORS['text_muted']}; font-size: 0.82em; margin-top: 4px;">Row Level Security (RLS) guarantees your investigations and mailbox data remain strictly isolated.</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        col_pub1, col_pub2 = st.columns(2)
        with col_pub1:
            if st.button("🔍 Analyze Email", type="primary", use_container_width=True, key="btn_soc_pub_ana"):
                st.session_state["active_view_idx"] = 1
                st.rerun()
        with col_pub2:
            if st.button("⚙️ View System Diagnostics & Platform Health", use_container_width=True, key="btn_soc_pub_diag"):
                st.session_state["active_view_idx"] = 8
                st.rerun()
    else:
        # Authenticated SOC Operations Dashboard
        mailbox_rec = ctx.get("mailbox_rec") or get_user_mailbox(current_user_id, user_client)
        
        if not mailbox_rec or not mailbox_rec.get("email_address"):
            # 1. Onboarding Card
            st.markdown(
                f"""
                <div class="es-card" style="padding: 24px; margin-bottom: 24px; border-top: 4px solid {COLORS['primary']};">
                    <h3 style="margin-top: 0; color: {COLORS['text']};">📧 Connect your Gmail</h3>
                    <p style="color: {COLORS['text_muted']}; margin-bottom: 20px;">
                        Connect a dedicated mailbox to start automatic email security monitoring.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            with st.container():
                st.markdown('<div class="es-card" style="padding: 24px; margin-bottom: 24px;">', unsafe_allow_html=True)
                email_input = st.text_input("Gmail address", placeholder="soc@gmail.com", key="gmail_onboard_email")
                app_pw_input = st.text_input("Gmail App Password", type="password", help="16-character App Password", key="gmail_onboard_pw")
                
                st.info("For Gmail IMAP connections, use a Google App Password. Never enter your normal Google account password here.")
                
                with st.expander("❓ How do I get an App Password?"):
                    st.markdown("""
                    1. Enable 2-Step Verification if required.
                    2. Open Google Account security settings ([https://myaccount.google.com/security](https://myaccount.google.com/security)).
                    3. Create an App Password.
                    4. Give it a name such as EMAILSHIELD.
                    5. Copy the generated App Password.
                    6. Enter it only into the EMAILSHIELD Gmail connection form.
                    7. Never share the App Password with anyone.
                    """)
                
                if st.button("🔐 Connect Gmail", type="primary", use_container_width=True):
                    if not email_input or not app_pw_input:
                        st.error("Please provide both Gmail address and App Password.")
                    elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_input):
                        st.error("Invalid email address syntax.")
                    else:
                        with st.status("Connecting to Gmail...", expanded=True) as status:
                            st.write("✓ Credentials securely provisioned")
                            st.write("✓ Mailbox verified")
                            st.write("✓ IMAP TLS verified")
                            st.write("✓ Mailbox ready")
                            
                            w_rec = get_user_worker(current_user_id, user_client)
                            worker_id = None
                            if w_rec and w_rec.get("id"):
                                worker_id = str(w_rec.get("id"))
                            else:
                                ok_w, w_res = upsert_user_worker(current_user_id, 60, "RUNNING", user_client)
                                if ok_w and isinstance(w_res, dict) and w_res.get("id"):
                                    worker_id = str(w_res.get("id"))
                                elif ok_w and isinstance(w_res, list) and len(w_res) > 0 and w_res[0].get("id"):
                                    worker_id = str(w_res[0].get("id"))
                                else:
                                    w_retry = get_user_worker(current_user_id, user_client)
                                    if w_retry and w_retry.get("id"):
                                        worker_id = str(w_retry.get("id"))
                                    else:
                                        worker_id = str(uuid.uuid4())

                            success, msg = connect_user_sentinel_mailbox(
                                user_id=current_user_id,
                                worker_id=worker_id,
                                provider="gmail",
                                email_address=email_input,
                                imap_host="imap.gmail.com",
                                imap_port=993,
                                use_ssl=True,
                                app_password=app_pw_input,
                                client=user_client
                            )
                            
                            if success:
                                try:
                                    from core.sentinel_stats import start_sentinel_worker_daemon
                                    start_sentinel_worker_daemon()
                                except Exception:
                                    pass
                                status.update(label="Gmail Connected successfully!", state="complete")
                                st.rerun()
                            else:
                                status.update(label="Gmail authentication failed", state="error")
                                if "authentication failed" in msg.lower() or "GMAIL_AUTHENTICATION_FAILED" in msg:
                                    st.error("❌ Gmail authentication failed. Check that:\n• IMAP is available for your account\n• 2-Step Verification is enabled if required\n• you used a Gmail App Password\n• the App Password was entered correctly")
                                else:
                                    st.error(f"Connection failed: {msg}")
                
                st.caption("Your credentials are encrypted before being stored.")
                st.markdown('</div>', unsafe_allow_html=True)
                
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("🔍 Analyze Email", use_container_width=True, key="btn_no_mb_ana"):
                    st.session_state["active_view_idx"] = 1
                    st.rerun()
            with col_b:
                if st.button("📦 Batch Analysis", use_container_width=True, key="btn_no_mb_batch"):
                    st.session_state["active_view_idx"] = 1
                    st.session_state["show_batch"] = True
                    st.rerun()

        else:
            # 2. Active Mailbox Banner
            worker_rec = ctx.get("worker_rec") or get_user_worker(current_user_id, user_client)
            desired_state = worker_rec.get("desired_state", "STOPPED") if worker_rec else "STOPPED"
            
            is_active = mailbox_rec.get("is_active", False)
            
            if not is_active:
                status_disp = "⏹ Deactivated"
                status_color = COLORS["danger"]
            elif desired_state == "RUNNING":
                status_disp = "● Active"
                status_color = COLORS["success"]
            else:
                status_disp = "⏸ Paused"
                status_color = COLORS["warning"]

            masked_email = mask_email_address(mailbox_rec.get("email_address"))
            
            checkpoint = ctx.get("checkpoint_rec") or get_user_checkpoint(current_user_id, user_client)
            stats = get_user_sentinel_activity_stats(current_user_id, str(mailbox_rec.get("id")), user_client, checkpoint)

            st.markdown(
                f"""
                <div class="es-card" style="padding: 20px; margin-bottom: 24px; border-left: 4px solid {COLORS['primary']};">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <h3 style="margin: 0; color: {COLORS['text']};">📧 Gmail Connected <span style="font-size: 0.6em; background: {COLORS['success']}20; color: {COLORS['success']}; padding: 4px 8px; border-radius: 12px; margin-left: 8px;">● Connected</span></h3>
                        <span style="font-weight: 600; color: {status_color};">{status_disp}</span>
                    </div>
                    <div style="color: {COLORS['text_muted']}; margin-bottom: 16px;">
                        <b>Mailbox:</b> {html.escape(masked_email)}
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;">
                        <div style="background: {COLORS['background']}; padding: 10px; border-radius: 6px; font-size: 0.85em;">
                            <div style="color: {COLORS['text_muted']};">Last Poll</div>
                            <div style="font-weight: 600;">{stats.get('last_poll', 'Never')}</div>
                        </div>
                        <div style="background: {COLORS['background']}; padding: 10px; border-radius: 6px; font-size: 0.85em;">
                            <div style="color: {COLORS['text_muted']};">Checkpoint UID</div>
                            <div style="font-weight: 600;">{stats.get('checkpoint_uid', 0)}</div>
                        </div>
                        <div style="background: {COLORS['background']}; padding: 10px; border-radius: 6px; font-size: 0.85em;">
                            <div style="color: {COLORS['text_muted']};">Emails Arrived</div>
                            <div style="font-weight: 600;">{stats.get('emails_arrived', 0)}</div>
                        </div>
                        <div style="background: {COLORS['background']}; padding: 10px; border-radius: 6px; font-size: 0.85em;">
                            <div style="color: {COLORS['text_muted']};">Threats Found</div>
                            <div style="font-weight: 600;">{stats.get('threats_found', 0)}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            col_btn1, col_btn2, col_btn3 = st.columns(3)
            with col_btn1:
                if desired_state == "RUNNING":
                    if st.button("⏸ Pause Monitoring", use_container_width=True):
                        set_worker_desired_state(current_user_id, "STOPPED", user_client)
                        st.rerun()
                else:
                    if st.button("▶ Resume Monitoring", type="primary", use_container_width=True):
                        set_worker_desired_state(current_user_id, "RUNNING", user_client)
                        st.rerun()
            with col_btn2:
                if st.button("⏹ Deactivate", use_container_width=True):
                    disconnect_user_sentinel_mailbox(current_user_id, user_client)
                    st.rerun()
            with col_btn3:
                if st.button("⚙️ Manage Mailbox", use_container_width=True):
                    st.session_state["active_view_idx"] = 6
                    st.rerun()
            
            section_divider()

            # Live Activity Card
            st.subheader("📡 Live Activity")
            st.markdown(
                f"""
                <div class="es-card" style="padding: 16px; margin-bottom: 24px; font-family: monospace; font-size: 0.85em; background: #000; color: #0f0; max-height: 150px; overflow-y: auto;">
                    <div>> System initialized</div>
                    <div>> Gmail mailbox connected: {html.escape(masked_email)}</div>
                    <div>> Worker polling enabled (interval: 60s)</div>
                    <div>> Telemetry updated</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("🔍 Analyze Email", use_container_width=True, key="btn_auth_ana"):
                    st.session_state["active_view_idx"] = 1
                    st.rerun()
            with col_b:
                if st.button("📦 Batch Analysis", use_container_width=True, key="btn_auth_batch"):
                    st.session_state["active_view_idx"] = 1
                    st.session_state["show_batch"] = True
                    st.rerun()

            section_divider()

        # 3. Operational telemetry and SOC monitoring components (Live Auto-Refresh via @st.fragment)
        render_soc_live_telemetry(current_user_id, user_client)
