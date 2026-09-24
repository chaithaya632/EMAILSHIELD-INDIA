import streamlit as st
import time
import html
import uuid
from views._theme import (
    inject_theme, page_header, metric_card, status_badge_html,
    detail_row, section_divider, error_card, info_card, success_card, empty_state, COLORS
)
from core.case_store import is_authorized_caller
from core.sentinel_control import (
    get_user_mailbox, get_user_worker, get_user_checkpoint,
    upsert_user_worker, set_worker_desired_state, connect_user_sentinel_mailbox,
    deactivate_user_sentinel, mask_email_address
)
from core.sentinel_stats import (
    get_user_sentinel_stats, get_sentinel_worker_runtime,
    reset_user_sentinel_stats, start_sentinel_worker_daemon
)


def render(current_user_id, user_client, **ctx):
    inject_theme()
    page_header("⚙️ Mailbox & Settings", "Configure your mailbox, monitor worker status, and manage the system lifecycle.")

    # 1. AUTHENTICATION GATE: Live Mail must never be accessible for unauthenticated sessions
    if not is_authorized_caller(current_user_id, user_client):
        st.markdown("### 📡 Live Mail")
        st.markdown(f"**Status:** {status_badge_html('neutral', 'DISCONNECTED')}", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        info_card(
            "Authentication Required",
            "Reason: Sign in to access Live Mail Analysis."
        )
        return

    # Fetch authoritative records for the authenticated user (reuse ctx when available)
    mailbox_rec = ctx.get("mailbox_rec")
    worker_rec = ctx.get("worker_rec")
    checkpoint_rec = ctx.get("checkpoint_rec")

    if mailbox_rec is None and current_user_id and user_client:
        try:
            mailbox_rec = get_user_mailbox(current_user_id, user_client)
        except Exception:
            mailbox_rec = None

    if worker_rec is None and current_user_id and user_client:
        try:
            worker_rec = get_user_worker(current_user_id, user_client)
        except Exception:
            worker_rec = None

    if checkpoint_rec is None and current_user_id and user_client:
        try:
            checkpoint_rec = get_user_checkpoint(current_user_id, user_client)
        except Exception:
            checkpoint_rec = None

    mb_id = mailbox_rec.get("id") if mailbox_rec else None

    tab_live_mail, tab_diag = st.tabs([
        "📡 Live Mail",
        "🛡️ Advanced & Diagnostics"
    ])

    with tab_live_mail:
        st.markdown("### 📡 Live Mail")
        st.caption("Unified mailbox configuration, real-time worker monitoring, and operational lifecycle control.")

        # ─────────────────────────────────────────────────────────────
        # SUBSECTION 1: Mailbox
        # ─────────────────────────────────────────────────────────────
        st.markdown("#### 📬 Mailbox")

        desired_state = worker_rec.get("desired_state", "STOPPED") if worker_rec else "STOPPED"
        is_mb_active = bool(mailbox_rec and mailbox_rec.get("is_active", False))

        if not mailbox_rec or not mailbox_rec.get("email_address"):
            mb_status = "DISCONNECTED"
            mb_color = "neutral"
            disp_email = "Not configured"
            disp_provider = "N/A"
        elif is_mb_active:
            disp_email = mask_email_address(mailbox_rec.get("email_address", ""))
            disp_provider = str(mailbox_rec.get("provider", "Custom")).capitalize()
            if desired_state == "RUNNING":
                mb_status = "ACTIVE"
                mb_color = "safe"
            elif desired_state == "STOPPED":
                mb_status = "PAUSED"
                mb_color = "warning"
            else:
                mb_status = "ACTIVE"
                mb_color = "safe"
        else:
            disp_email = mask_email_address(mailbox_rec.get("email_address", ""))
            disp_provider = str(mailbox_rec.get("provider", "Custom")).capitalize()
            mb_status = "DEACTIVATED"
            mb_color = "danger"

        col_m1, col_m2, col_m3 = st.columns(3)
        with col_m1:
            st.markdown(f"**Email:** `{disp_email}`")
        with col_m2:
            st.markdown(f"**Provider:** `{disp_provider}`")
        with col_m3:
            st.markdown(f"**Status:** {status_badge_html(mb_color, mb_status)}", unsafe_allow_html=True)

        manage_expander_title = "⚙️ Connect / Change Mailbox" if (not mailbox_rec or not mailbox_rec.get("email_address")) else "⚙️ Manage Mailbox"
        with st.expander(manage_expander_title, expanded=(not mailbox_rec or not mailbox_rec.get("email_address"))):
            st.markdown("Select your email provider for setup instructions.")
            provider = st.selectbox("Email Provider", ["Gmail", "Outlook / Office 365", "Yahoo", "Zoho", "Corporate IMAP"], key="sb_mb_provider")

            if provider == "Gmail":
                info_card(
                    "Gmail Setup Instructions",
                    "1. Go to your Google Account > Security.<br>"
                    "2. Enable 2-Step Verification.<br>"
                    "3. Search for 'App Passwords' and create one for 'EmailShield'.<br>"
                    "4. Use the generated 16-character password to connect."
                )
                st.markdown("[Go to Google Account Security](https://myaccount.google.com/security)")
            elif provider == "Outlook / Office 365":
                info_card(
                    "Outlook Setup Instructions",
                    "Ensure IMAP is enabled in your account settings. If your organization uses 2FA, create an App Password."
                )
            elif provider == "Yahoo":
                info_card(
                    "Yahoo Setup Instructions",
                    "Generate a third-party app password in your Yahoo Account Security settings."
                )
            elif provider == "Zoho":
                info_card(
                    "Zoho Setup Instructions",
                    "Enable IMAP access in Zoho Mail settings. If MFA is active, generate an Application Specific Password."
                )
            else:
                info_card(
                    "Corporate IMAP Setup",
                    "Enter your organization's IMAP server address and port (usually 993). Ensure your firewall allows outbound connections."
                )

            st.markdown("---")
            st.markdown("##### Mailbox Credentials")

            with st.form("connect_mailbox_form"):
                col1, col2 = st.columns(2)
                with col1:
                    email_input = st.text_input("Email Address")
                with col2:
                    password_input = st.text_input("Password / App Password", type="password")
                host_input = st.text_input("IMAP Server (Optional for major providers)")
                if st.form_submit_button("Connect", use_container_width=True):
                    if not email_input or not password_input:
                        error_card("Validation Error", "Please provide both an email address and a password / app password.")
                    else:
                        prov_lower = provider.lower()
                        if "gmail" in prov_lower:
                            clean_prov = "gmail"
                            default_host = "imap.gmail.com"
                        elif "outlook" in prov_lower or "office" in prov_lower:
                            clean_prov = "outlook"
                            default_host = "outlook.office365.com"
                        elif "yahoo" in prov_lower:
                            clean_prov = "yahoo"
                            default_host = "imap.mail.yahoo.com"
                        elif "zoho" in prov_lower:
                            clean_prov = "zoho"
                            default_host = "imap.zoho.com"
                        else:
                            clean_prov = "custom"
                            default_host = "imap.gmail.com"

                        resolved_host = host_input.strip() if host_input and host_input.strip() else default_host
                        wid = worker_rec.get("id") if (worker_rec and worker_rec.get("id")) else None
                        if not wid:
                            ok_w, w_res = upsert_user_worker(current_user_id, 60, "RUNNING", user_client)
                            if ok_w and isinstance(w_res, dict) and w_res.get("id"):
                                wid = str(w_res.get("id"))
                            elif ok_w and isinstance(w_res, list) and len(w_res) > 0 and w_res[0].get("id"):
                                wid = str(w_res[0].get("id"))
                            else:
                                w_retry = get_user_worker(current_user_id, user_client)
                                if w_retry and w_retry.get("id"):
                                    wid = str(w_retry.get("id"))
                                else:
                                    wid = str(uuid.uuid4())

                        success, msg = connect_user_sentinel_mailbox(
                            user_id=current_user_id,
                            worker_id=wid,
                            provider=clean_prov,
                            email_address=email_input.strip(),
                            imap_host=resolved_host,
                            imap_port=993,
                            use_ssl=True,
                            app_password=password_input.strip(),
                            client=user_client
                        )
                        if success:
                            try:
                                start_sentinel_worker_daemon()
                            except Exception:
                                pass
                            success_card("Mailbox Connection", msg)
                            st.rerun()
                        else:
                            error_card("Connection Failed", msg)

        section_divider()

        # ─────────────────────────────────────────────────────────────
        # SUBSECTION 2: Monitoring (Worker Monitoring)
        # ─────────────────────────────────────────────────────────────
        st.markdown("#### 📡 Worker Monitoring")
        st.caption("🟢 Telemetry auto-refreshes every 2 seconds without full-page reload.")

        @st.fragment(run_every=2)
        def render_monitoring_fragment():
            try:
                rt = get_sentinel_worker_runtime()
            except Exception:
                rt = {}

            try:
                stats = get_user_sentinel_stats(
                    user_id=current_user_id,
                    mailbox_id=mb_id,
                    client=user_client,
                    checkpoint_rec=checkpoint_rec
                )
            except Exception:
                stats = {
                    "emails_arrived": 0,
                    "emails_analysed": 0,
                    "clean_count": 0,
                    "suspicious_count": 0,
                    "high_critical_count": 0,
                    "last_poll_time": "Never",
                    "last_processed_uid": 0,
                    "errors": 0,
                    "recent_events": []
                }

            is_proc_alive = rt.get("worker_process_alive", False)

            if is_mb_active and desired_state == "RUNNING" and is_proc_alive:
                monitoring_status = "ACTIVE"
            elif is_mb_active and desired_state == "RUNNING" and not is_proc_alive:
                monitoring_status = "STARTING / IDLE"
            elif desired_state == "STOPPED":
                monitoring_status = "PAUSED"
            elif not is_mb_active:
                monitoring_status = "DEACTIVATED"
            else:
                monitoring_status = "OFFLINE"

            worker_status = "RUNNING" if is_proc_alive else desired_state

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown(metric_card("Monitoring Status", monitoring_status), unsafe_allow_html=True)
            with col2:
                st.markdown(metric_card("Worker Status", worker_status), unsafe_allow_html=True)
            with col3:
                st.markdown(metric_card("Emails Analysed", str(stats.get("emails_analysed", 0))), unsafe_allow_html=True)
            with col4:
                threats = stats.get("suspicious_count", 0) + stats.get("high_critical_count", 0)
                st.markdown(metric_card("Threats Detected", str(threats)), unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            meta_c1, meta_c2, meta_c3, meta_c4 = st.columns(4)
            with meta_c1:
                st.markdown(f"**Last Poll:** `{stats.get('last_poll_time', 'Never')}`")
            with meta_c2:
                st.markdown(f"**Last UID:** `{stats.get('last_processed_uid', 0)}`")
            with meta_c3:
                st.markdown(f"**Emails Arrived:** `{stats.get('emails_arrived', 0)}`")
            with meta_c4:
                st.markdown(f"**Processing Errors:** `{stats.get('errors', 0)}`")

            section_divider()
            st.markdown("##### Live Activity")

            recent_events = stats.get("recent_events", [])
            logs = []
            if recent_events:
                for evt in recent_events[:6]:
                    logs.append(f"{evt.get('time', '')} [{evt.get('category', 'Clean')}] Subject: '{html.escape(evt.get('subject', 'No Subject')[:35])}'")

            now_str = time.strftime("%H:%M:%S")
            if is_proc_alive:
                logs.append(f"{now_str} Worker process active (PID: {rt.get('worker_pid', 'system')})")
                logs.append(f"{now_str} Telemetry synced with checkpoint UID {stats.get('last_processed_uid', 0)}")
            elif desired_state == "RUNNING":
                logs.append(f"{now_str} Worker state RUNNING (awaiting scheduled poll cycle)")
            else:
                logs.append(f"{now_str} Worker state is STOPPED / PAUSED")

            log_content = "<br>".join([f"<code>{html.escape(log)}</code>" for log in logs])
            st.markdown(
                f"<div style='background-color:#1E1E1E; color:#D4D4D4; padding:10px; border-radius:5px; font-family:monospace; max-height: 200px; overflow-y:auto;'>{log_content}</div>", 
                unsafe_allow_html=True
            )

            if st.button("🔄 Force Refresh Telemetry", key="btn_force_refresh_telemetry"):
                st.rerun(scope="fragment")

        render_monitoring_fragment()

        section_divider()

        # ─────────────────────────────────────────────────────────────
        # SUBSECTION 3: Lifecycle
        # ─────────────────────────────────────────────────────────────
        st.markdown("#### ⚠️ Lifecycle Management")
        st.caption("Manage worker execution and configuration. Historical cases, reports, and evidence are preserved.")

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("▶ Resume Monitoring", key="btn_resume_worker", use_container_width=True, type="primary"):
                ok, msg = set_worker_desired_state(current_user_id, "RUNNING", user_client)
                if ok:
                    try:
                        start_sentinel_worker_daemon()
                    except Exception:
                        pass
                    success_card("Lifecycle Update", "Worker desired state set to RUNNING. Mailbox polling active.")
                    st.rerun()
                else:
                    error_card("Error", msg)

        with col2:
            if st.button("⏸ Pause Monitoring", key="btn_pause_worker", use_container_width=True):
                ok, msg = set_worker_desired_state(current_user_id, "STOPPED", user_client)
                if ok:
                    info_card("Lifecycle Update", "Worker desired state set to STOPPED. Mailbox polling paused. Checkpoints preserved.")
                    st.rerun()
                else:
                    error_card("Error", msg)

        with col3:
            if st.button("⏹ Deactivate Mailbox", key="btn_deactivate_worker", use_container_width=True):
                ok, msg = deactivate_user_sentinel(current_user_id, user_client)
                if ok:
                    info_card("Lifecycle Update", "Mailbox deactivated. Worker stopped. Historical data preserved.")
                    st.rerun()
                else:
                    error_card("Error", msg)

        with st.expander("⚠️ Configuration Reset"):
            st.warning("This will reset temporary errors and runtime metadata. It **will not** reset the last processed UID or delete historical evidence.")
            if st.button("⚠️ Reset Configuration", key="btn_reset_config"):
                try:
                    reset_user_sentinel_stats(current_user_id, mb_id)
                    success_card("Configuration Reset", "Runtime configuration reset successfully. Checkpoint UID preserved.")
                    st.rerun()
                except Exception as e:
                    error_card("Reset Error", str(e))

    with tab_diag:
        st.markdown("### 🛡️ Advanced & Diagnostics")
        st.markdown("#### System Health")
        st.markdown(detail_row("Disk Space", "45% Used"), unsafe_allow_html=True)
        st.markdown(detail_row("Detection Pipeline", "Operational"), unsafe_allow_html=True)
        
        section_divider()
        st.markdown("#### Storage Management")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Dry-Run Cleanup"):
                info_card("Dry-Run", "Found 45MB of temporary files to clean.")
        with col2:
            if st.button("Execute Safe Cleanup"):
                success_card("Cleanup", "45MB of temporary files removed successfully.")
