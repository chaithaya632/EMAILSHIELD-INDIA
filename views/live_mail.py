import streamlit as st
import os
import uuid
import html
from typing import Tuple

from views._theme import (
    inject_theme, page_header, metric_card, status_badge_html, 
    empty_state, section_divider, detail_row, error_card, 
    info_card, success_card, COLORS
)

from core.case_store import is_authorized_caller
from core.rate_limiter import check_sliding_window_rate_limit

from core.sentinel_control import (
    get_user_worker, upsert_user_worker, set_worker_desired_state, 
    get_user_mailbox, connect_user_sentinel_mailbox, disconnect_user_sentinel_mailbox, 
    get_user_checkpoint, get_user_alerts, save_user_alert_metadata, 
    deactivate_user_sentinel, delete_user_sentinel_config, 
    ALLOWED_PROVIDERS, PROVIDER_IMAP_DEFAULTS, mask_email_address
)

from core.telegram_alert import (
    get_telegram_config, verify_telegram_bot_token, validate_telegram_token_format, 
    validate_telegram_chat_id, test_telegram_alert_delivery
)

from core.whatsapp_alert import (
    get_whatsapp_config, test_whatsapp_alert_delivery, 
    validate_whatsapp_phone, validate_whatsapp_apikey
)


def check_rate_limit(action: str, max_requests: int = 10, window_seconds: int = 60) -> Tuple[bool, int]:
    if "rate_limits" not in st.session_state:
        st.session_state["rate_limits"] = {}
    return check_sliding_window_rate_limit(
        tracker=st.session_state["rate_limits"],
        action=action,
        max_requests=max_requests,
        window_seconds=window_seconds
    )


def render(current_user_id, user_client, **ctx):
    inject_theme()
    
    st.header("📡 Live Mail Analysis")
    st.caption("Continuous, evidence-backed email monitoring for authorized user mailboxes.")

    if not is_authorized_caller(current_user_id, user_client):
        st.info("🔐 **Authentication Required**: Please sign in or register via the sidebar to access Live Mail Analysis.")
        return

    # Extract initial context OR fallback to dynamic fetching (preserving existing behaviour)
    worker_rec = ctx.get("worker_rec") if "worker_rec" in ctx else get_user_worker(current_user_id, user_client)
    mailbox_rec = ctx.get("mailbox_rec") if "mailbox_rec" in ctx else get_user_mailbox(current_user_id, user_client)
    checkpoint_rec = ctx.get("checkpoint_rec") if "checkpoint_rec" in ctx else get_user_checkpoint(current_user_id, user_client)
    alerts_rec = ctx.get("alerts_rec") if "alerts_rec" in ctx else get_user_alerts(current_user_id, user_client)

    is_mailbox_active = bool(mailbox_rec and mailbox_rec.get("is_active", False))
    desired_state = worker_rec.get("desired_state", "STOPPED") if worker_rec else "STOPPED"
    has_worker = worker_rec is not None
    worker_id = worker_rec.get("id") if worker_rec else str(uuid.uuid4())
    raw_email = mailbox_rec.get("email_address", "") if mailbox_rec else ""
    masked_email = mask_email_address(raw_email)

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

    section_divider()

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
                if st.button("⏹️ Stop Monitoring", key="btn_stop_active_sentinel", use_container_width=False):
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
                if st.button("▶️ Resume Monitoring", type="primary", key="btn_resume_active_sentinel", use_container_width=False):
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
            if st.button("🔌 Disconnect Mailbox", type="secondary", key="btn_disconnect_mb", use_container_width=False):
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
        @st.fragment(run_every=2)
        def render_live_activity_tab():
            # Re-fetch fresh state on each fragment tick so cloud and local get latest updates
            fresh_worker_rec = get_user_worker(current_user_id, user_client)
            fresh_checkpoint_rec = get_user_checkpoint(current_user_id, user_client)

            from core.sentinel_stats import get_user_sentinel_stats
            sentinel_stats = get_user_sentinel_stats(
                user_id=current_user_id,
                mailbox_id=mailbox_rec.get("id") if mailbox_rec else None,
                client=user_client,
                checkpoint_rec=fresh_checkpoint_rec
            )

            # Section 16 Safe Diagnostics Block
            try:
                from core.sentinel_stats import get_sentinel_worker_runtime
                worker_rt = get_sentinel_worker_runtime(worker_rec=fresh_worker_rec)
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
                        st.rerun(scope="fragment")
                    else:
                        st.error(msg_start)

            st.caption("🟢 Auto-refresh: ON (2s interval)")

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
                if not sentinel_stats.get("has_polled", False) and sentinel_stats.get("emails_arrived", 0) == 0:
                    st.info("ℹ️ **Waiting for first poll...** Initial sync establishes the checkpoint UID. Historical mailbox messages are skipped to inspect incoming arrivals only.")
                else:
                    st.caption("No new threat events in the latest poll cycle. Inbox is monitored continuously.")

            section_divider()

            threats_count = sentinel_stats.get("suspicious", 0) + sentinel_stats.get("high_critical", 0)
            st.markdown(
                f"**{sentinel_stats.get('emails_arrived', 0)}** Arrived · "
                f"**{sentinel_stats.get('emails_analysed', 0)}** Analysed · "
                f"**{threats_count}** Threats"
            )

            p_col1, p_col2 = st.columns([2, 1])
            with p_col1:
                st.markdown(f"**Last Poll**  \n{sentinel_stats.get('last_poll_time', 'N/A')}")
            with p_col2:
                if st.button("🔄 Refresh Telemetry", key="btn_refresh_sentinel_telemetry", help="Optional manual refresh", use_container_width=False):
                    st.rerun(scope="fragment")

            with st.expander("⚙️ Technical Details", expanded=False):
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

        render_live_activity_tab()

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
            if st.button("🔔 Test Alert", key="btn_mobile_quick_test_banner", use_container_width=False):
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

        section_divider()

        alert_col1, alert_col2 = st.columns(2)

        # =========================================================
        # 1. TELEGRAM ALERTS (Section 5)
        # =========================================================
        with alert_col1:
            st.markdown("**✈️ Telegram Alerts (HIGH Risk Only)**")

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
                    if st.button("🧪 Test Alert", key="btn_test_tg_connected", use_container_width=False):
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
                    if st.button("🔌 Disconnect", key="btn_disc_tg", type="secondary", use_container_width=False):
                        for k in ["sentinel_tg_token", "sentinel_tg_destination", "sentinel_tg_target", "sentinel_tg_token_entry", "sentinel_tg_enabled", "sentinel_tg_enabled_chk", "sentinel_tg_toggle_connected", "_tg_token_auth_cache"]:
                            st.session_state.pop(k, None)
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
                    if st.button("💾 Connect / Save", key="btn_save_tg_config", use_container_width=False):
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
                    if st.button("🧪 Test Alert", key="btn_test_tg_alert", use_container_width=False):
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
                    if st.button("🧪 Test Alert", key="btn_test_wa_connected", use_container_width=False):
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
                    if st.button("🔌 Disconnect", key="btn_disc_wa", type="secondary", use_container_width=False):
                        for k in ["sentinel_wa_apikey", "sentinel_wa_destination", "sentinel_wa_target", "sentinel_wa_key_entry", "sentinel_wa_enabled", "sentinel_wa_enabled_chk", "sentinel_wa_toggle_connected"]:
                            st.session_state.pop(k, None)
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
                    "WhatsApp Phone",
                    value=runtime_wa.get("phone", "") or (wa_config.get("destination_target", "") if wa_config else ""),
                    placeholder="+919876543210",
                    help="Include country code with '+' (e.g., +91). This is the WhatsApp number to receive alerts.",
                    key="sentinel_wa_target"
                )

                has_wa_env_key = bool(os.environ.get("CALLMEBOT_API_KEY"))
                if not has_wa_env_key:
                    if runtime_wa["is_apikey_configured"]:
                        st.caption("🔒 *API Key configured in session memory (Runtime Protected).*")
                        wa_key_in = st.text_input(
                            "Change CallMeBot API Key (optional)",
                            value="",
                            type="password",
                            placeholder="Leave blank to keep existing key",
                            help="Enter a new API key if you wish to change it.",
                            key="sentinel_wa_key_entry"
                        )
                    else:
                        wa_key_in = st.text_input(
                            "CallMeBot API Key",
                            value="",
                            type="password",
                            placeholder="6-digit alphanumeric key",
                            help="Stored in transient session memory only.",
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
                    if st.button("💾 Connect / Save", key="btn_save_wa_config", use_container_width=False):
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
                    if st.button("🧪 Test Alert", key="btn_test_wa_unconn", use_container_width=False):
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
