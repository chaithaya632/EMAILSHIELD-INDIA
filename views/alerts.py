import streamlit as st
from views._theme import (
    inject_theme, page_header, metric_card, status_badge_html, empty_state, section_divider, detail_row, error_card, info_card, success_card, COLORS
)
from core.case_store import is_authorized_caller
from core.telegram_alert import (
    get_telegram_config, test_telegram_alert_delivery,
    validate_telegram_token_format, validate_telegram_chat_id
)
from core.whatsapp_alert import (
    get_whatsapp_config, test_whatsapp_alert_delivery,
    validate_whatsapp_phone, validate_whatsapp_apikey
)
from core.sentinel_control import save_user_alert_metadata
from core.alert_session import (
    save_telegram_connection,
    get_telegram_connection,
    get_telegram_credentials,
    disconnect_telegram,
    set_telegram_status,
    save_whatsapp_connection,
    get_whatsapp_connection,
    get_whatsapp_credentials,
    disconnect_whatsapp,
    set_whatsapp_status,
)

def render(current_user_id, user_client, **ctx):
    inject_theme()
    page_header("Mobile Threat Alerts", "Configure automated Telegram and WhatsApp security notifications for high-priority cyber threats.")

    if not is_authorized_caller(current_user_id, user_client):
        info_card("🔐 **Authentication Required**: Please sign in or register via the sidebar to access and configure mobile threat alerts.")
        return

    # Extract worker_id safely from context
    worker_rec = ctx.get("worker_rec")
    worker_id = None
    if isinstance(worker_rec, dict):
        worker_id = worker_rec.get("id")
    elif hasattr(worker_rec, "id"):
        worker_id = getattr(worker_rec, "id", None)
    if not worker_id:
        worker_id = ctx.get("worker_id")

    tab_tg, tab_wa = st.tabs(["✈️ Telegram Bot Alerts", "💬 WhatsApp Alerts"])

    with tab_tg:
        st.subheader("✈️ Telegram Security Bot")
        st.markdown(
            "Receive real-time push alerts on your phone whenever a **HIGH** or **CRITICAL** threat arrives in your monitored mailbox."
        )
        with st.expander("❓ How do I get a Telegram Bot Token and Chat ID?", expanded=False):
            st.markdown(
                """
                1. Open Telegram and search for **@BotFather**.
                2. Send `/newbot` and follow prompts to choose a bot name and a username ending in `bot`.
                3. Copy the **Bot Token**: Authenticates your Telegram bot.
                4. To find your **Chat ID**: Destination where EmailShield sends alerts, search for `@userinfobot` on Telegram and click Start.
                
                ⚠️ **Security Notice:** Never share your Telegram Bot Token. EmailShield masks the token after configuration.
                Click **🧪 Test Alert** to verify end-to-end delivery.
                """
            )
        tg_conn = get_telegram_connection(current_user_id)
        is_tg_active = bool(tg_conn.get("connected") and tg_conn.get("status") == "ACTIVE")
        tg_status = tg_conn.get("status", "NOT_CONNECTED")

        if is_tg_active:
            st.markdown(status_badge_html("safe", "🟢 ACTIVE"), unsafe_allow_html=True)
            st.markdown("**Connected**")
            st.markdown(f"**Destination:** {tg_conn.get('masked_destination', '')}")
            if tg_conn.get("bot_username"):
                st.markdown(f"**Bot:** {tg_conn.get('bot_username')}")

            col_tg_act1, col_tg_act2 = st.columns(2)
            with col_tg_act1:
                btn_test_tg_connected = st.button("🧪 Test Alert", key="btn_test_tg_connected", type="primary")
            with col_tg_act2:
                btn_disc_tg = st.button("🔌 Disconnect", key="btn_disc_tg", type="secondary")

            if btn_test_tg_connected:
                tok, cid = get_telegram_credentials(current_user_id)
                if not tok or not cid:
                    error_card("Telegram Alert Failed", "Failed to retrieve decrypted Telegram credentials from session.")
                else:
                    with st.spinner("Testing Telegram alert delivery..."):
                        test_res = test_telegram_alert_delivery(tok, cid)
                    if test_res.get("delivery_status") == "DELIVERED":
                        success_card("Telegram Alert Sent", test_res.get("details") or "Test alert successfully sent to Telegram!")
                    else:
                        error_card("Telegram Alert Failed", test_res.get("details") or "Failed to send Telegram alert.")

            if btn_disc_tg:
                disconnect_telegram(current_user_id)
                if user_client and worker_id:
                    save_user_alert_metadata(
                        current_user_id,
                        worker_id,
                        "telegram",
                        "",
                        is_enabled=False,
                        high_risk_only=True,
                        client=user_client
                    )
                st.rerun()

        else:
            if tg_status == "CONNECTION_FAILED":
                badge_label = "🔴 CONNECTION FAILED"
                badge_style = "danger"
            elif tg_status == "TEST_FAILED":
                badge_label = "🔴 TEST FAILED"
                badge_style = "danger"
            elif tg_status == "DISCONNECTED":
                badge_label = "⚪ DISCONNECTED"
                badge_style = "neutral"
            else:
                badge_label = "⚪ NOT CONNECTED"
                badge_style = "neutral"

            st.markdown(status_badge_html(badge_style, badge_label), unsafe_allow_html=True)

            tg_conf = get_telegram_config() if tg_status != "DISCONNECTED" else {}
            init_tg_token = tg_conf.get("token") or tg_conf.get("bot_token", "")
            init_tg_chat = tg_conf.get("chat_id") or tg_conf.get("destination_target", "")

            tg_token = st.text_input(
                "Telegram Bot Token:",
                value=init_tg_token,
                type="password",
                placeholder="e.g. 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ",
                key="tg_cfg_tok"
            )
            tg_chat = st.text_input(
                "Telegram Chat ID:",
                value=init_tg_chat,
                placeholder="e.g. 987654321",
                key="tg_cfg_chat"
            )

            col_tg1, col_tg2 = st.columns(2)
            with col_tg1:
                btn_test_tg_page = st.button("🧪 Send Test Telegram Alert", type="primary", key="btn_test_tg_page")
            with col_tg2:
                btn_save_tg_page = st.button("💾 Save / Connect", key="btn_save_tg_page")

            if btn_test_tg_page or btn_save_tg_page:
                token_str = (tg_token or "").strip()
                chat_str = (tg_chat or "").strip()

                if not token_str or not chat_str:
                    set_telegram_status(current_user_id, "CONNECTION_FAILED")
                    error_card("Validation Error", "Please configure both Telegram Bot Token and Chat ID.")
                elif not validate_telegram_token_format(token_str):
                    set_telegram_status(current_user_id, "CONNECTION_FAILED")
                    error_card("Validation Error", "Invalid Telegram Bot Token format. Expected <bot_id>:<token> (e.g. 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ).")
                else:
                    is_valid_chat, chat_msg = validate_telegram_chat_id(chat_str)
                    if not is_valid_chat:
                        set_telegram_status(current_user_id, "CONNECTION_FAILED")
                        error_card("Validation Error", chat_msg)
                    else:
                        with st.spinner("Testing Telegram alert delivery..."):
                            test_res = test_telegram_alert_delivery(token_str, chat_str)
                        if test_res.get("delivery_status") == "DELIVERED":
                            save_telegram_connection(
                                current_user_id,
                                token_str,
                                chat_str,
                                bot_username=test_res.get("bot_username")
                            )
                            if user_client and worker_id:
                                save_user_alert_metadata(
                                    current_user_id,
                                    worker_id,
                                    "telegram",
                                    chat_str,
                                    is_enabled=True,
                                    high_risk_only=True,
                                    client=user_client
                                )
                            st.rerun()
                        else:
                            set_telegram_status(current_user_id, "TEST_FAILED")
                            error_card("Telegram Alert Failed", test_res.get("details") or "Failed to send Telegram alert.")

    with tab_wa:
        st.subheader("💬 WhatsApp Threat Notifications")
        st.markdown(
            "Receive WhatsApp messages via CallMeBot gateway for urgent incident response."
        )
        with st.expander("❓ How do I configure WhatsApp Alerts?", expanded=False):
            st.markdown(
                """
                Integration provider: **WhatsApp via CallMeBot** gateway.
                1. Add the CallMeBot phone number to your contacts on WhatsApp.
                2. Send the message: `I allow callmebot to send me messages` to request your key.
                3. **Phone Number**: The WhatsApp destination in international format (+91...).
                4. **CallMeBot API Key**: The authentication credential used by CallMeBot.
                
                Visit [callmebot.com](https://www.callmebot.com) for official documentation.
                ⚠️ **Security Notice:** Never share your CallMeBot API key. EmailShield masks credentials after configuration.
                Click **🧪 Test Alert** to dispatch a harmless verification ping.
                """
            )
        wa_conn = get_whatsapp_connection(current_user_id)
        is_wa_active = bool(wa_conn.get("connected") and wa_conn.get("status") == "ACTIVE")
        wa_status = wa_conn.get("status", "NOT_CONNECTED")

        if is_wa_active:
            st.markdown(status_badge_html("safe", "🟢 ACTIVE"), unsafe_allow_html=True)
            st.markdown("**Connected**")
            st.markdown(f"**Destination:** {wa_conn.get('masked_destination', '')}")
            st.markdown("**Provider:** Connected (CallMeBot Gateway)")

            col_wa_act1, col_wa_act2 = st.columns(2)
            with col_wa_act1:
                btn_test_wa_connected = st.button("🧪 Test Alert", key="btn_test_wa_connected", type="primary")
            with col_wa_act2:
                btn_disc_wa = st.button("🔌 Disconnect", key="btn_disc_wa", type="secondary")

            if btn_test_wa_connected:
                phone, apikey = get_whatsapp_credentials(current_user_id)
                if not phone or not apikey:
                    error_card("WhatsApp Alert Failed", "Failed to retrieve decrypted WhatsApp credentials from session.")
                else:
                    with st.spinner("Testing WhatsApp alert delivery..."):
                        test_res = test_whatsapp_alert_delivery(phone, apikey)
                    if test_res.get("delivery_status") == "DELIVERED":
                        success_card("WhatsApp Alert Sent", test_res.get("details") or "Test alert successfully sent to WhatsApp!")
                    else:
                        error_card("WhatsApp Alert Failed", test_res.get("details") or "Failed to send WhatsApp alert.")

            if btn_disc_wa:
                disconnect_whatsapp(current_user_id)
                if user_client and worker_id:
                    save_user_alert_metadata(
                        current_user_id,
                        worker_id,
                        "whatsapp",
                        "",
                        is_enabled=False,
                        high_risk_only=True,
                        client=user_client
                    )
                st.rerun()

        else:
            if wa_status == "CONNECTION_FAILED":
                wa_badge_label = "🔴 CONNECTION FAILED"
                wa_badge_style = "danger"
            elif wa_status == "TEST_FAILED":
                wa_badge_label = "🔴 TEST FAILED"
                wa_badge_style = "danger"
            elif wa_status == "DISCONNECTED":
                wa_badge_label = "⚪ DISCONNECTED"
                wa_badge_style = "neutral"
            else:
                wa_badge_label = "⚪ NOT CONNECTED"
                wa_badge_style = "neutral"

            st.markdown(status_badge_html(wa_badge_style, wa_badge_label), unsafe_allow_html=True)

            wa_conf = get_whatsapp_config() if wa_status != "DISCONNECTED" else {}
            init_wa_phone = wa_conf.get("phone") or wa_conf.get("phone_number", "")
            init_wa_key = wa_conf.get("apikey") or wa_conf.get("api_key", "")

            wa_phone = st.text_input(
                "WhatsApp Phone Number (with Country Code):",
                value=init_wa_phone,
                placeholder="e.g. +919876543210",
                key="wa_cfg_ph"
            )
            wa_key = st.text_input(
                "CallMeBot API Key:",
                value=init_wa_key,
                type="password",
                key="wa_cfg_key"
            )

            col_wa1, col_wa2 = st.columns(2)
            with col_wa1:
                btn_test_wa_page = st.button("🧪 Send Test WhatsApp Alert", type="primary", key="btn_test_wa_page")
            with col_wa2:
                btn_save_wa_page = st.button("💾 Save / Connect", key="btn_save_wa_page")

            if btn_test_wa_page or btn_save_wa_page:
                phone_str = (wa_phone or "").strip()
                key_str = (wa_key or "").strip()

                if not phone_str or not key_str:
                    set_whatsapp_status(current_user_id, "CONNECTION_FAILED")
                    error_card("Validation Error", "Please configure both Phone Number and CallMeBot API Key.")
                else:
                    is_valid_phone, phone_res = validate_whatsapp_phone(phone_str)
                    if not is_valid_phone:
                        set_whatsapp_status(current_user_id, "CONNECTION_FAILED")
                        error_card("Validation Error", phone_res)
                    else:
                        is_valid_key, key_res = validate_whatsapp_apikey(key_str)
                        if not is_valid_key:
                            set_whatsapp_status(current_user_id, "CONNECTION_FAILED")
                            error_card("Validation Error", key_res)
                        else:
                            with st.spinner("Testing WhatsApp alert delivery..."):
                                test_res = test_whatsapp_alert_delivery(phone_res, key_res)
                            if test_res.get("delivery_status") == "DELIVERED":
                                save_whatsapp_connection(current_user_id, phone_res, key_res)
                                if user_client and worker_id:
                                    save_user_alert_metadata(
                                        current_user_id,
                                        worker_id,
                                        "whatsapp",
                                        phone_res,
                                        is_enabled=True,
                                        high_risk_only=True,
                                        client=user_client
                                    )
                                st.rerun()
                            else:
                                set_whatsapp_status(current_user_id, "TEST_FAILED")
                                error_card("WhatsApp Alert Failed", test_res.get("details") or "Failed to send WhatsApp alert.")
