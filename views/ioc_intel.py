import streamlit as st
import html
import ipaddress

from views._theme import (
    inject_theme, page_header, metric_card, status_badge_html, 
    empty_state, section_divider, detail_row, error_card, 
    info_card, success_card, COLORS
)

from core.case_store import (
    is_authenticated_soc_caller,
    get_all_indicators,
    export_case_iocs_csv,
    export_case_iocs_json
)
from core.geolocation import get_geolocation, get_country_flag, derive_authoritative_location
from core.infrastructure_intel import assess_infrastructure, is_public_ip
from core.url_forensics import analyze_url
from core.domain_reputation import get_domain_reputation

def render(current_user_id, user_client, **ctx):
    inject_theme()
    
    page_header("Threat Intelligence & IOC Command Center", "Investigate threat indicators, inspect suspicious links, and export IOCs for SIEM ingestion.")

    tab_ioc_repo, tab_geoip, tab_ioc_sandbox = st.tabs([
        "📁 Tenant IOC Repository",
        "🗺️ GeoIP & Threat Infrastructure",
        "🔬 URL / Indicator Sandbox Inspector"
    ])

    with tab_ioc_repo:
        st.subheader("📁 Indicators of Compromise (IOCs)")
        if not is_authenticated_soc_caller(current_user_id, user_client):
            info_card("🔐 **Authentication Required**: Please sign in to access IOC and threat intelligence data.")
        else:
            indicators = get_all_indicators(client=user_client, limit=1000)
            if indicators:
                c_ioc1, c_ioc2 = st.columns([3, 1])
                with c_ioc1:
                    ioc_types = sorted(list({ind.get("type", "UNKNOWN") for ind in indicators}))
                    type_filter = st.selectbox("Filter by IOC Type:", ["All"] + ioc_types)
                with c_ioc2:
                    metric_card("Total Extracted IOCs", str(len(indicators)))

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
                empty_state("No IOCs", "No IOCs recorded yet. Analyze an email to extract indicators.", "🔍")

    with tab_geoip:
        st.subheader("🗺️ GeoIP & Threat Infrastructure Intelligence")
        st.caption("Active & historical threat infrastructure intelligence, origin geolocations, and routing context.")

        if not is_authenticated_soc_caller(current_user_id, user_client):
            info_card("🔐 **Authentication Required**: Please sign in to access GeoIP and threat infrastructure intelligence.")
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
                error_card(st.session_state["manual_geo_error"])

            section_divider()
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
                    st.markdown(f"**Target IP:** `{html.escape(active_manual_ip)}`")

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
                                <span style="background-color: {vpn_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">VPN: {html.escape(str(b_vpn))}</span>
                                <span style="background-color: {tor_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Tor: {html.escape(str(b_tor))}</span>
                                <span style="background-color: {relay_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Open Relay: {html.escape(str(b_relay))}</span>
                                <span style="background-color: {botnet_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Botnet: {html.escape(str(b_botnet))}</span>
                                <span style="background-color: {threat_bg}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.76em; font-weight: bold;">Threat Feed: {html.escape(str(b_threat))}</span>
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
                    st.markdown(f"**Associated Case:** `{html.escape(str(cached_payload.get('case_id', 'Active Investigation')))}`")

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
                        f"> **Relay-Masked:** YES — {html.escape(str(sloc.get('relay_masked_explanation', 'The available email telemetry does not expose a reliable public client/originating IP.')))}"
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
                info_card("ℹ️ Enter an IP address above to inspect geographic and threat infrastructure intelligence, or analyze an email in '📧 Analyze Email' to populate email-derived hops.")

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
                    res = analyze_url(ioc_clean)
                    st.markdown(f"**Target URL:** `{html.escape(res.url)}`")
                    st.markdown(f"**Defanged URL:** `{html.escape(res.defanged_url)}`")
                    
                    # Modernize risk level display using status badge
                    if res.risk_level.upper() in ["HIGH", "CRITICAL"]:
                        badge_color = COLORS["danger"]
                    elif res.risk_level.upper() == "MEDIUM":
                        badge_color = COLORS["warning"]
                    else:
                        badge_color = COLORS["success"]
                    
                    st.markdown(f"**Risk Level:** {status_badge_html(res.risk_level, badge_color)}", unsafe_allow_html=True)
                    st.markdown(f"**Threat Category:** `{html.escape(res.threat_category)}`")
                    
                    if res.reasons:
                        st.write("**Detection Flags:**")
                        for r in res.reasons:
                            st.write(f"- {html.escape(r)}")
                elif "." in ioc_clean and not any(c in ioc_clean for c in "/: "):
                    d_rep = get_domain_reputation(ioc_clean)
                    st.json(d_rep.model_dump())
                else:
                    geo = get_geolocation(ioc_clean)
                    st.json(geo)
