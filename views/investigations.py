import streamlit as st
import html
from views._theme import (
    inject_theme, page_header, metric_card, status_badge_html, 
    empty_state, section_divider, detail_row, error_card, 
    info_card, success_card, COLORS
)
from core.case_store import (
    is_authenticated_soc_caller, get_case_record, get_all_cases, 
    export_case_executive_pdf, export_case_report_pdf, 
    export_case_zip_package, export_case_evidence_manifest, 
    export_case_report_json, export_case_ncrp_pdf, 
    export_case_iocs_csv, export_case_iocs_json
)
from core.investigation import (
    LIFECYCLE_STATES, normalize_to_lifecycle_status, 
    map_lifecycle_to_db_status, build_investigation_timeline, 
    get_investigation_evidence, get_investigation_emails, 
    get_investigation_indicators, add_analyst_note, 
    transition_investigation_status, open_or_get_investigation, 
    search_investigations, build_evidence_manifest, 
    verify_evidence_integrity, verify_all_manifest_integrity, 
    build_chain_of_custody, IntegrityStatus, EvidenceType
)
from core.geolocation import derive_authoritative_location, get_country_flag
from core.correlation import build_case_infrastructure_graph
from core.ncrp_packager import generate_ncrp_complaint_text

def render(current_user_id, user_client, **ctx):
    inject_theme()
    
    page_header('Investigations', 'Search, review, and manage forensic investigations')

    if not is_authenticated_soc_caller(current_user_id, user_client):
        st.info("🔐 **Authentication Required**: Please sign in or register via the sidebar to view, search, and manage historical investigations.")
        return

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
        
        sev_col = {"CRITICAL": COLORS["red"], "HIGH": COLORS["amber"], "MEDIUM": COLORS["amber"], "LOW": COLORS["green"]}.get(sev, COLORS["text_secondary"])
        status_col = {"NEW": COLORS["blue"], "INVESTIGATING": COLORS["amber"], "CONTAINED": COLORS["purple"], "CLOSED": COLORS["green"]}.get(lifecycle_s, COLORS["text_secondary"])

        st.markdown(
            f"""
            <div style="background-color: {COLORS['surface']}; border: 1px solid {COLORS['border']}; border-radius: 10px; padding: 18px; margin: 10px 0 20px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <h3 style="color: {COLORS['accent']}; margin: 0;">🔎 Investigation: {html.escape(active_inv_id)}</h3>
                    <div>
                        <span style="background-color: {sev_col}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: bold; margin-right: 6px;">SEVERITY: {sev}</span>
                        <span style="background-color: {status_col}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; font-weight: bold;">STATUS: {lifecycle_s}</span>
                    </div>
                </div>
                <p style="color: {COLORS['text']}; font-size: 0.95em; margin: 8px 0 4px 0;">
                    <b>Subject:</b> {html.escape(str(active_case.get('subject', 'No Subject')))}
                </p>
                <div style="color: {COLORS['text_secondary']}; font-size: 0.82em;">
                    👤 <b>Assigned:</b> {html.escape(str(active_case.get('assigned_investigator', 'Unassigned')))} | 
                    🕒 <b>Created:</b> {active_case.get('timestamp', 'N/A')} | 
                    🎯 <b>Verdict:</b> <code style="color: {COLORS['red']};">{html.escape(verdict)}</code>
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

            section_divider()
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

            section_divider()
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
                        <div style="background-color: {COLORS['surface_2']}; border-left: 3px solid {COLORS['accent']}; border-radius: 4px; padding: 10px 14px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; font-size: 0.82em; color: {COLORS['text_secondary']};">
                                <b>{html.escape(ev.get('event_type', 'Event'))}</b>
                                <span>{html.escape(str(ev.get('timestamp', '')))} | <code>{act_badge}</code></span>
                            </div>
                            <div style="color: {COLORS['text']}; font-size: 0.9em; margin-top: 4px;">
                                {html.escape(ev.get('description', ''))}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                empty_state("No Timeline Events", "No timeline events recorded.")

        with tab_ws_mail:
            st.subheader("📧 Related Emails & Bounded Metadata")
            st.caption("Protected envelope metadata. Sensitive tokens, passwords, and raw mailboxes are never exposed.")
            emails = get_investigation_emails(active_case)
            if not emails:
                empty_state("No Emails", "No related emails found.")
            for em in emails:
                st.markdown(f"**Subject:** `{em.get('subject')}`")
                c_em1, c_em2 = st.columns(2)
                with c_em1:
                    detail_row("From", em.get('from', ''))
                    detail_row("Date", em.get('date', ''))
                with c_em2:
                    detail_row("To", em.get('to', ''))
                    detail_row("Message-ID", em.get('message_id', ''))
                
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
                empty_state("No Indicators", "No extracted indicators of compromise for this investigation.")

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
                empty_state("No Attack Graph", "No correlated attack relationships available for this investigation.")

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
                    success_card(f"✅ **INTEGRITY VERIFIED**: All {len(manifest)} evidence artifacts matched their recorded cryptographic SHA-256 digests.")
                elif overall_status == IntegrityStatus.MISMATCH:
                    error_card("🚨 **INTEGRITY MISMATCH**: One or more evidence artifacts failed cryptographic SHA-256 verification!")
                else:
                    st.warning("⚠️ **HASH NOT AVAILABLE**: Some artifacts do not have recorded cryptographic digests.")
                st.markdown("##### Cryptographic Evidence Manifest")
                st.dataframe(verified_manifest, use_container_width=True)
            else:
                st.markdown("##### Cryptographic Evidence Manifest")
                st.dataframe(manifest, use_container_width=True)

            section_divider()
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
                empty_state("No Notes", "No analyst notes recorded yet.")

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

            section_divider()
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
            empty_state("No Investigations", "No historical investigations found for your account. Upload or analyze an email to create a case.")
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

            section_divider()
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
