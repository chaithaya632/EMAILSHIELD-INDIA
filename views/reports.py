import streamlit as st
import io
from views._theme import (
    inject_theme, page_header, metric_card, status_badge_html,
    empty_state, section_divider, detail_row, error_card,
    info_card, success_card, COLORS
)
from core.case_store import get_all_cases, is_authenticated_soc_caller
from core.correlation import build_case_infrastructure_graph
from core.ncrp_packager import generate_ncrp_pdf_annexure, generate_ncrp_complaint_text
from core.report import generate_pdf_report
from core.eml_sanitizer import sanitize_eml_content

def render(current_user_id, user_client, **ctx):
    inject_theme()
    page_header(
        "Evidence & Forensic Reports",
        "Structured electronic evidence certificates under Section 63(4)(c) BSA 2023, NCRP complaint drafting, and attack graph visualization."
    )

    tab_reports, tab_graph = st.tabs(["📄 Evidence & Legal Compliance", "🕸️ Attack Graph"])

    is_authed = is_authenticated_soc_caller(current_user_id, user_client)
    cases = get_all_cases(client=user_client, limit=50) if is_authed else []

    with tab_reports:
        if not is_authed:
            info_card("🔐 **Authentication Required**: Please sign in to access evidence and investigation reports.")
        else:
            current_payload = st.session_state.get("_cached_analysis_payload")

            selected_report_dict = None
            selected_cid = None

            if current_payload and "case_report" in current_payload:
                selected_cid = current_payload["case_id"]
                selected_report_dict = current_payload["case_report"].model_dump()
                info_card(f"Prepared reports for active case: **`{selected_cid}`**")
            elif cases:
                case_opts = [c.get("case_id") for c in cases if c.get("case_id")]
                sel_id = st.selectbox("Select case for reporting:", case_opts, key="reports_case_select")
                sel_case = next((c for c in cases if c.get("case_id") == sel_id), None)
                if sel_case:
                    selected_cid = sel_id
                    selected_report_dict = sel_case
            else:
                empty_state("No investigation available", "Analyze an email or load a sample scenario first.")

            if selected_report_dict and selected_cid:
                col_rep1, col_rep2 = st.columns(2)
                with col_rep1:
                    st.markdown("#### 🇮🇳 Legal Evidence Dossier (BSA 2023)")
                    st.caption("Electronic evidence annexure compliant with Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam.")
                    ncrp_pdf_buf = io.BytesIO()
                    generate_ncrp_pdf_annexure(selected_report_dict, ncrp_pdf_buf)
                    st.download_button(
                        "🇮🇳 Download Section 63(4)(c) BSA Annexure (PDF)",
                        ncrp_pdf_buf.getvalue(),
                        file_name=f"BSA_Sec63_Annexure_{selected_cid}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )

                    st.markdown("#### 🛡️ Comprehensive Technical Dossier")
                    st.caption("Full technical investigation report including headers, indicators, and ML telemetry.")
                    tech_pdf_buf = io.BytesIO()
                    generate_pdf_report(selected_report_dict, tech_pdf_buf)
                    st.download_button(
                        "📄 Download Full Forensic PDF Report",
                        tech_pdf_buf.getvalue(),
                        file_name=f"Forensic_Report_{selected_cid}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )

                with col_rep2:
                    st.markdown("#### 📝 Cybercrime.gov.in Complaint Draft")
                    st.caption("Copy-paste ready complaint text structured for the National Cyber Crime Reporting Portal.")
                    complaint_text = generate_ncrp_complaint_text(selected_report_dict)
                    st.text_area("NCRP Portal Complaint Text:", value=complaint_text, height=180)

                    st.markdown("#### 🔒 Defanged & Sanitized EML")
                    st.caption("Safe-to-share RFC 822 evidence file with neutralized links and quarantined attachments.")
                    current_raw = st.session_state.get("current_email_bytes")
                    if current_raw:
                        san_bytes, def_c, quar_c = sanitize_eml_content(current_raw)
                        st.download_button(
                            f"🛡️ Download Sanitized EML ({def_c} defanged, {quar_c} quarantined)",
                            san_bytes,
                            file_name=f"{selected_cid}_sanitized.eml",
                            mime="message/rfc822",
                            use_container_width=True
                        )
                    else:
                        st.caption("Raw EML binary available when loaded in current session.")

    with tab_graph:
        st.markdown("#### 🕸️ Threat Infrastructure Attack Graph")
        st.caption("Interactive graph correlating Case, Sender, Relay MTAs, Origin IP, ASN, Hosting Provider, and Threat Indicators.")

        if not is_authed:
            info_card("🔐 **Authentication Required**: Please sign in to access investigation attack graphs.")
        else:
            current_payload = st.session_state.get("_cached_analysis_payload")

            target_case_dict = None
            target_case_id = None

            if current_payload and "case_report" in current_payload:
                target_case_id = current_payload["case_id"]
                target_case_dict = current_payload["case_report"].model_dump()
                info_card(f"Displaying attack graph for currently analyzed case: **`{target_case_id}`**")
            elif cases:
                case_options = [c.get("case_id") for c in cases if c.get("case_id")]
                sel_c_id = st.selectbox("Select Case to visualize:", case_options, key="graph_case_select")
                sel_c = next((c for c in cases if c.get("case_id") == sel_c_id), None)
                if sel_c:
                    target_case_id = sel_c_id
                    target_case_dict = sel_c
            else:
                empty_state("No cases available to graph", "Run an email investigation first.")

            if target_case_dict and target_case_id:
                try:
                    fig_g = build_case_infrastructure_graph(target_case_id, target_case_dict)
                    st.plotly_chart(fig_g, use_container_width=True)
                    st.caption("Legend: 🔴 Threat IOCs | 🔵 Origin Infrastructure / ASN | 🟣 Sender & Domain Entities | 🟢 Clean / Verified")
                except Exception as e:
                    error_card(f"Error generating attack graph: {e}")
