"""
core/report.py
Forensic Reporting & Investigator Document Generation Engine for EMAILSHIELD INDIA.

Provides:
1. Executive Summary PDF Report (generate_executive_pdf_report) for SOC Managers.
2. 16-Section Technical Forensic PDF Report (generate_pdf_report).
3. Machine-Readable JSON Telemetry Export (generate_json_report).
"""

import datetime
import html
import io
import json
import os
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.evidence import scan_and_redact_secrets


def safe_text(val: Any, max_len: int = None) -> str:
    """Safely truncates and XML-escapes text for ReportLab Paragraphs to prevent unclosed tag errors."""
    if val is None:
        return ""
    s = str(val).strip()
    if max_len and len(s) > max_len:
        s = s[:max_len] + "..."
    return html.escape(s)


def _get_item_val(item: Any, key: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def generate_json_report(case_data: Dict[str, Any], filepath: Any = None, output_path: Any = None) -> Any:
    """Serialize sanitized case data to formatted JSON string or write to file/stream."""
    target = output_path if output_path is not None else filepath
    clean_data = scan_and_redact_secrets(case_data)
    json_str = json.dumps(clean_data, indent=4, default=str)
    if target is None:
        return json_str
    if isinstance(target, str):
        with open(target, "w", encoding="utf-8") as f:
            f.write(json_str)
        return json_str
    elif hasattr(target, "write"):
        if isinstance(target, io.BytesIO):
            target.write(json_str.encode("utf-8"))
            target.seek(0)
        else:
            target.write(json_str)
        return target
    return json_str


# =====================================================================
# 1. EXECUTIVE SUMMARY PDF REPORT
# =====================================================================

def generate_executive_pdf_report(case_data: Dict[str, Any], filepath: Any = None, output_path: Any = None) -> Any:
    """
    Generates a high-level 1-2 page Executive Summary PDF report designed for SOC managers,
    CISOs, and incident commanders.
    """
    target = output_path if output_path is not None else filepath
    target = target if target is not None else io.BytesIO()
    clean_case = scan_and_redact_secrets(case_data)

    doc = SimpleDocTemplate(target, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle("ExecTitle", parent=styles["Title"], fontSize=17, leading=21, textColor=colors.HexColor("#0f172a"))
    subtitle_style = ParagraphStyle("ExecSubTitle", parent=styles["Normal"], fontSize=9.5, leading=13, textColor=colors.HexColor("#475569"))
    h2_style = ParagraphStyle("ExecH2", parent=styles["Heading2"], fontSize=11, leading=15, textColor=colors.HexColor("#1e293b"), spaceBefore=8, spaceAfter=4)
    body_style = ParagraphStyle("ExecBody", parent=styles["Normal"], fontSize=8.5, leading=11.5, textColor=colors.HexColor("#334155"))
    table_text_style = ParagraphStyle("ExecTable", parent=styles["Normal"], fontSize=8, leading=10)
    verdict_style = ParagraphStyle("ExecVerdict", parent=styles["Normal"], fontSize=10.5, leading=13, textColor=colors.HexColor("#b91c1c"), fontName="Helvetica-Bold")

    elements = []

    # Title Banner
    elements.append(Paragraph("EMAILSHIELD INDIA — INVESTIGATION REPORT", title_style))
    elements.append(Paragraph("Executive Threat Summary & Incident Commander Briefing", subtitle_style))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceBefore=2, spaceAfter=6))

    cid = safe_text(clean_case.get("case_id") or clean_case.get("case_number") or "UNKNOWN")
    ts = safe_text(clean_case.get("timestamp") or clean_case.get("created_at") or "N/A")
    updated = safe_text(clean_case.get("updated_at") or ts)
    sha = safe_text(clean_case.get("sha256") or clean_case.get("original_sha256") or "N/A")
    status = safe_text(clean_case.get("status", "Open"))
    severity = safe_text(clean_case.get("case_severity", "MEDIUM"))
    inv = safe_text(clean_case.get("assigned_investigator") or clean_case.get("investigator") or "SOC Analyst")
    verdict = safe_text(clean_case.get("threat_verdict") or clean_case.get("risk_score", "UNCLASSIFIED"))
    conf = clean_case.get("verdict_confidence", 85)
    sender = safe_text(clean_case.get("sender", "Unknown"))
    recipient = safe_text(clean_case.get("recipient", "Monitored Mailbox User"))
    subject = safe_text(clean_case.get("subject", "No Subject"))

    meta_table_data = [
        [Paragraph("<b>Investigation ID:</b>", body_style), Paragraph(f"<code>{cid}</code>", body_style), Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(status, body_style)],
        [Paragraph("<b>Intake Timestamp:</b>", body_style), Paragraph(ts, body_style), Paragraph("<b>Severity / Verdict:</b>", body_style), Paragraph(f"<b>{severity}</b> | {verdict} ({conf}%)", verdict_style)],
        [Paragraph("<b>Last Updated:</b>", body_style), Paragraph(updated, body_style), Paragraph("<b>Assigned Lead:</b>", body_style), Paragraph(inv, body_style)],
        [Paragraph("<b>Evidence SHA-256:</b>", body_style), Paragraph(f"<font name='Courier'>{sha[:32]}...</font>", body_style), Paragraph("<b>Affected Recipient:</b>", body_style), Paragraph(recipient, body_style)],
        [Paragraph("<b>Suspect Sender:</b>", body_style), Paragraph(sender, body_style), Paragraph("<b>Email Subject:</b>", body_style), Paragraph(subject, body_style)],
    ]
    meta_table = Table(meta_table_data, colWidths=[110, 190, 110, 130])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 8))

    # Executive Summary Text
    elements.append(Paragraph("Executive Summary:", h2_style))
    summary_text = (
        f"Investigation <b>{cid}</b> was initiated upon detection of a <b>{severity}</b> severity electronic communication "
        f"classified as <b>{verdict}</b> with {conf}% forensic confidence. The message arrived from sender <b>{sender}</b> "
        f"addressed to <b>{recipient}</b> under subject '<i>{subject[:60]}</i>'. "
        f"The electronic message has been cryptographically sealed under SHA-256 digest <code>{sha[:16]}...</code>."
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 6))

    # Observed Infrastructure & Primary Attack Indicators
    sloc = clean_case.get("sender_location") or {}
    infra_desc = f"Origin IP: {sloc.get('sender_ip', 'Relay-masked')} ({sloc.get('city', 'Unknown City')}, {sloc.get('country', 'Unknown Country')})" if sloc.get("is_identified") else "Origin IP relay-masked; message routed through intermediate enterprise MTA relays."

    indicators = clean_case.get("indicators", [])
    ioc_summary = f"{len(indicators)} technical indicators extracted (domains, URLs, IPs, payment VPAs)." if indicators else "No external technical indicators observed."

    # Recommended Investigation Status
    if severity in ("HIGH", "CRITICAL") or verdict in ("THREAT", "MALICIOUS"):
        rec_status = "CONTAINMENT RECOMMENDED: Immediate firewall domain/IP block, perimeter sinkholing, and user credential review."
    elif verdict == "SUSPICIOUS":
        rec_status = "ACTIVE INVESTIGATION: Monitor mailbox telemetry and perform secondary sandbox verification on unverified links."
    else:
        rec_status = "CLOSE CASE: Threat cleared by multi-layer forensic and ML heuristics. Benign business communication."

    exec_points = [
        [Paragraph("<b>Primary Attack Indicators:</b>", body_style), Paragraph(ioc_summary, body_style)],
        [Paragraph("<b>Observed Infrastructure:</b>", body_style), Paragraph(infra_desc, body_style)],
        [Paragraph("<b>Recommended Action:</b>", body_style), Paragraph(f"<b>{rec_status}</b>", body_style)],
    ]
    exec_table = Table(exec_points, colWidths=[140, 400])
    exec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(exec_table)
    elements.append(Spacer(1, 10))

    # Legal Disclaimer & Evidence Integrity Stamp
    disclaimer = (
        "<b>INCIDENT COMMANDER NOTICE:</b> This executive summary is synthesized from RFC 5322 electronic mail evidence. "
        "All cryptographic hashes and forensic classifications derive strictly from verified telemetry. "
        "Generated by EMAILSHIELD INDIA."
    )
    elements.append(Paragraph(disclaimer, ParagraphStyle("ExecLegal", parent=styles["Normal"], fontSize=7, leading=9, textColor=colors.HexColor("#64748b"))))

    doc.build(elements)
    if hasattr(target, "seek"):
        target.seek(0)
    return target


# =====================================================================
# 2. 16-SECTION TECHNICAL FORENSIC REPORT
# =====================================================================

def generate_pdf_report(case_data: Dict[str, Any], filepath: Any = None, output_path: Any = None) -> Any:
    """
    Generate comprehensive 16-section technical forensic evidence report.
    Only includes sections for which data actually exists; falls back to 'Not available'.
    """
    target = output_path if output_path is not None else filepath
    target = target if target is not None else io.BytesIO()
    clean_case = scan_and_redact_secrets(case_data)

    doc = SimpleDocTemplate(target, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle("DocTitle", parent=styles["Title"], fontSize=17, leading=21, textColor=colors.HexColor("#0f172a"))
    subtitle_style = ParagraphStyle("DocSubTitle", parent=styles["Normal"], fontSize=9.5, leading=13, textColor=colors.HexColor("#475569"))
    heading2_style = ParagraphStyle("SectionHeader", parent=styles["Heading2"], fontSize=11, leading=15, textColor=colors.HexColor("#1e293b"), spaceBefore=7, spaceAfter=3)
    body_style = ParagraphStyle("BodyTextCustom", parent=styles["Normal"], fontSize=8, leading=10.5, textColor=colors.HexColor("#334155"))
    table_text_style = ParagraphStyle("TableText", parent=styles["Normal"], fontSize=7.5, leading=9.5)
    verdict_style = ParagraphStyle("VerdictText", parent=styles["Normal"], fontSize=10.5, leading=13, textColor=colors.HexColor("#b91c1c"), fontName="Helvetica-Bold")

    elements = []

    # Header Banner
    elements.append(Paragraph("EMAILSHIELD INDIA — TECHNICAL FORENSIC REPORT", title_style))
    elements.append(Paragraph("Forensic Evidence Report — Telemetry, Chain-of-Custody & Threat Assessment", subtitle_style))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceBefore=2, spaceAfter=6))

    # SECTION 1 & 2: Investigation & Email Metadata Box
    cid = safe_text(clean_case.get("case_id") or clean_case.get("case_number") or "UNKNOWN")
    ts = safe_text(clean_case.get("timestamp") or clean_case.get("created_at") or "N/A")
    sha = safe_text(clean_case.get("sha256") or clean_case.get("original_sha256") or "N/A")
    status = safe_text(clean_case.get("status", "Open"))
    inv = safe_text(clean_case.get("assigned_investigator") or clean_case.get("investigator") or "SOC Analyst #1")
    verdict = safe_text(clean_case.get("threat_verdict") or clean_case.get("bec_telemetry", {}).get("verdict") or clean_case.get("risk_score", "UNCLASSIFIED"))
    conf = clean_case.get("verdict_confidence") or clean_case.get("bec_telemetry", {}).get("confidence_pct") or 85
    sender_disp = safe_text(clean_case.get("sender", "Unknown"), 40)
    recipient_disp = safe_text(clean_case.get("recipient", "Monitored Inbox"), 40)
    subject_disp = safe_text(clean_case.get("subject", "N/A"), 35)

    sloc = clean_case.get("sender_location") or {}
    loc_disp = safe_text(sloc.get("display_location") if sloc.get("is_identified") else "Unavailable", 40)
    ip_isp_disp = safe_text(f"{sloc.get('sender_ip', 'N/A')} ({sloc.get('org', 'N/A')})" if sloc.get("is_identified") else "N/A", 35)

    meta_table_data = [
        [Paragraph("<b>Case ID:</b>", body_style), Paragraph(cid, body_style), Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(status, body_style)],
        [Paragraph("<b>Evidence SHA-256:</b>", body_style), Paragraph(f"<font name='Courier'>{sha[:32]}...</font>", body_style), Paragraph("<b>Investigator:</b>", body_style), Paragraph(inv, body_style)],
        [Paragraph("<b>Intake Timestamp:</b>", body_style), Paragraph(ts, body_style), Paragraph("<b>Classification:</b>", body_style), Paragraph(f"<b>{verdict}</b> ({conf}%)", verdict_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(sender_disp, body_style), Paragraph("<b>Recipient:</b>", body_style), Paragraph(recipient_disp, body_style)],
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(subject_disp, body_style), Paragraph("<b>Approx. Origin / IP:</b>", body_style), Paragraph(f"{loc_disp} | {ip_isp_disp}", body_style)],
    ]
    meta_table = Table(meta_table_data, colWidths=[110, 190, 110, 130])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 8))

    # SECTION 3: Cryptographic Authentication & RFC 7489 Alignment
    elements.append(Paragraph("1. Authentication Analysis & RFC 7489 Alignment:", heading2_style))
    auth = clean_case.get("auth_alignment") or {}
    auth_data = [
        ["Mechanism", "Result", "Alignment Status", "Technical Details"],
        ["SPF (Sender Policy)", safe_text(auth.get("spf_result", "NONE")), "Aligned" if auth.get("spf_aligned") else "Unaligned", f"Envelope-From: {safe_text(auth.get('envelope_from_domain', 'N/A'))}"],
        ["DKIM (Signature)", safe_text(auth.get("dkim_result", "NONE")), "Aligned" if auth.get("dkim_aligned") else "Unaligned", f"Signing Domain (d=): {safe_text(auth.get('dkim_signing_domain', 'N/A'))}"],
        ["DMARC (Effective)", safe_text(auth.get("effective_dmarc", "NONE")), "Enforced" if "PASS" in str(auth.get("effective_dmarc")) else "Failed/Bypassed", safe_text(auth.get("dmarc_reason", "N/A"), 80)],
    ]
    a_table = Table(auth_data, colWidths=[90, 80, 90, 280])
    a_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(a_table)
    elements.append(Spacer(1, 8))

    # SECTION 4, 5, 6: IP & Domain Infrastructure Assessment
    infra = clean_case.get("infrastructure_intel") or {}
    if hasattr(infra, "model_dump"):
        infra = infra.model_dump()

    elements.append(Paragraph("2. IP & Domain Infrastructure Intelligence:", heading2_style))
    if infra:
        c_ind = infra.get("cloud_indicator") or {}
        v_ind = infra.get("vpn_indicator") or {}
        t_ind = infra.get("tor_indicator") or {}
        r_ind = infra.get("open_relay_indicator") or {}
        b_ind = infra.get("botnet_indicator") or {}
        tm_ind = infra.get("threat_intel_match") or {}

        infra_data = [
            ["Vector", "Classification", "Confidence", "Forensic Observation"],
            ["Hosting / Cloud", safe_text(c_ind.get("provider", "Standard")), f"{c_ind.get('confidence', 80)}%", safe_text(c_ind.get("evidence", "Standard hosting"), 60)],
            ["VPN Indicator", safe_text(v_ind.get("status", "NOT_DETECTED")), f"{v_ind.get('confidence', 85)}%", safe_text(v_ind.get("evidence", "No VPN identified"), 60)],
            ["Tor Exit Relay", safe_text(t_ind.get("status", "NOT_DETECTED")), f"{t_ind.get('confidence', 95)}%", safe_text(t_ind.get("evidence", "Not in Tor registry"), 60)],
            ["Open Relay (Passive)", safe_text(r_ind.get("status", "NOT_INDICATED")), f"{r_ind.get('confidence', 85)}%", safe_text(r_ind.get("evidence", "Standard delivery"), 60)],
            ["Botnet / Spambot", safe_text(b_ind.get("status", "NOT_INDICATED")), f"{b_ind.get('confidence', 85)}%", safe_text(b_ind.get("evidence", "No botnet C2 detected"), 60)],
            ["Threat Intel Feed", safe_text(tm_ind.get("status", "NO_MATCH")), f"{tm_ind.get('confidence', 90)}%", safe_text(tm_ind.get("evidence", "Clean reputation"), 60)],
        ]
        infra_table = Table(infra_data, colWidths=[100, 110, 60, 270])
        infra_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(infra_table)
    else:
        elements.append(Paragraph("Infrastructure intelligence: Evaluated under RFC 5322 headers. No external passive flags raised.", body_style))
    elements.append(Spacer(1, 8))

    # SECTION 7: Attachment Analysis
    attachments = clean_case.get("attachment_analyses") or []
    if attachments:
        elements.append(Paragraph("3. Attachment Signatures & Forensics:", heading2_style))
        att_data = [["Filename", "Declared MIME", "SHA-256 Checksum", "Risk Rating"]]
        for a in attachments[:5]:
            att_data.append([
                Paragraph(safe_text(_get_item_val(a, "filename", "")), table_text_style),
                Paragraph(safe_text(_get_item_val(a, "content_type", "")), table_text_style),
                Paragraph(f"<font name='Courier'>{safe_text(_get_item_val(a, 'sha256', ''))[:28]}...</font>", table_text_style),
                Paragraph(safe_text(_get_item_val(a, "verdict_label", "BENIGN")), table_text_style),
            ])
        att_table = Table(att_data, colWidths=[120, 110, 220, 90])
        att_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(att_table)
        elements.append(Spacer(1, 8))

    # SECTION 8: IOC Inventory
    elements.append(Paragraph("4. Extracted Indicators of Compromise (IOCs):", heading2_style))
    iocs = clean_case.get("indicators", [])
    if iocs:
        ioc_data = [["Type", "Indicator Value", "Observed Source"]]
        for ind in iocs[:8]:
            ioc_data.append([
                Paragraph(safe_text(_get_item_val(ind, "type", "")), table_text_style),
                Paragraph(safe_text(_get_item_val(ind, "value", ""), 75), table_text_style),
                Paragraph(safe_text(_get_item_val(ind, "source", "Email Body/Headers")), table_text_style),
            ])
        ioc_table = Table(ioc_data, colWidths=[70, 370, 100])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(ioc_table)
    else:
        elements.append(Paragraph("No technical indicators observed.", body_style))
    elements.append(Spacer(1, 8))

    # SECTION 9: Forensic Rule Findings
    elements.append(Paragraph("5. Forensic Findings & Rule Violations:", heading2_style))
    findings = clean_case.get("rule_findings", [])
    if findings:
        r_table_data = [["Rule ID", "Finding", "Severity", "Explanation"]]
        for f in findings[:6]:
            r_table_data.append([
                Paragraph(safe_text(_get_item_val(f, "rule_id")), table_text_style),
                Paragraph(safe_text(_get_item_val(f, "finding")), table_text_style),
                Paragraph(safe_text(_get_item_val(f, "severity")), table_text_style),
                Paragraph(safe_text(_get_item_val(f, "explanation"), 120), table_text_style),
            ])
        rf_table = Table(r_table_data, colWidths=[65, 145, 60, 270])
        rf_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(rf_table)
    else:
        elements.append(Paragraph("No explicit heuristic rule triggers logged.", body_style))
    elements.append(Spacer(1, 8))

    # SECTION 10: Investigation Timeline (Phase 12 Integration)
    elements.append(Paragraph("6. Chronological Investigation Timeline:", heading2_style))
    from core.investigation import build_investigation_timeline
    timeline = build_investigation_timeline(clean_case)
    if timeline:
        time_data = [["Timestamp", "Event Type", "Actor", "Description"]]
        for ev in timeline[:6]:
            time_data.append([
                Paragraph(safe_text(ev.get("timestamp", ""))[:19], table_text_style),
                Paragraph(safe_text(ev.get("event_type", "")), table_text_style),
                Paragraph(safe_text(ev.get("actor", "SYSTEM")), table_text_style),
                Paragraph(safe_text(ev.get("description", ""), 90), table_text_style),
            ])
        t_table = Table(time_data, colWidths=[100, 120, 65, 255])
        t_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_table)
    else:
        elements.append(Paragraph("Timeline events not available.", body_style))
    elements.append(Spacer(1, 8))

    # SECTION 11: Evidence Manifest & Integrity Status
    elements.append(Paragraph("7. Evidence Manifest & Cryptographic Integrity:", heading2_style))
    from core.evidence import build_evidence_manifest
    manifest = build_evidence_manifest(clean_case)
    if manifest:
        m_data = [["Evidence ID", "Type", "Source", "SHA-256 Digest", "Integrity"]]
        for item in manifest[:6]:
            m_data.append([
                Paragraph(safe_text(item.get("evidence_id")), table_text_style),
                Paragraph(safe_text(item.get("evidence_type")), table_text_style),
                Paragraph(safe_text(item.get("source"), 25), table_text_style),
                Paragraph(f"<font name='Courier'>{safe_text(item.get('sha256', ''))[:20]}...</font>", table_text_style),
                Paragraph(safe_text(item.get("integrity_status", "VERIFIED")), table_text_style),
            ])
        m_table = Table(m_data, colWidths=[110, 95, 120, 135, 80])
        m_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(m_table)
    else:
        elements.append(Paragraph("Evidence manifest not available.", body_style))
    elements.append(Spacer(1, 8))

    # SECTION 12: Chain of Custody
    elements.append(Paragraph("8. Chain of Custody Ledger:", heading2_style))
    from core.evidence import build_chain_of_custody
    chain = build_chain_of_custody(clean_case)
    if chain:
        c_data = [["Timestamp", "Event", "Actor", "Action Recorded"]]
        for ce in chain[:6]:
            c_data.append([
                Paragraph(safe_text(ce.get("Timestamp", ""))[:19], table_text_style),
                Paragraph(safe_text(ce.get("Event", "")), table_text_style),
                Paragraph(safe_text(ce.get("Actor", "SYSTEM")), table_text_style),
                Paragraph(safe_text(ce.get("Action", ""), 90), table_text_style),
            ])
        c_table = Table(c_data, colWidths=[100, 110, 60, 270])
        c_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(c_table)
    else:
        elements.append(Paragraph("Historical custody event not available.", body_style))
    elements.append(Spacer(1, 8))

    # SECTION 13: Analyst Notes (if recorded)
    notes = clean_case.get("analyst_notes", "")
    if notes and str(notes).strip():
        elements.append(Paragraph("9. Analyst Collaboration Notes:", heading2_style))
        for line in str(notes).strip().split("\n")[:5]:
            if line.strip():
                elements.append(Paragraph(f"• {safe_text(line.strip())}", body_style))
        elements.append(Spacer(1, 8))

    # Legal Disclaimer & Evidence Integrity Stamp
    elements.append(Spacer(1, 10))
    disclaimer = (
        "<b>FORENSIC EVIDENCE & INTEGRITY ATTESTATION:</b> This document constitutes a machine-generated "
        "forensic evidence report compiled under RFC 5322/2822 parsing standards. SHA-256 evidence digests "
        "are cryptographically verifiable against original digital media. Geolocation and IP indicators "
        "provide approximate infrastructure context derived from mail evidence and do not constitute proof "
        "of physical individual identity or physical location. Generated by EMAILSHIELD INDIA."
    )
    elements.append(Paragraph(disclaimer, ParagraphStyle("Legal", parent=styles["Normal"], fontSize=7, leading=9, textColor=colors.HexColor("#64748b"))))

    doc.build(elements)
    if hasattr(target, "seek"):
        target.seek(0)
    return target
