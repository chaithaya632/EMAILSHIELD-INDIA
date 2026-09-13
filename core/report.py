import json
import os
import html
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from typing import Dict, Any

def safe_text(val: Any, max_len: int = None) -> str:
    """Safely truncates and XML-escapes text for ReportLab Paragraphs to prevent unclosed tag errors."""
    if val is None:
        return ""
    s = str(val).strip()
    if max_len and len(s) > max_len:
        s = s[:max_len] + "..."
    return html.escape(s)

def generate_json_report(case_data: Dict[str, Any], filepath: str):
    with open(filepath, 'w') as f:
        json.dump(case_data, f, indent=4, default=str)
        
def generate_pdf_report(case_data: Dict[str, Any], filepath: str):
    doc = SimpleDocTemplate(filepath, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('DocTitle', parent=styles['Title'], fontSize=18, leading=22, textColor=colors.HexColor('#0f172a'))
    subtitle_style = ParagraphStyle('DocSubTitle', parent=styles['Normal'], fontSize=10, leading=14, textColor=colors.HexColor('#475569'))
    heading2_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=12, leading=16, textColor=colors.HexColor('#1e293b'), spaceBefore=8, spaceAfter=4)
    body_style = ParagraphStyle('BodyTextCustom', parent=styles['Normal'], fontSize=8.5, leading=11, textColor=colors.HexColor('#334155'))
    table_text_style = ParagraphStyle('TableText', parent=styles['Normal'], fontSize=8, leading=10)
    verdict_style = ParagraphStyle('VerdictText', parent=styles['Normal'], fontSize=11, leading=14, textColor=colors.HexColor('#b91c1c'), fontName='Helvetica-Bold')

    elements = []
    
    # Header Banner
    elements.append(Paragraph("EMAILSHIELD INDIA — FORENSIC INTELLIGENCE REPORT", title_style))
    elements.append(Paragraph("Forensic Evidence Report — Electronic Mail Telemetry, Chain-of-Custody & Threat Assessment", subtitle_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceBefore=2, spaceAfter=8))
    
    # Case Evidence & Chain of Custody Box
    cid = safe_text(case_data.get('case_id', 'UNKNOWN'))
    ts = safe_text(case_data.get('timestamp', 'N/A'))
    sha = safe_text(case_data.get('original_sha256', 'N/A'))
    status = safe_text(case_data.get('status', 'Open'))
    inv = safe_text(case_data.get('assigned_investigator', 'SOC Analyst #1'))
    verdict = safe_text(case_data.get('threat_verdict') or case_data.get('bec_telemetry', {}).get('verdict') or case_data.get('risk_score', 'UNCLASSIFIED'))
    conf = case_data.get('verdict_confidence') or case_data.get('bec_telemetry', {}).get('confidence_pct') or 85
    sender_disp = safe_text(case_data.get('sender', 'Unknown'), 40)
    subject_disp = safe_text(case_data.get('subject', 'N/A'), 35)
    
    sloc = case_data.get('sender_location') or {}
    loc_disp = safe_text(sloc.get('display_location') if sloc.get('is_identified') else 'Unavailable', 40)
    ip_isp_disp = safe_text(f"{sloc.get('sender_ip', 'N/A')} ({sloc.get('org', 'N/A')})" if sloc.get('is_identified') else 'N/A', 35)

    meta_table_data = [
        [Paragraph("<b>Case ID:</b>", body_style), Paragraph(cid, body_style), Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(status, body_style)],
        [Paragraph("<b>Evidence SHA-256:</b>", body_style), Paragraph(f"<font name='Courier'>{safe_text(sha[:32])}...</font>", body_style), Paragraph("<b>Investigator:</b>", body_style), Paragraph(inv, body_style)],
        [Paragraph("<b>Intake Timestamp:</b>", body_style), Paragraph(ts, body_style), Paragraph("<b>Classification:</b>", body_style), Paragraph(f"<b>{verdict}</b> ({conf}%)", verdict_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(sender_disp, body_style), Paragraph("<b>Subject:</b>", body_style), Paragraph(subject_disp, body_style)],
        [Paragraph("<b>Approx. Origin:</b>", body_style), Paragraph(loc_disp, body_style), Paragraph("<b>Originating IP / ISP:</b>", body_style), Paragraph(ip_isp_disp, body_style)]
    ]
    meta_table = Table(meta_table_data, colWidths=[110, 190, 110, 130])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    # Threat Findings & Forensic Violations
    elements.append(Paragraph("Forensic Findings & Rule Violations:", heading2_style))
    findings = case_data.get("rule_findings", [])
    if findings:
        r_table_data = [["Rule ID", "Finding", "Severity", "Explanation"]]
        for f in findings[:6]:
            r_table_data.append([
                Paragraph(safe_text(f.get("rule_id", "")), table_text_style),
                Paragraph(safe_text(f.get("finding", "")), table_text_style),
                Paragraph(safe_text(f.get("severity", "")), table_text_style),
                Paragraph(safe_text(f.get("explanation", ""), 120), table_text_style)
            ])
        rf_table = Table(r_table_data, colWidths=[65, 145, 60, 270])
        rf_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(rf_table)
    else:
        elements.append(Paragraph("No explicit rule violations recorded.", body_style))
        
    elements.append(Spacer(1, 10))

    # Cryptographic Authentication & DMARC Alignment
    elements.append(Paragraph("Cryptographic Authentication & RFC 7489 Alignment:", heading2_style))
    auth = case_data.get("auth_alignment") or {}
    auth_data = [
        ["Mechanism", "Result", "Alignment Status", "Technical Details"],
        ["SPF (Sender Policy)", safe_text(auth.get("spf_result", "NONE")), "Aligned" if auth.get("spf_aligned") else "Unaligned", f"Envelope-From: {safe_text(auth.get('envelope_from_domain', 'N/A'))}"],
        ["DKIM (Signature)", safe_text(auth.get("dkim_result", "NONE")), "Aligned" if auth.get("dkim_aligned") else "Unaligned", f"Signing Domain (d=): {safe_text(auth.get('dkim_signing_domain', 'N/A'))}"],
        ["DMARC (Effective)", safe_text(auth.get("effective_dmarc", "NONE")), "Enforced" if "PASS" in str(auth.get("effective_dmarc")) else "Failed/Bypassed", safe_text(auth.get("dmarc_reason", "N/A"), 80)]
    ]
    a_table = Table(auth_data, colWidths=[90, 80, 90, 280])
    a_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(a_table)
    elements.append(Spacer(1, 10))

    # Attachment Forensics
    attachments = case_data.get("attachment_analyses") or []
    if attachments:
        elements.append(Paragraph("Attachment Cryptographic Signatures & Forensics:", heading2_style))
        att_data = [["Filename", "Declared MIME", "SHA-256 Checksum", "Risk Rating"]]
        for a in attachments[:5]:
            att_data.append([
                Paragraph(safe_text(a.get("filename", "")), table_text_style),
                Paragraph(safe_text(a.get("content_type", "")), table_text_style),
                Paragraph(f"<font name='Courier'>{safe_text(a.get('sha256', ''))[:28]}...</font>", table_text_style),
                Paragraph(safe_text(a.get("verdict_label", "BENIGN")), table_text_style)
            ])
        att_table = Table(att_data, colWidths=[120, 110, 220, 90])
        att_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(att_table)
        elements.append(Spacer(1, 10))

    # Indicators of Compromise (IOCs)
    elements.append(Paragraph("Extracted Indicators of Compromise (IOCs):", heading2_style))
    iocs = case_data.get("indicators", [])
    if iocs:
        ioc_data = [["Type", "Indicator Value", "Observed Source"]]
        for ind in iocs[:8]:
            ioc_data.append([
                Paragraph(safe_text(ind.get("type", "")), table_text_style),
                Paragraph(safe_text(ind.get("value", ""), 75), table_text_style),
                Paragraph(safe_text(ind.get("source", "Email Body/Headers")), table_text_style)
            ])
        ioc_table = Table(ioc_data, colWidths=[70, 370, 100])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(ioc_table)
    else:
        elements.append(Paragraph("No technical indicators observed.", body_style))

    # Legal Disclaimer & Evidence Integrity Stamp
    elements.append(Spacer(1, 14))
    disclaimer = (
        "<b>FORENSIC EVIDENCE & INTEGRITY ATTESTATION:</b> This document constitutes a machine-generated "
        "forensic evidence report compiled under RFC 5322/2822 parsing standards. SHA-256 evidence digests "
        "are cryptographically verifiable against original digital media. Geolocation and IP indicators "
        "provide approximate infrastructure context derived from mail evidence and do not constitute proof "
        "of physical individual identity or physical location. Generated by EMAILSHIELD INDIA."
    )
    elements.append(Paragraph(disclaimer, ParagraphStyle('Legal', parent=styles['Normal'], fontSize=7, leading=9, textColor=colors.HexColor('#64748b'))))

    doc.build(elements)


