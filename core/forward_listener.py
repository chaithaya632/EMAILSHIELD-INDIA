import email
import email.policy
import re
import uuid
import datetime
from typing import Dict, Any, Optional, Tuple, List
from core.parser import SecureEmailParser
from core.indicators import extract_all_indicators
from core.auth_claims import parse_auth_results
from core.geolocation import get_geolocation
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.case_store import save_case
from core.schemas import (
    CaseReport, Indicator, GeolocationInfo, AuthEvidence,
    RuleFinding, MLAssessment, EventTimeline, DomainReputation
)
from core.domain_reputation import get_domain_reputation
from core.ai_reasoning import generate_forensic_reasoning

def extract_email_address(raw_header: str) -> str:
    """Extract clean email address from header string like 'Rahul <rahul@enterprise.in>'."""
    if not raw_header:
        return "unknown@user.com"
    match = re.search(r'<([^>]+)>', raw_header)
    if match:
        return match.group(1).strip().lower()
    match2 = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_header)
    if match2:
        return match2.group(0).strip().lower()
    return raw_header.strip().lower()

def extract_forward_metadata(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Extracts the outer forwarder identity and separates the inner forwarded email.
    Supports both RFC 822 attached .eml and inline forwarded text.
    """
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    
    outer_from = str(msg.get("From", ""))
    outer_to = str(msg.get("To", ""))
    outer_subject = str(msg.get("Subject", "Forwarded Email"))
    outer_date = str(msg.get("Date", ""))
    
    forwarded_by = extract_email_address(outer_from)
    
    # Check if there is an attached RFC822 message (.eml attachment)
    inner_bytes = None
    for part in msg.walk():
        content_type = part.get_content_type()
        filename = part.get_filename() or ""
        if content_type == "message/rfc822" or filename.lower().endswith(".eml"):
            payload = part.get_payload()
            if isinstance(payload, list) and len(payload) > 0:
                inner_bytes = payload[0].as_bytes()
            elif isinstance(payload, (bytes, bytearray)):
                inner_bytes = bytes(payload)
            elif hasattr(part, 'as_bytes'):
                inner_bytes = part.as_bytes()
            break
            
    # If no separate .eml attachment, check for inline forwarded text
    if not inner_bytes:
        body_text = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_text += part.get_content()
                except Exception:
                    body_text += str(part.get_payload())
                    
        # Check for inline forward patterns
        forward_marker = re.search(
            r'(-{3,}\s*Forwarded message\s*-{3,}|-{3,}\s*Original Message\s*-{3,})',
            body_text,
            re.IGNORECASE
        )
        if forward_marker:
            inner_section = body_text[forward_marker.end():].strip()
            # Synthesize an .eml from the inline forwarded block
            synthesized = f"Subject: {outer_subject}\nFrom: Forwarded-Original\nContent-Type: text/plain; charset=utf-8\n\n{inner_section}"
            inner_bytes = synthesized.encode("utf-8", errors="replace")
        else:
            inner_bytes = raw_bytes

    return {
        "forwarded_by": forwarded_by,
        "outer_from": outer_from,
        "outer_to": outer_to,
        "outer_subject": outer_subject,
        "outer_date": outer_date,
        "inner_bytes": inner_bytes
    }

def generate_automated_response(case_report: CaseReport) -> str:
    """Generates an enterprise-grade automated reply email for the user who forwarded the suspicious message."""
    verdict_icons = {
        "HIGH": "🚨 HIGH RISK (PHISHING / MALICIOUS)",
        "SUSPICIOUS": "⚠️ SUSPICIOUS (PROCEED WITH CAUTION)",
        "LOW": "✅ CLEAN / LOW RISK (AUTHENTIC)"
    }
    verdict_text = verdict_icons.get(case_report.risk_score, "ℹ️ UNCERTAIN")
    
    actions = {
        "HIGH": (
            "1. DO NOT click on any links or download attachments from this email.\n"
            "2. DO NOT reply or submit credentials or financial information.\n"
            "3. The email has been recorded in the security queue for perimeter blocking."
        ),
        "SUSPICIOUS": (
            "1. Verify the sender through a trusted separate channel (e.g. phone call or official portal).\n"
            "2. Avoid clicking links directly; navigate to official websites manually.\n"
            "3. If in doubt, delete the message."
        ),
        "LOW": (
            "1. Cryptographic and behavioral checks did not observe malicious indicators.\n"
            "2. Ensure standard operational security when opening files."
        )
    }
    recommended_action = actions.get(case_report.risk_score, "Verify sender manually.")
    
    findings_list = "\n".join([f"  • {r}" for r in case_report.risk_reasons[:4]]) or "  • No adverse indicators."
    
    loc_summary = "None detected"
    if case_report.geolocation:
        g = case_report.geolocation[0]
        loc_summary = f"{g.city or 'Unknown City'}, {g.country} (ISP: {g.org or 'Unknown'})"

    reply = f"""Subject: [EMAILSHIELD #{case_report.case_id}] Threat Analysis Verdict: {case_report.risk_score}

Dear User ({case_report.forwarded_by or 'Investigator'}),

EMAILSHIELD INDIA Automated Forensic Gateway has completed the threat evaluation for the email you forwarded:

----------------------------------------------------------------------
📋 INCIDENT SUMMARY
----------------------------------------------------------------------
• Incident Ticket ID : {case_report.case_id}
• Verdict            : {verdict_text}
• Analyzed Subject   : {case_report.subject}
• Original Sender    : {case_report.sender}
• Infrastructure     : {loc_summary}
• Evidence SHA-256   : {case_report.original_sha256[:16]}...

----------------------------------------------------------------------
🔍 FORENSIC FINDINGS
----------------------------------------------------------------------
{findings_list}

----------------------------------------------------------------------
🛡️ RECOMMENDED ACTION
----------------------------------------------------------------------
{recommended_action}

Thank you for reporting this incident to the EMAILSHIELD Cyber Defense System.
Reference ID: {case_report.case_id} | Automated SOC Response Gateway
"""
    return reply

def process_forwarded_message(raw_bytes: bytes, ml_classifier) -> Tuple[CaseReport, str]:
    """
    Processes a forwarded email end-to-end:
    1. Identifies the user who forwarded it.
    2. Runs the inner payload through the parser, indicators, geo, rules, and ML.
    3. Builds and saves the CaseReport with multi-user attribution.
    4. Produces the automated response text for the user.
    """
    meta = extract_forward_metadata(raw_bytes)
    forwarded_by = meta["forwarded_by"]
    inner_bytes = meta["inner_bytes"]
    
    # 1. Parse inner payload
    parser = SecureEmailParser(inner_bytes)
    parsed_data = parser.parse()
    headers = parsed_data.get("headers", {})
    body = parsed_data.get("body", "")
    
    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    
    # 2. Indicators
    indicators = []
    raw_iocs = extract_all_indicators(body + " " + str(headers))
    for ip in raw_iocs["ipv4"]:
        indicators.append(Indicator(type="IP", value=ip, source="Body/Headers"))
    for url in raw_iocs["urls"]:
        indicators.append(Indicator(type="URL", value=url, source="Body/Headers"))
    for email_addr in raw_iocs["emails"]:
        indicators.append(Indicator(type="Email", value=email_addr, source="Body/Headers"))
        
    # 3. Auth claims
    auth_header = str(headers.get("authentication-results", ""))
    auth_evidence = []
    if auth_header:
        parsed_auth = parse_auth_results(auth_header)
        for a in parsed_auth:
            auth_evidence.append(AuthEvidence(**a))
            
    # 4. Geolocation
    geolocations = []
    for ip in raw_iocs["ipv4"]:
        geo = get_geolocation(ip)
        geolocations.append(GeolocationInfo(**geo))
        
    # 5. ML & Rules
    subject = str(headers.get("subject", meta["outer_subject"]))
    sender_val = str(headers.get("from", "Unknown"))
    domain_rep = get_domain_reputation(sender_val)
    
    ml_pred = ml_classifier.predict(subject, body)
    ml_assessment = MLAssessment(**ml_pred, model_version="1.0")
    
    rule_results = evaluate_rules(parsed_data, domain_rep=domain_rep)
    rule_findings = [RuleFinding(**r) for r in rule_results]
    
    risk_score, reasons = calculate_hybrid_risk(rule_results, ml_pred["probability"])
    
    ai_briefing = generate_forensic_reasoning(
        subject=subject,
        sender=sender_val,
        risk_score=risk_score,
        risk_reasons=reasons,
        rule_findings=rule_findings,
        ml_prob=ml_pred["probability"],
        domain_rep=domain_rep,
        origin_geo=geolocations[0] if geolocations else None
    )
    
    # 6. Timeline
    timeline_events = []
    for idx, rec in enumerate(parsed_data.get("received_chain", [])):
        ip_match = None
        raw_ips = extract_all_indicators(rec)["ipv4"]
        if raw_ips:
            ip_match = raw_ips[0]
        loc_str = "UNKNOWN"
        lat = None
        lon = None
        city = None
        if ip_match:
            g = get_geolocation(ip_match)
            parts = [p for p in [g.get("city"), g.get("region"), g.get("country")] if p and p != "UNKNOWN"]
            loc_str = ", ".join(parts) if parts else g.get("country", "UNKNOWN")
            city = g.get("city")
            lat = g.get("latitude")
            lon = g.get("longitude")
        
        timeline_events.append(EventTimeline(
            timestamp=datetime.datetime.utcnow(),
            source=f"Hop {idx+1}",
            ip=ip_match,
            hostname=None,
            country=loc_str,
            city=city,
            latitude=lat,
            longitude=lon,
            evidence_ref=rec[:100] + "..."
        ))
        
    timeline_events.append(EventTimeline(
        timestamp=datetime.datetime.utcnow(),
        source=f"Forwarded by {forwarded_by}",
        ip=None,
        hostname="EMAILSHIELD-INGESTION",
        country="User Endpoint",
        evidence_ref="User forward-to-verify submission"
    ))
    
    # 7. Case Report
    case_report = CaseReport(
        case_id=case_id,
        timestamp=datetime.datetime.utcnow(),
        original_sha256=parsed_data["sha256"],
        subject=subject,
        sender=sender_val,
        forwarded_by=forwarded_by,
        ingestion_source="Forward-to-Verify",
        indicators=indicators,
        geolocation=geolocations,
        auth_results=auth_evidence,
        rule_findings=rule_findings,
        ml_assessment=ml_assessment,
        domain_reputation=domain_rep,
        ai_reasoning=ai_briefing,
        timeline=timeline_events,
        risk_score=risk_score,
        risk_reasons=reasons
    )
    
    save_case(case_report.model_dump())
    auto_reply = generate_automated_response(case_report)
    
    return case_report, auto_reply
