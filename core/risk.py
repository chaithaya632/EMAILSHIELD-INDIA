import re
from typing import Dict, Any, List

def evaluate_rules(
    parsed_email: Dict[str, Any],
    domain_rep: Any = None,
    url_analyses: Any = None,
    auth_alignment: Any = None,
    attachment_analyses: Any = None,
    lookalike_analysis: Any = None,
    bec_telemetry: Any = None,
    relay_transit: Any = None
) -> List[Dict[str, str]]:
    findings = []
    headers = parsed_email.get("headers", {})
    body = parsed_email.get("body", "").lower()
    
    # Check if this email is a recognized newsletter or bulk mailing
    is_newsletter = bool(
        headers.get("list-unsubscribe") or
        headers.get("list-id") or
        str(headers.get("precedence", "")).lower() == "bulk" or
        headers.get("feedback-id")
    )

    # 1. Reply-To Mismatch
    from_header = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    
    # Helper to extract just the email address
    def extract_email(header_val: str):
        if not isinstance(header_val, str):
            return ""
        match = re.search(r'<(.+?)>', header_val)
        if match:
            return match.group(1).lower()
        return header_val.strip().lower()

    def get_base_domain(email_str: str):
        if "@" not in email_str:
            return ""
        dom = email_str.split("@")[-1].lower()
        parts = dom.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else dom

    if reply_to and from_header:
        f_email = extract_email(from_header)
        r_email = extract_email(reply_to)
        
        if f_email and r_email and f_email != r_email:
            f_dom = get_base_domain(f_email)
            r_dom = get_base_domain(r_email)
            same_org = (f_dom == r_dom) and bool(f_dom)

            has_bec_fraud = bec_telemetry and (
                bec_telemetry.get("is_financial_lure") or
                bec_telemetry.get("is_display_name_spoof") or
                bec_telemetry.get("is_executive_lure")
            )

            # High severity ONLY when impersonating executives/finance or diverting away from legitimate brand
            if has_bec_fraud:
                findings.append({
                    "rule_id": "RULE-001",
                    "finding": "Reply-To Diversion (Financial/Executive Lure)",
                    "evidence": f"From: {from_header} | Reply-To: {reply_to}",
                    "severity": "HIGH",
                    "explanation": "Reply-To address redirects replies away from apparent sender during an executive/financial lure."
                })
            elif not same_org and not is_newsletter:
                findings.append({
                    "rule_id": "RULE-001",
                    "finding": "Reply-To address mismatch",
                    "evidence": f"From: {from_header} | Reply-To: {reply_to}",
                    "severity": "MEDIUM",
                    "explanation": "Reply-To address differs from sender domain. Verify recipient before sending sensitive data."
                })
            elif is_newsletter or same_org:
                # Standard practice in bulk publishing (e.g. newsletter dispatch email vs personal reply address)
                findings.append({
                    "rule_id": "RULE-001-INFO",
                    "finding": "Author Reply-To configured",
                    "evidence": f"From: {from_header} | Reply-To: {reply_to}",
                    "severity": "LOW",
                    "explanation": "Author or support direct reply address configured for subscriber convenience."
                })

    # 2. Return-Path Mismatch
    return_path = headers.get("return-path", "")
    if return_path and from_header:
        f_email = extract_email(from_header)
        rp_email = extract_email(return_path)
        if f_email and rp_email and f_email != rp_email:
            f_dom = get_base_domain(f_email)
            rp_dom = get_base_domain(rp_email)
            same_rp_org = (f_dom == rp_dom) and bool(f_dom)
            auth_ok = auth_alignment and auth_alignment.get("effective_dmarc") in ["PASS", "PASS (Delegated ESP)"]

            if not same_rp_org and not is_newsletter and not auth_ok:
                findings.append({
                    "rule_id": "RULE-002",
                    "finding": "Return-Path mismatch",
                    "evidence": f"From: {from_header} | Return-Path: {return_path}",
                    "severity": "MEDIUM",
                    "explanation": "Return-Path differs from the From address."
                })
            else:
                findings.append({
                    "rule_id": "RULE-002-INFO",
                    "finding": "ESP Bulk Return-Path routing",
                    "evidence": f"From: {from_header} | Return-Path: {return_path}",
                    "severity": "LOW",
                    "explanation": "Standard bounce handling mailbox routed via authorized email delivery provider."
                })

    # Check authentication status
    auth_ok = False
    if auth_alignment:
        auth_ok = auth_alignment.get("effective_dmarc") in ["PASS", "PASS (Delegated ESP)"]
    if not auth_ok:
        auth_res = str(headers.get("authentication-results", "")).lower()
        if "dmarc=pass" in auth_res or ("spf=pass" in auth_res and "dkim=pass" in auth_res):
            auth_ok = True

    subject_text = str(headers.get("subject", "")).lower()
    full_text = f"{subject_text} {body}".lower()

    # 3. Urgency language & Extortion Scareware
    urgency_keywords = [
        "urgent", "immediate action required", "account suspension", "verify your account",
        "overdue", "final notice", "final warning", "account locked", "account blocked",
        "account has been locked", "account has been blocked", "action required",
        "will be deleted", "will be removed today", "backup halted", "storage full",
        "space full", "payment failed", "payment declined", "reschedule",
        "delivery status notification", "schedule confirmation", "claim your", "2nd attempt"
    ]
    for kw in urgency_keywords:
        if kw in full_text:
            is_suspension = any(s in full_text for s in ["suspension", "verify your account", "locked", "blocked", "deleted"])
            findings.append({
                "rule_id": "RULE-007",
                "finding": "Urgency / Threat language detected",
                "evidence": f"Keyword found: '{kw}'",
                "severity": "HIGH" if (not auth_ok and is_suspension) else ("MEDIUM" if not auth_ok else "LOW"),
                "explanation": "Subject or body contains language intended to create urgency, panic, or accelerated victim response."
            })
            break # Only fire once

    # 4. Credential & Billing Update requests
    cred_keywords = [
        "password", "login", "credentials", "click here to verify", "update your billing",
        "update your payment", "payment failed", "payment declined", "update your walmart",
        "renew your subscription", "confirm the payment", "verify your login"
    ]
    for kw in cred_keywords:
        if kw in full_text:
            findings.append({
                "rule_id": "RULE-006",
                "finding": "Credential / Payment Action request",
                "evidence": f"Keyword found: '{kw}'",
                "severity": "MEDIUM" if not auth_ok else "LOW",
                "explanation": "Message references account login, credential verification, or urgent billing update."
            })
            break

    # 4b. Cloud Storage Deletion / Extortion Scareware
    extortion_patterns = [
        r"photos (?:and|&) videos will be deleted",
        r"cloud (?:space|storage) (?:is )?full",
        r"backup halted",
        r"cloud files will be (?:removed|deleted)",
        r"your storage is (?:almost )?full",
        r"all storage used"
    ]
    is_official_cloud = any(f"@{dom}" in from_header.lower() for dom in ["google.com", "microsoft.com", "apple.com", "icloud.com", "dropbox.com"])
    if not is_official_cloud:
        for ep in extortion_patterns:
            if re.search(ep, full_text):
                findings.append({
                    "rule_id": "RULE-020",
                    "finding": "Cloud Storage Extortion / Scareware Lure",
                    "evidence": f"Scareware pattern matched: '{ep}'",
                    "severity": "HIGH",
                    "explanation": "Email exploits artificial urgency regarding data loss or photo deletion to solicit payment or credentials."
                })
                break

    # 4c. Deceptive Brand Subdomain / Combo-Squatting in Sender Domain
    from core.domain_reputation import OFFICIAL_BRAND_DOMAINS
    raw_from_dom = extract_email(from_header).split("@")[-1].lower() if "@" in extract_email(from_header) else ""
    if not auth_ok and raw_from_dom:
        for mb, legit_doms in OFFICIAL_BRAND_DOMAINS.items():
            if mb in raw_from_dom and not any(raw_from_dom == ld or raw_from_dom.endswith("." + ld) for ld in legit_doms):
                findings.append({
                    "rule_id": "RULE-021",
                    "finding": f"Deceptive Brand Subdomain Spoofing ({mb.upper()})",
                    "evidence": f"Sender domain '{raw_from_dom}' inserts brand '{mb}' into unauthorized host",
                    "severity": "HIGH",
                    "explanation": "Adversary embeds a trusted commercial brand name as a deceptive subdomain or prefix on an unrelated server."
                })
                break

    # 5. Attachment metadata anomaly
    attachments = parsed_email.get("attachments", [])
    suspicious_exts = [".exe", ".scr", ".vbs", ".js", ".bat", ".iso", ".img", ".zip"]
    for att in attachments:
        filename = att.get("filename", "").lower()
        if any(filename.endswith(ext) for ext in suspicious_exts):
            findings.append({
                "rule_id": "RULE-008",
                "finding": "Suspicious attachment extension",
                "evidence": f"File: {filename}",
                "severity": "HIGH",
                "explanation": "Attachment has a potentially dangerous extension."
            })

    # 6. Domain Reputation Anomalies
    if domain_rep:
        if getattr(domain_rep, "is_nrd", False):
            findings.append({
                "rule_id": "RULE-009",
                "finding": "Newly Registered Domain (NRD)",
                "evidence": f"Domain '{domain_rep.domain}' registered {domain_rep.domain_age_days} days ago",
                "severity": "HIGH",
                "explanation": "Newly created domains have high statistical correlation with cyber threats."
            })
        if not getattr(domain_rep, "has_mx_record", True):
            findings.append({
                "rule_id": "RULE-010",
                "finding": "Missing DNS / MX Records",
                "evidence": f"Domain '{domain_rep.domain}' lacks valid DNS records",
                "severity": "HIGH",
                "explanation": "Sender domain cannot legitimately receive mail; probable spoofing."
            })
        if getattr(domain_rep, "risk_level", "LOW") == "HIGH" and not getattr(domain_rep, "is_nrd", False):
            findings.append({
                "rule_id": "RULE-011",
                "finding": "Brand Impersonation / Deceptive Domain",
                "evidence": f"Domain '{domain_rep.domain}' exhibits brand impersonation indicators",
                "severity": "HIGH",
                "explanation": "Domain attempts to mimic a legitimate institutional or financial brand."
            })

    # 7. URL / Link Threat Intelligence
    if url_analyses:
        for u in url_analyses:
            risk = getattr(u, "risk_level", "LOW")
            cat = getattr(u, "threat_category", "Unknown")
            defanged = getattr(u, "defanged_url", getattr(u, "url", "Unknown"))
            impact = getattr(u, "potential_impact", "")
            
            if risk == "CRITICAL":
                findings.append({
                    "rule_id": "RULE-012",
                    "finding": f"Critical Malicious Link ({cat})",
                    "evidence": f"URL: {defanged} | Threat: {cat} | Potential Impact: {impact[:90]}...",
                    "severity": "HIGH",
                    "explanation": "Embedded hyperlink links to a weaponized malware dropper or counterfeit credential harvesting portal."
                })
            elif risk == "HIGH":
                findings.append({
                    "rule_id": "RULE-013",
                    "finding": f"High-Risk Phishing Link ({cat})",
                    "evidence": f"URL: {defanged} | Threat: {cat} | Potential Impact: {impact[:90]}...",
                    "severity": "HIGH",
                    "explanation": "Embedded hyperlink matches known phishing lures, typosquatting patterns, or raw IP hosts."
                })

    # 8. Cryptographic DMARC Alignment Bypass
    if auth_alignment:
        eff_dmarc = auth_alignment.get("effective_dmarc", "")
        if "Alignment Bypass" in eff_dmarc or auth_alignment.get("threat_detected"):
            findings.append({
                "rule_id": "RULE-014",
                "finding": "DMARC Alignment Failure / Domain Spoofing",
                "evidence": auth_alignment.get("dmarc_reason", "Header-From domain unaligned with SPF/DKIM"),
                "severity": "HIGH",
                "explanation": "Sender attempted SPF/DKIM bypass using third-party signing domain while faking visible Header-From."
            })

    # 9. Attachment Forensics (Double Extensions / Macros / Disk Images)
    if attachment_analyses:
        for att in attachment_analyses:
            r_level = att.get("risk_level", "LOW")
            fname = att.get("filename", "")
            flags = att.get("risk_flags", [])
            
            if att.get("is_double_ext"):
                findings.append({
                    "rule_id": "RULE-015",
                    "finding": f"Double Extension Payload: {fname}",
                    "evidence": f"Attachment: {fname} | SHA-256: {att.get('sha256')[:16]}...",
                    "severity": "HIGH",
                    "explanation": "Adversary masked an executable binary with a false document extension (e.g. .pdf.exe)."
                })
            elif r_level in ["CRITICAL", "HIGH"]:
                findings.append({
                    "rule_id": "RULE-015B",
                    "finding": f"Suspicious/Weaponized Attachment: {fname}",
                    "evidence": f"File: {fname} | Indicators: {'; '.join(flags)}",
                    "severity": "HIGH" if r_level == "CRITICAL" else "MEDIUM",
                    "explanation": "Attachment exhibits weaponized traits (executable headers, macros, or disk container abuse)."
                })

    # 10. Lookalike Domain & Homoglyph Impersonation
    if lookalike_analysis and lookalike_analysis.get("is_lookalike"):
        target_b = lookalike_analysis.get("impersonated_brand", "Established Brand")
        tech = lookalike_analysis.get("technique", "Typosquatting")
        findings.append({
            "rule_id": "RULE-016",
            "finding": f"Brand Impersonation / Lookalike Domain ({target_b})",
            "evidence": f"Domain: {lookalike_analysis.get('domain')} | Technique: {tech} | Reasons: {'; '.join(lookalike_analysis.get('reasons', []))}",
            "severity": "HIGH",
            "explanation": "Adversary registered a deceptive lookalike domain using homoglyphs, brand combos, or typosquatting."
        })

    # 11. Display-Name Spoofing & BEC Wire Fraud Lures
    if bec_telemetry:
        if bec_telemetry.get("is_display_name_spoof"):
            findings.append({
                "rule_id": "RULE-017",
                "finding": f"Display-Name Executive Spoofing ({bec_telemetry.get('display_name')})",
                "evidence": f"Display: '{bec_telemetry.get('display_name')}' | Actual: '{bec_telemetry.get('sender_email')}'",
                "severity": "HIGH",
                "explanation": "Executive persona name used on an unauthorized free webmail address to mislead recipient."
            })
        if bec_telemetry.get("is_financial_lure") and bec_telemetry.get("bec_risk_score", 0) >= 40:
            findings.append({
                "rule_id": "RULE-017B",
                "finding": f"BEC Wire Transfer / Financial Fraud Lure",
                "evidence": f"Flags: {'; '.join(bec_telemetry.get('flags', []))}",
                "severity": "HIGH",
                "explanation": "Email solicits urgent fund redirection, bank account alteration, or confidential invoice processing."
            })

    # 12. MTA Relay Transit Delays & Clock Manipulation
    if relay_transit and relay_transit.get("anomalies"):
        for anom in relay_transit.get("anomalies", []):
            is_negative = "Negative Delta" in anom
            findings.append({
                "rule_id": "RULE-018",
                "finding": "SMTP Relay Header Timestamp Anomaly",
                "evidence": anom,
                "severity": "HIGH" if is_negative else "MEDIUM",
                "explanation": "Negative hop delta detected — possible clock skew, timestamp inconsistency, or header anomaly; requires investigation."
            })

    # 13. Hyperlink Anchor Text Spoofing
    from core.indicators import extract_anchor_spoofs
    anchor_spoofs = extract_anchor_spoofs(parsed_email.get("body", ""))
    for sp in anchor_spoofs:
        findings.append({
            "rule_id": "RULE-019",
            "finding": f"Hyperlink Anchor Spoof ({sp.get('displayed_domain')})",
            "evidence": f"Displayed domain: '{sp.get('displayed_domain')}' | Actual destination: '{sp.get('actual_destination')[:55]}...'",
            "severity": "HIGH",
            "explanation": "Adversary masked an external target address using a false visible brand domain."
        })

    return findings

def calculate_hybrid_risk(
    rule_findings: List[Dict[str, str]],
    ml_prob: float,
    auth_alignment: Any = None
) -> tuple[str, List[str]]:
    risk_score = "LOW"
    reasons = []

    auth_ok = False
    if auth_alignment:
        auth_ok = auth_alignment.get("effective_dmarc") in ["PASS", "PASS (Delegated ESP)"]

    high_rules = sum(1 for f in rule_findings if f.get("severity") == "HIGH")
    medium_rules = sum(1 for f in rule_findings if f.get("severity") == "MEDIUM")

    if high_rules >= 1:
        risk_score = "HIGH"
    elif not auth_ok and (ml_prob > 0.85 or (medium_rules >= 3 and ml_prob > 0.6)):
        risk_score = "HIGH"
    elif not auth_ok and (ml_prob > 0.65 or medium_rules >= 2):
        risk_score = "SUSPICIOUS"
    elif auth_ok and high_rules == 0:
        # Authenticated email with no high-severity forensic violations
        risk_score = "LOW"
    elif ml_prob > 0.88 and medium_rules >= 2:
        risk_score = "SUSPICIOUS"

    if high_rules > 0:
        reasons.append(f"Critical forensic violations detected ({high_rules} High-Severity Finding{'s' if high_rules > 1 else ''}).")
    if medium_rules > 0 and (not auth_ok or high_rules > 0):
        reasons.append(f"Suspicious heuristic indicators detected ({medium_rules}).")
    if ml_prob > 0.85 and not auth_ok:
        reasons.append(f"ML probability indicates strong phishing signals ({ml_prob:.2f}).")
    elif ml_prob > 0.65 and not auth_ok:
        reasons.append(f"ML probability indicates moderate phishing signals ({ml_prob:.2f}).")

    if not reasons:
        reasons.append("No significant malicious indicators found.")

    return risk_score, reasons
