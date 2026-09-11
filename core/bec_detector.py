import re
from typing import Dict, Any, List, Optional, Tuple

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "protonmail.com",
    "proton.me", "zoho.com", "mail.com", "gmx.com", "yandex.com", "icloud.com"
}

VIP_TITLES = [
    r"\bceo\b", r"\bcfo\b", r"\bcoo\b", r"\bcto\b", r"\bciso\b",
    r"\bchief executive\b", r"\bchief financial\b", r"\bchief operating\b",
    r"\bmanaging director\b", r"\bpresident\b", r"\bvice president\b",
    r"\bvp\b", r"\bchairman\b", r"\bdirector\b", r"\bfounder\b",
    r"\bboard of directors\b", r"\bpayroll\b", r"\bhuman resources\b",
    r"\baccounting\b", r"\bfinance team\b", r"\bbilling department\b"
]

FINANCIAL_FRAUD_PATTERNS = [
    r"\bwire transfer\b",
    r"\bswift code\b",
    r"\brouting number\b",
    r"\bbank account (details|number|update|change)\b",
    r"\bchange (of|our) banking details\b",
    r"\bupdate banking\b",
    r"\bnew bank account\b",
    r"\bremit(tance)? (immediately|urgently|payment)\b",
    r"\bprocess (\$?[\d,]+|invoice|payment|transfer)\b",
    r"\bpayment (is )?overdue\b",
    r"\bpay the attached invoice\b",
    r"\bach (transfer|payment)\b"
]

CONFIDENTIALITY_SECRECY_PATTERNS = [
    r"\bkeep this (strictly )?confidential\b",
    r"\bi am in a meeting\b",
    r"\bcannot take calls\b",
    r"\bdo not call me\b",
    r"\bonly email me\b",
    r"\bdiscreet\b",
    r"\burge you not to discuss\b"
]

def parse_from_header(from_header: str) -> Tuple[str, str, str]:
    """
    Parses a From header into (display_name, email_address, domain).
    Example: '"John Doe, CEO" <john@gmail.com>' -> ('John Doe, CEO', 'john@gmail.com', 'gmail.com')
    """
    if not from_header:
        return "", "", ""
    
    match = re.search(r'^(.*?)\s*<([^>]+)>', from_header)
    if match:
        display_name = match.group(1).strip(' "\'')
        email_addr = match.group(2).strip().lower()
    else:
        display_name = ""
        email_addr = from_header.strip().lower()
        
    domain = email_addr.split('@')[-1] if '@' in email_addr else ""
    return display_name, email_addr, domain

def detect_bec_and_impersonation(headers: Dict[str, Any], body: str, attachments: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Deep forensic detection of Business Email Compromise (BEC),
    Display-Name Spoofing, Executive Impersonation, and Wire Fraud Lures.
    """
    from_header = ""
    reply_to = ""
    subject = ""
    for k, v in headers.items():
        k_low = k.lower()
        val_str = " ".join(v) if isinstance(v, list) else str(v)
        if k_low == "from":
            from_header = val_str
        elif k_low == "reply-to":
            reply_to = val_str
        elif k_low == "subject":
            subject = val_str

    display_name, sender_email, sender_domain = parse_from_header(from_header)
    _, reply_email, reply_domain = parse_from_header(reply_to)

    body_lower = (body or "").lower()
    subject_lower = (subject or "").lower()
    combined_text = f"{subject_lower} {body_lower}"

    bec_score = 0
    flags = []
    is_display_name_spoof = False
    is_executive_lure = False
    is_financial_lure = False
    is_freemail_sender = sender_domain in FREE_WEBMAIL_DOMAINS

    # 1. Executive / VIP Title in Display Name or Body
    for pattern in VIP_TITLES:
        if re.search(pattern, display_name.lower()):
            is_executive_lure = True
            flags.append(f"Executive/VIP leadership title identified in Display Name: '{display_name}'")
            bec_score += 35
            break
        elif re.search(pattern, combined_text):
            flags.append("Executive role/authority invoked in message text")
            bec_score += 15
            break

    # 2. Display Name Spoofing via Free Webmail
    if is_freemail_sender and (is_executive_lure or len(display_name.split()) >= 2):
        # Sending from a personal @gmail.com but display name claims to be CEO / Corporate persona
        is_display_name_spoof = True
        flags.append(f"🚨 Display-Name Spoofing: Corporate/Executive persona ('{display_name}') sending from public freemail service ('{sender_domain}')")
        bec_score += 35

    # 3. Financial / Wire Transfer Fraud Lures
    found_financial = []
    for pattern in FINANCIAL_FRAUD_PATTERNS:
        match = re.search(pattern, combined_text)
        if match:
            found_financial.append(match.group(0))
            bec_score += 20

    if found_financial:
        is_financial_lure = True
        unique_financial = list(set(found_financial))[:3]
        flags.append(f"Financial routing / wire transfer triggers: {', '.join(unique_financial)}")

    # 4. Secrecy & Meeting Lures ("I am in a meeting, do not call me")
    for pattern in CONFIDENTIALITY_SECRECY_PATTERNS:
        match = re.search(pattern, combined_text)
        if match:
            flags.append(f"Urgent secrecy/out-of-office diversion lure: '{match.group(0)}'")
            bec_score += 20
            break

    # 5. Reply-To Redirection Mismatch
    if reply_email and sender_email and reply_email != sender_email:
        flags.append(f"Reply-To diversion: Replies routed away from '{sender_email}' to '{reply_email}'")
        bec_score += 25

    # Cap score
    bec_score = min(bec_score, 100)

    # Multi-class verdict synthesis
    # Categories: BEC, Executive Impersonation, Malware Delivery, Credential Harvesting, Spam, Legitimate
    has_malware_att = False
    if attachments:
        has_malware_att = any(
            att.get("risk_level") in ["CRITICAL", "HIGH"] or att.get("is_dangerous_executable") or att.get("is_double_ext")
            for att in attachments
        )

    has_cred_lure = bool(re.search(r'\b(password|login|verify account|sign in|credentials)\b', combined_text))

    if has_malware_att:
        verdict = "Malware Delivery"
        confidence = 94
    elif bec_score >= 50 and is_financial_lure:
        verdict = "Business Email Compromise (BEC / Wire Fraud)"
        confidence = min(int(bec_score * 0.95 + 10), 99)
    elif bec_score >= 40 and is_executive_lure:
        verdict = "Executive Impersonation"
        confidence = min(int(bec_score * 0.9 + 10), 95)
    elif has_cred_lure and ("verify" in combined_text or "suspension" in combined_text or "urgent" in combined_text):
        verdict = "Credential Harvesting"
        confidence = 88
    elif bec_score >= 30:
        verdict = "Suspicious Financial / Authority Solicitation"
        confidence = 72
    else:
        verdict = "Standard / Legitimate"
        confidence = 85

    return {
        "verdict": verdict,
        "confidence_pct": confidence,
        "bec_risk_score": bec_score,
        "is_display_name_spoof": is_display_name_spoof,
        "is_executive_lure": is_executive_lure,
        "is_financial_lure": is_financial_lure,
        "display_name": display_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "flags": flags
    }
