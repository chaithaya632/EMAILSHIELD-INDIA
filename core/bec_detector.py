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

HARD_WIRE_PATTERNS = [
    r"\bwire transfer\b",
    r"\bswift code\b",
    r"\brouting number\b",
    r"\bchange (of|our|the) banking details\b",
    r"\bupdate banking (details|information)\b",
    r"\bnew bank account\b",
    r"\bremit(tance)? (immediately|urgently)\b",
    r"\bach transfer\b"
]

TRANSACTIONAL_PATTERNS = [
    r"\bprocess (\$?[\d,]+|invoice|payment|transfer)\b",
    r"\bpayment (is )?overdue\b",
    r"\bpay the attached invoice\b",
    r"\bbank account (details|number|update|change)\b"
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

KNOWN_SPOOFED_ENTITIES = {
    "dhl": ["dhl.com", "dhl.de"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com", "usps.gov"],
    "singpost": ["singpost.com"],
    "singapore-post": ["singpost.com"],
    "singapore post": ["singpost.com"],
    "starhub": ["starhub.com"],
    "singtel": ["singtel.com"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com"],
    "office365": ["microsoft.com", "office.com"],
    "google": ["google.com", "google.co.in", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "sbi": ["sbi.co.in", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net"],
    "icici": ["icicibank.com"],
    "dbs": ["dbs.com", "dbs.com.sg"],
    "uob": ["uob.com.sg", "uobgroup.com"],
    "mcafee": ["mcafee.com"],
    "norton": ["norton.com"],
    "walmart": ["walmart.com"],
    "lowes": ["lowes.com"],
    "swiggy": ["swiggy.in"],
    "united healthcare": ["uhc.com", "unitedhealthgroup.com"],
    "united-healthcare": ["uhc.com", "unitedhealthgroup.com"]
}

GENERIC_SERVICE_LURES = [
    "cloud storage", "cloud backup", "cloud full", "cloud capacity",
    "payment-declined", "payment declined", "payment-failed", "payment failed",
    "delivery status", "parcel delivery", "emergency notice", "account security",
    "verification", "final notice", "storage notice", "daily-health-alert"
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

def detect_bec_and_impersonation(
    headers: Dict[str, Any],
    body: str,
    attachments: List[Dict[str, Any]] = None,
    auth_alignment: Any = None
) -> Dict[str, Any]:
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

    # Determine cryptographic authentication status
    auth_ok = False
    if auth_alignment:
        auth_ok = auth_alignment.get("effective_dmarc") in ["PASS", "PASS (Delegated ESP)"]
    if not auth_ok:
        auth_res = str(headers.get("authentication-results", "")).lower()
        if "dmarc=pass" in auth_res or ("spf=pass" in auth_res and "dkim=pass" in auth_res):
            auth_ok = True

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
        elif re.search(pattern, combined_text) and not auth_ok:
            flags.append("Executive role/authority invoked in message text")
            bec_score += 15
            break

    # Check if bulk newsletter
    is_newsletter = bool(
        headers.get("list-unsubscribe") or
        headers.get("list-id") or
        str(headers.get("precedence", "")).lower() == "bulk" or
        headers.get("feedback-id")
    )

    # 2. Display Name Spoofing (Freemail, Brand Mimicry & Service Lures)
    brand_keywords = [
        "support", "security", "billing", "helpdesk", "administrator", "service",
        "official", "verification", "bank", "portal", "compliance", "legal", "payroll",
        "customs", "delivery", "shipping", "dispatch", "express", "order"
    ]
    disp_lower = display_name.lower().strip()
    has_dept_lure = any(re.search(rf"\b{bk}\b", disp_lower) for bk in brand_keywords)

    matched_brand = None
    for brand, legit_domains in KNOWN_SPOOFED_ENTITIES.items():
        if brand in disp_lower:
            # If the sender domain matches official domains, or brand is cleanly in sender_domain and authenticated
            brand_clean = brand.replace(" ", "").replace("-", "")
            domain_clean = sender_domain.replace("-", "").replace(".", "")
            is_legit = any(sender_domain == ld or sender_domain.endswith("." + ld) for ld in legit_domains) or (brand_clean in domain_clean and auth_ok)
            if not is_legit:
                matched_brand = brand
                break

    matched_service_lure = None
    if not matched_brand and not is_newsletter:
        for lure in GENERIC_SERVICE_LURES:
            if lure in disp_lower:
                matched_service_lure = lure
                break

    if not is_newsletter and is_freemail_sender and (is_executive_lure or has_dept_lure):
        # Sending from a personal @gmail.com but display name claims to be CEO / Corporate persona
        is_display_name_spoof = True
        flags.append(f"🚨 Display-Name Spoofing: Corporate/Executive persona ('{display_name}') sending from public freemail service ('{sender_domain}')")
        bec_score += 35
    elif matched_brand:
        # Claims to be a major institution (DHL, SingPost, StarHub, Google, Walmart, McAfee, etc.) but domain does not match
        is_display_name_spoof = True
        flags.append(f"🚨 Brand Display-Name Spoofing: Visible sender claims '{display_name}' ({matched_brand.upper()}), but originated from unassociated domain '{sender_domain}'")
        bec_score += 45
    elif matched_service_lure and not auth_ok:
        # Deceptive system or security department lure on unauthenticated domain
        is_display_name_spoof = True
        flags.append(f"🚨 Deceptive Sender Persona: Display name uses service lure '{display_name}' on unaligned/untrusted domain '{sender_domain}'")
        bec_score += 35

    # 3. Financial / Wire Transfer Fraud Lures
    found_hard_wire = []
    for pattern in HARD_WIRE_PATTERNS:
        match = re.search(pattern, combined_text)
        if match:
            found_hard_wire.append(match.group(0))

    found_transactional = []
    for pattern in TRANSACTIONAL_PATTERNS:
        match = re.search(pattern, combined_text)
        if match:
            found_transactional.append(match.group(0))

    # Real financial lure requires either hard wire patterns, OR transactional patterns on unauthenticated/spoofed senders
    if found_hard_wire:
        is_financial_lure = True
        bec_score += 30
        flags.append(f"Urgent wire transfer / account modification triggers: {', '.join(list(set(found_hard_wire))[:3])}")
    elif found_transactional and (not auth_ok or is_display_name_spoof):
        is_financial_lure = True
        bec_score += 20
        flags.append(f"Unverified financial/payment routing triggers: {', '.join(list(set(found_transactional))[:3])}")

    # 4. Secrecy & Meeting Lures ("I am in a meeting, do not call me")
    for pattern in CONFIDENTIALITY_SECRECY_PATTERNS:
        match = re.search(pattern, combined_text)
        if match:
            flags.append(f"Urgent secrecy/out-of-office diversion lure: '{match.group(0)}'")
            bec_score += 20
            break

    def get_base_domain(e_str: str) -> str:
        if "@" not in e_str:
            return ""
        parts = e_str.split("@")[-1].lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else parts[0]

    same_org = (get_base_domain(sender_email) == get_base_domain(reply_email)) and bool(sender_email)

    # 5. Reply-To Redirection Mismatch (Flag only if cross-domain and not newsletter)
    if reply_email and sender_email and reply_email != sender_email and not same_org and not is_newsletter:
        flags.append(f"Reply-To diversion: Replies routed away from '{sender_email}' to '{reply_email}'")
        bec_score += 25

    # Cap score
    bec_score = min(bec_score, 100)

    # Multi-class verdict synthesis
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
    elif (bec_score >= 50 and is_financial_lure) or (is_financial_lure and is_display_name_spoof):
        verdict = "Business Email Compromise (BEC / Wire Fraud)"
        confidence = min(int(bec_score * 0.95 + 10), 99)
    elif is_display_name_spoof and is_executive_lure:
        verdict = "Executive Impersonation"
        confidence = min(int(bec_score * 0.9 + 10), 95)
    elif is_display_name_spoof:
        verdict = "Brand / Service Impersonation (Display Spoof)"
        confidence = min(int(bec_score * 0.9 + 10), 95)
    elif has_cred_lure and ("verify" in combined_text or "suspension" in combined_text or "urgent" in combined_text) and not is_newsletter:
        if auth_ok:
            verdict = "Security Alert / Notification (Authenticated)"
            confidence = 88
        else:
            verdict = "Credential Harvesting"
            confidence = 88
    elif bec_score >= 40 and is_financial_lure and not auth_ok:
        verdict = "Suspicious Financial / Authority Solicitation"
        confidence = 72
    elif is_newsletter and not is_display_name_spoof and not is_financial_lure and auth_ok:
        verdict = "Standard / Legitimate (Newsletter / Subscription)"
        confidence = 95
    elif auth_ok and (found_transactional or "inr" in combined_text or "statement" in combined_text or "debited" in combined_text):
        verdict = "Standard / Legitimate (Transactional / Billing)"
        confidence = 90
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
