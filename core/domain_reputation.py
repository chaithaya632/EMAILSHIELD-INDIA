import socket
import re
import datetime
from typing import Dict, Any, Optional, List
import requests
from core.schemas import DomainReputation

_DOMAIN_CACHE: Dict[str, DomainReputation] = {}

KNOWN_REPUTABLE_DOMAINS = {
    "google.com": {"age": 10000, "reg": "MarkMonitor", "created": "1997-09-15"},
    "gmail.com": {"age": 8000, "reg": "MarkMonitor", "created": "2004-03-31"},
    "microsoft.com": {"age": 12000, "reg": "Corporation Service Company", "created": "1991-05-02"},
    "outlook.com": {"age": 9000, "reg": "Corporation Service Company", "created": "1999-04-12"},
    "apple.com": {"age": 14000, "reg": "Corporation Service Company", "created": "1987-02-19"},
    "amazon.com": {"age": 11000, "reg": "MarkMonitor", "created": "1994-11-01"},
    "paypal.com": {"age": 10000, "reg": "MarkMonitor", "created": "1999-07-15"},
    "github.com": {"age": 6000, "reg": "MarkMonitor", "created": "2007-10-09"}
}

BRAND_TARGETS = [
    "paypal", "google", "microsoft", "apple", "netflix", "amazon",
    "sbi", "hdfc", "icici", "rbi", "income-tax", "chase", "wells-fargo"
]

def extract_domain(sender_str: str) -> str:
    """Extract domain from an email address or raw string."""
    if not sender_str:
        return "unknown.com"
    clean = sender_str.strip().lower()
    # Check for <user@domain.com>
    match = re.search(r'@([\w\.-]+)', clean)
    if match:
        return match.group(1).strip(">").strip()
    return clean

def get_domain_reputation(sender_or_domain: str) -> DomainReputation:
    """
    Analyzes domain reputation using DNS, ICANN RDAP (Registration Data Access Protocol),
    and typosquatting/brand impersonation heuristics.
    """
    domain = extract_domain(sender_or_domain)
    
    if domain in _DOMAIN_CACHE:
        return _DOMAIN_CACHE[domain]
        
    notes = []
    risk_level = "LOW"
    is_nrd = False
    has_mx = True
    resolved_ips = []
    registrar = "Unknown"
    creation_date = "Unknown"
    domain_age_days = None

    # Step 1: Check known trusted domains
    if domain in KNOWN_REPUTABLE_DOMAINS:
        info = KNOWN_REPUTABLE_DOMAINS[domain]
        rep = DomainReputation(
            domain=domain,
            registrar=info["reg"],
            creation_date=info["created"],
            domain_age_days=info["age"],
            is_nrd=False,
            has_mx_record=True,
            dns_resolved_ips=["Resolved Legitimate Provider"],
            risk_level="LOW",
            notes=["Established high-reputation domain."]
        )
        _DOMAIN_CACHE[domain] = rep
        return rep

    # Step 2: Check DNS Resolution
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        resolved_ips = ips[:3]
        notes.append(f"DNS A Record verified ({len(ips)} IP addresses).")
    except socket.gaierror:
        has_mx = False
        risk_level = "HIGH"
        notes.append("⚠️ Domain lacks valid DNS A/MX records (NXDOMAIN). High spoofing probability.")

    # Step 3: Brand Impersonation / Typosquatting Heuristics
    domain_parts = domain.split(".")
    base_name = domain_parts[0] if len(domain_parts) > 1 else domain
    
    for brand in BRAND_TARGETS:
        if brand in base_name and domain != f"{brand}.com" and domain != f"{brand}.in":
            risk_level = "HIGH"
            notes.append(f"🚨 Deceptive Brand Impersonation: Domain contains '{brand}' but is not official.")
            break

    # Step 4: Query ICANN RDAP for Domain Age & Registrar
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=2.5)
        if resp.status_code == 200:
            rdap_data = resp.json()
            
            # Find registrar
            for entity in rdap_data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles or "registrant" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if len(field) > 3 and field[0] == "fn":
                                registrar = str(field[3])
                                break
                if registrar != "Unknown":
                    break

            # Find creation date
            for event in rdap_data.get("events", []):
                action = event.get("eventAction", "").lower()
                if "registration" in action or "created" in action:
                    creation_date = event.get("eventDate", "")[:10]
                    try:
                        c_dt = datetime.datetime.strptime(creation_date, "%Y-%m-%d")
                        now_dt = datetime.datetime.utcnow()
                        age = (now_dt - c_dt).days
                        domain_age_days = max(0, age)
                        
                        if domain_age_days < 30:
                            is_nrd = True
                            risk_level = "HIGH"
                            notes.append(f"🚨 Newly Registered Domain (NRD): Registered only {domain_age_days} days ago!")
                        elif domain_age_days < 180:
                            if risk_level != "HIGH":
                                risk_level = "MEDIUM"
                            notes.append(f"⚠️ Young Domain: Registered {domain_age_days} days ago.")
                        else:
                            notes.append(f"Domain age: {domain_age_days} days ({domain_age_days//365} yrs).")
                    except Exception:
                        pass
                    break
        elif resp.status_code == 404:
            notes.append("RDAP returned 404: Domain may be unregistered, private, or suspended.")
    except Exception:
        notes.append("RDAP query timed out; evaluated via heuristic DNS reputation.")

    if not notes:
        notes.append("Standard domain profile.")

    rep = DomainReputation(
        domain=domain,
        registrar=registrar,
        creation_date=creation_date,
        domain_age_days=domain_age_days,
        is_nrd=is_nrd,
        has_mx_record=has_mx,
        dns_resolved_ips=resolved_ips,
        risk_level=risk_level,
        notes=notes
    )
    
    _DOMAIN_CACHE[domain] = rep
    return rep
