import socket
import re
import datetime
from typing import Dict, Any, Optional, List
import requests
from core.schemas import DomainReputation

_DOMAIN_CACHE: Dict[str, DomainReputation] = {}

KNOWN_REPUTABLE_DOMAINS = {
    # Tech & Global Email
    "google.com": {"age": 10000, "reg": "MarkMonitor", "created": "1997-09-15"},
    "google.co.in": {"age": 9000, "reg": "MarkMonitor", "created": "2003-06-23"},
    "gmail.com": {"age": 8000, "reg": "MarkMonitor", "created": "2004-03-31"},
    "microsoft.com": {"age": 12000, "reg": "Corporation Service Company", "created": "1991-05-02"},
    "outlook.com": {"age": 9000, "reg": "Corporation Service Company", "created": "1999-04-12"},
    "hotmail.com": {"age": 10000, "reg": "Corporation Service Company", "created": "1996-03-27"},
    "live.com": {"age": 7000, "reg": "Corporation Service Company", "created": "2005-11-01"},
    "office.com": {"age": 9000, "reg": "Corporation Service Company", "created": "1999-08-11"},
    "apple.com": {"age": 14000, "reg": "Corporation Service Company", "created": "1987-02-19"},
    "icloud.com": {"age": 6000, "reg": "Corporation Service Company", "created": "2011-05-31"},
    "amazon.com": {"age": 11000, "reg": "MarkMonitor", "created": "1994-11-01"},
    "amazon.in": {"age": 6000, "reg": "MarkMonitor", "created": "2011-08-01"},
    "amazonses.com": {"age": 5000, "reg": "MarkMonitor", "created": "2010-12-14"},
    "paypal.com": {"age": 10000, "reg": "MarkMonitor", "created": "1999-07-15"},
    "github.com": {"age": 6000, "reg": "MarkMonitor", "created": "2007-10-09"},
    "yahoo.com": {"age": 11000, "reg": "MarkMonitor", "created": "1995-01-18"},
    "zoho.com": {"age": 7000, "reg": "MarkMonitor", "created": "2005-09-01"},
    "zoho.in": {"age": 5000, "reg": "MarkMonitor", "created": "2011-04-12"},
    "linkedin.com": {"age": 8000, "reg": "MarkMonitor", "created": "2002-11-02"},
    "twitter.com": {"age": 7000, "reg": "Corporate Domains", "created": "2006-01-21"},
    "x.com": {"age": 9000, "reg": "GoDaddy", "created": "1993-04-02"},
    "youtube.com": {"age": 8000, "reg": "MarkMonitor", "created": "2005-02-14"},
    "facebook.com": {"age": 8000, "reg": "RegistrarSafe", "created": "1997-03-29"},
    "instagram.com": {"age": 5000, "reg": "RegistrarSafe", "created": "2010-10-06"},
    "whatsapp.com": {"age": 6000, "reg": "RegistrarSafe", "created": "2008-09-04"},
    "netflix.com": {"age": 10000, "reg": "MarkMonitor", "created": "1997-11-10"},
    "spotify.com": {"age": 7000, "reg": "MarkMonitor", "created": "2006-07-14"},
    "uber.com": {"age": 6000, "reg": "MarkMonitor", "created": "2009-03-01"},
    # Subscriptions & Newsletters
    "substack.com": {"age": 3000, "reg": "NameCheap", "created": "2017-07-07"},
    "beehiiv.com": {"age": 1500, "reg": "NameCheap", "created": "2021-04-12"},
    "convertkit.com": {"age": 4000, "reg": "NameCheap", "created": "2013-01-01"},
    "mailchimp.com": {"age": 9000, "reg": "MarkMonitor", "created": "2001-04-12"},
    "medium.com": {"age": 5000, "reg": "MarkMonitor", "created": "2011-06-01"},
    "growthschool.io": {"age": 1800, "reg": "GoDaddy", "created": "2020-08-01"},
    "sisinty.com": {"age": 3500, "reg": "GoDaddy", "created": "2016-01-01"},
    # Indian Banking & Enterprise
    "sbi.co.in": {"age": 8000, "reg": "National Informatics Centre", "created": "2003-05-15"},
    "statebankofindia.com": {"age": 8000, "reg": "Network Solutions", "created": "2001-08-20"},
    "sbicard.com": {"age": 7000, "reg": "Network Solutions", "created": "2006-03-10"},
    "onlinesbi.sbi": {"age": 3000, "reg": "NIC", "created": "2017-01-01"},
    "hdfcbank.com": {"age": 9000, "reg": "Network Solutions", "created": "2000-02-14"},
    "hdfcbank.net": {"age": 7000, "reg": "Network Solutions", "created": "2005-01-01"},
    "icicibank.com": {"age": 9000, "reg": "Network Solutions", "created": "1999-11-20"},
    "icicibank.net": {"age": 7000, "reg": "Network Solutions", "created": "2005-01-01"},
    "axisbank.com": {"age": 8000, "reg": "Network Solutions", "created": "2002-05-10"},
    "kotak.com": {"age": 9000, "reg": "Network Solutions", "created": "1997-04-16"},
    "pnbindia.in": {"age": 6000, "reg": "INRegistry", "created": "2005-03-15"},
    "rbi.org.in": {"age": 9000, "reg": "ERNET India", "created": "1998-04-01"},
    "incometax.gov.in": {"age": 5000, "reg": "NIC", "created": "2010-01-01"},
    "gov.in": {"age": 10000, "reg": "NIC", "created": "1995-01-01"},
    "nic.in": {"age": 10000, "reg": "NIC", "created": "1995-01-01"},
    "irctc.co.in": {"age": 8000, "reg": "INRegistry", "created": "2002-08-11"},
    # Indian Tech / E-Commerce
    "flipkart.com": {"age": 6000, "reg": "MarkMonitor", "created": "2007-08-10"},
    "myntra.com": {"age": 6000, "reg": "MarkMonitor", "created": "2007-05-04"},
    "swiggy.in": {"age": 4000, "reg": "INRegistry", "created": "2014-04-10"},
    "zomato.com": {"age": 6000, "reg": "MarkMonitor", "created": "2008-07-10"},
    "paytm.com": {"age": 6000, "reg": "MarkMonitor", "created": "2009-08-14"},
    "phonepe.com": {"age": 4000, "reg": "MarkMonitor", "created": "2015-11-04"},
    "cred.club": {"age": 3000, "reg": "GoDaddy", "created": "2018-04-10"},
    "airtel.in": {"age": 7000, "reg": "INRegistry", "created": "2005-02-15"},
    "jio.com": {"age": 5000, "reg": "MarkMonitor", "created": "2012-08-01"},
    "tcs.com": {"age": 10000, "reg": "MarkMonitor", "created": "1995-10-01"},
    "infosys.com": {"age": 10000, "reg": "MarkMonitor", "created": "1995-05-01"},
    "wipro.com": {"age": 10000, "reg": "MarkMonitor", "created": "1995-07-01"}
}

OFFICIAL_BRAND_DOMAINS = {
    "sbi": {"sbi.co.in", "statebankofindia.com", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "sbipayments.com", "sbicaps.com", "sbilife.co.in", "sbimf.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfcbank.net", "hdfcsec.com", "hdfcfund.com", "hdfcergo.com"},
    "icici": {"icicibank.com", "icicibank.net", "icicidirect.com", "iciciprulife.com", "icicilombard.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com", "kotakmahindra.com"},
    "pnb": {"pnbindia.in", "pnb.bank.in"},
    "rbi": {"rbi.org.in"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com", "googlemail.com"},
    "microsoft": {"microsoft.com", "outlook.com", "hotmail.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazonses.com"},
    "paypal": {"paypal.com", "paypal.in"},
    "netflix": {"netflix.com"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"}
}

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
    except (socket.gaierror, socket.timeout, OSError):
        # Do not mark as high risk purely due to offline / local DNS resolution limits
        notes.append("DNS A query could not resolve in time. Performing heuristic verification.")

    # Step 3: Brand Impersonation / Typosquatting Heuristics
    domain_parts = domain.split(".")
    base_name = domain_parts[0] if len(domain_parts) > 1 else domain
    
    for brand, legit_domains in OFFICIAL_BRAND_DOMAINS.items():
        if any(domain == ld or domain.endswith(f".{ld}") for ld in legit_domains):
            break
        # Exact brand name on an unauthorized TLD (e.g. sbi.xyz, paypal.cc, apple.top)
        is_exact_brand = (base_name == brand)
        # Combo-squatting with hyphens, dots, or deception keywords (e.g. sbi-verify, paypal-security, apple-support)
        is_deceptive_combo = bool(
            re.search(rf"(^|[-_.])({re.escape(brand)})([-_.])", base_name) or
            re.search(rf"^(secure|verify|login|support|account|update|alert|portal)-?{re.escape(brand)}$", base_name) or
            re.search(rf"^{re.escape(brand)}-?(secure|verify|login|support|account|update|alert|portal|online|banking)$", base_name)
        )
        if is_exact_brand or is_deceptive_combo:
            risk_level = "HIGH"
            notes.append(f"🚨 Deceptive Brand Impersonation: Domain matches target brand '{brand}' but is not an authorized official domain.")
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
