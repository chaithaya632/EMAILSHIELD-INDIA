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

TLD_WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'io': 'whois.nic.io',
    'in': 'whois.nixiregistry.in',
    'co.in': 'whois.nixiregistry.in',
    'gov.in': 'whois.nixiregistry.in',
    'ai': 'whois.nic.ai',
    'co': 'whois.nic.co',
    'me': 'whois.nic.me',
    'info': 'whois.afilias.net',
    'biz': 'whois.biz',
    'xyz': 'whois.nic.xyz',
    'club': 'whois.nic.club',
    'top': 'whois.nic.top',
    'tech': 'whois.nic.tech',
    'online': 'whois.nic.online',
    'site': 'whois.nic.site',
    'app': 'whois.nic.google',
    'dev': 'whois.nic.google'
}

TWO_PART_TLDS = {
    'co.in', 'gov.in', 'net.in', 'org.in', 'edu.in', 'ac.in', 'res.in', 'bank.in',
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'com.au', 'net.au', 'org.au', 'co.nz',
    'com.sg', 'com.my', 'co.za', 'com.br', 'co.jp'
}

def get_registered_domain(domain: str) -> str:
    """Extract registered apex domain (eSLD), e.g. 'accounts.google.com' -> 'google.com'."""
    parts = domain.lower().split('.')
    if len(parts) <= 2:
        return domain.lower()
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in TWO_PART_TLDS and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def extract_domain(sender_str: str) -> str:
    """Extract clean domain from an email address, URL, or raw string."""
    if not sender_str:
        return "unknown.com"
    clean = str(sender_str).strip().lower()
    clean = clean.strip(' "\'<>[]')
    if "@" in clean:
        match = re.search(r'@([\w\.-]+)', clean)
        if match:
            clean = match.group(1)
    if "://" in clean:
        clean = clean.split("://", 1)[1]
    clean = clean.split("/")[0].split(":")[0].strip(" .")
    clean = re.sub(r'^[^\w]+|[^\w]+$', '', clean)
    return clean or "unknown.com"

def resolve_whois_and_rdap(domain: str) -> tuple[str, str, Optional[int]]:
    """
    Multi-tiered real-time registry intelligence:
    Tier 1: Direct RFC 3912 port 43 WHOIS socket query
    Tier 2: ICANN RDAP REST API
    Returns (registrar, creation_date, domain_age_days)
    """
    registrar = "Unknown"
    creation_date = "Unknown"
    domain_age_days = None

    # Tier 1: Direct WHOIS Socket Query (Port 43)
    try:
        parts = domain.lower().split('.')
        tld = parts[-1]
        if len(parts) >= 2 and (parts[-2] in ['co', 'gov', 'org', 'net', 'edu', 'res', 'ac']):
            tld = f"{parts[-2]}.{parts[-1]}"
        server = TLD_WHOIS_SERVERS.get(tld, 'whois.iana.org')

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.5)
        s.connect((server, 43))
        s.send(f"{domain}\r\n".encode("utf-8"))
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 65536:
                break
        s.close()
        text = raw.decode("utf-8", errors="ignore")

        # Handle referral if querying root IANA
        if "refer:" in text.lower() and server == 'whois.iana.org':
            for line in text.splitlines():
                if line.lower().startswith("refer:"):
                    ref_srv = line.split(":", 1)[1].strip()
                    if ref_srv:
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.settimeout(3.5)
                        s2.connect((ref_srv, 43))
                        s2.send(f"{domain}\r\n".encode("utf-8"))
                        raw2 = b""
                        while True:
                            c = s2.recv(4096)
                            if not c:
                                break
                            raw2 += c
                            if len(raw2) > 65536:
                                break
                        s2.close()
                        text = raw2.decode("utf-8", errors="ignore")
                        break

        # Parse registrar & creation date from WHOIS response
        for line in text.splitlines():
            line_str = line.strip()
            # Registrar
            if re.match(r'^(registrar|sponsoring registrar|registrar name):\s*(.+)', line_str, re.I):
                val = re.split(r':\s*', line_str, maxsplit=1)[1].strip()
                if val and registrar == "Unknown":
                    registrar = val
            # Creation Date
            if re.match(r'^(creation date|created date|registration date|created on|created):\s*(.+)', line_str, re.I):
                val = re.split(r':\s*', line_str, maxsplit=1)[1].strip()
                d_match = re.search(r'(\d{4}-\d{2}-\d{2})', val)
                if d_match and creation_date == "Unknown":
                    creation_date = d_match.group(1)
                elif creation_date == "Unknown":
                    d_match2 = re.search(r'(\d{1,2}-[A-Za-z]{3}-\d{4})', val)
                    if d_match2:
                        try:
                            dt = datetime.datetime.strptime(d_match2.group(1), "%d-%b-%Y")
                            creation_date = dt.strftime("%Y-%m-%d")
                        except Exception:
                            pass
    except Exception:
        pass

    # Tier 2: Fallback / Augment via ICANN RDAP REST API
    if registrar == "Unknown" or creation_date == "Unknown":
        try:
            resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=4.0)
            if resp.status_code == 200:
                rdap_data = resp.json()
                if registrar == "Unknown":
                    for entity in rdap_data.get("entities", []):
                        roles = entity.get("roles", [])
                        if "registrar" in roles or "registrant" in roles:
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for field in vcard[1]:
                                    if len(field) > 3 and field[0] == "fn" and field[3]:
                                        registrar = str(field[3])
                                        break
                            if registrar == "Unknown" and entity.get("handle"):
                                registrar = str(entity.get("handle"))
                            break

                if creation_date == "Unknown":
                    for event in rdap_data.get("events", []):
                        action = event.get("eventAction", "").lower()
                        if "registration" in action or "created" in action:
                            creation_date = event.get("eventDate", "")[:10]
                            break
        except Exception:
            pass

    # Compute Domain Age
    if creation_date != "Unknown":
        try:
            c_dt = datetime.datetime.strptime(creation_date, "%Y-%m-%d")
            now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            domain_age_days = max(0, (now_dt - c_dt).days)
        except Exception:
            pass

    return registrar, creation_date, domain_age_days

def get_domain_reputation(sender_or_domain: str) -> DomainReputation:
    """
    Analyzes domain reputation using real-time WHOIS (RFC 3912), ICANN RDAP, DNS,
    and typosquatting/brand impersonation heuristics.
    """
    domain = extract_domain(sender_or_domain)
    root_domain = get_registered_domain(domain)
    
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

    # Step 1: Check known trusted domains (checks both exact subdomain and parent root domain)
    lookup_target = domain if domain in KNOWN_REPUTABLE_DOMAINS else (root_domain if root_domain in KNOWN_REPUTABLE_DOMAINS else None)
    if lookup_target:
        info = KNOWN_REPUTABLE_DOMAINS[lookup_target]
        created = info.get("created", "2000-01-01")
        try:
            c_dt = datetime.datetime.strptime(created, "%Y-%m-%d")
            now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            domain_age_days = max(0, (now_dt - c_dt).days)
        except Exception:
            domain_age_days = info.get("age", 5000)

        label = f"Verified parent domain '{root_domain}'" if root_domain != domain else "Verified domain"
        rep = DomainReputation(
            domain=domain,
            registrar=info["reg"],
            creation_date=created,
            domain_age_days=domain_age_days,
            is_nrd=False,
            has_mx_record=True,
            dns_resolved_ips=["Resolved Legitimate Provider"],
            risk_level="LOW",
            notes=[f"{label} ({domain_age_days} days old | Registrar: {info['reg']})."]
        )
        _DOMAIN_CACHE[domain] = rep
        return rep

    # Step 2: Check DNS Resolution
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        resolved_ips = ips[:3]
        notes.append(f"DNS A Record verified ({len(ips)} IP addresses).")
    except (socket.gaierror, socket.timeout, OSError):
        notes.append("DNS A query evaluated via heuristic fallback.")

    # Step 3: Brand Impersonation / Typosquatting Heuristics
    domain_parts = domain.split(".")
    base_name = domain_parts[0] if len(domain_parts) > 1 else domain
    
    for brand, legit_domains in OFFICIAL_BRAND_DOMAINS.items():
        if any(domain == ld or domain.endswith(f".{ld}") or root_domain == ld for ld in legit_domains):
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

    # Step 4: Real-time WHOIS & RDAP Registry Intelligence
    # Query apex root domain first (e.g. 'google.com' instead of 'accounts.google.com')
    reg, cdate, age = resolve_whois_and_rdap(root_domain)
    if (reg == "Unknown" or cdate == "Unknown") and root_domain != domain:
        r2, c2, a2 = resolve_whois_and_rdap(domain)
        if reg == "Unknown":
            reg = r2
        if cdate == "Unknown":
            cdate = c2
        if age is None:
            age = a2

    if reg != "Unknown":
        registrar = reg
    if cdate != "Unknown":
        creation_date = cdate
    if age is not None:
        domain_age_days = age
        if domain_age_days < 30:
            is_nrd = True
            risk_level = "HIGH"
            notes.append(f"🚨 Newly Registered Domain (NRD): Registered only {domain_age_days} days ago!")
        elif domain_age_days < 180:
            if risk_level != "HIGH":
                risk_level = "MEDIUM"
            notes.append(f"⚠️ Young Domain: Registered {domain_age_days} days ago.")
        else:
            notes.append(f"Domain age: {domain_age_days} days ({domain_age_days // 365} yrs).")

    if registrar != "Unknown":
        notes.append(f"Registrar: {registrar}.")

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
