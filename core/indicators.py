import re
from typing import List, Set, Dict, Any

# Regex patterns (supports both standard and defanged indicators)
IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}(?:\.|\[\.\]|\(\.\))){3}[0-9]{1,3}\b')
URL_REGEX = re.compile(r'(?:https?|hxxps?|h[xX]{2}ps?)://[^\s<>"\'{}|\\^`]+', re.IGNORECASE)
HTML_A_REGEX = re.compile(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+(?:\@|\[@\]|\(@\))[a-zA-Z0-9.-]+(?:\.|\[\.\]|\(\.\))[a-zA-Z]{2,}')

def refang_ioc(text: str) -> str:
    """Refangs security-defanged indicators (e.g., hxxps:// -> https://, [.] -> .)."""
    if not text:
        return ""
    s = text
    s = re.sub(r'^(?:hxxps|h[xX]{2}ps)://', 'https://', s, flags=re.IGNORECASE)
    s = re.sub(r'^(?:hxxp|h[xX]{2}p)://', 'http://', s, flags=re.IGNORECASE)
    s = s.replace('[.]', '.').replace('(.)', '.')
    s = s.replace('[@]', '@').replace('(@)', '@')
    s = s.replace('[:]', ':').replace('[/]', '/')
    return s

def refang_url(url: str) -> str:
    return refang_ioc(url)

def extract_ipv4(text: str) -> List[str]:
    matches = IPV4_REGEX.findall(text)
    cleaned = []
    for ip in matches:
        refanged = refang_ioc(ip)
        if validate_ipv4(refanged):
            cleaned.append(refanged)
    return list(set(cleaned))

def validate_ipv4(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            if not (0 <= int(p) <= 255):
                return False
        except ValueError:
            return False
    return True

COMMON_MULTI_LEVEL_TLDS = {
    # India (.in)
    "co.in", "gov.in", "org.in", "net.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in", "mil.in",
    # United Kingdom (.uk)
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
    # Australia (.au)
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
    # New Zealand (.nz)
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "edu.nz",
    # South Africa (.za)
    "co.za", "org.za", "gov.za", "ac.za", "net.za",
    # Japan (.jp)
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    # Brazil (.br)
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # Singapore (.sg)
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    # Canada (.ca) - provincial
    "qc.ca", "on.ca", "bc.ca", "ab.ca",
    # Others commonly seen
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.tr", "org.tr", "edu.tr", "gov.tr",
    "com.tw", "org.tw", "gov.tw", "edu.tw",
    "com.hk", "org.hk", "gov.hk", "edu.hk",
    "com.my", "org.my", "gov.my", "edu.my",
    "co.id", "net.id", "or.id", "go.id", "ac.id", "web.id", "biz.id",
    "com.ph", "org.ph", "gov.ph", "edu.ph",
    "com.pk", "org.pk", "gov.pk", "edu.pk",
    "com.ng", "org.ng", "gov.ng", "edu.ng",
    "co.ke", "or.ke", "go.ke", "ac.ke"
}

INTRA_ORG_PAIRS = {
    ("nse.co.in", "nseindia.com"),
    ("sebi.gov.in", "scores.gov.in"),
    ("cdsl.co.in", "cdslindia.com"),
    ("nsdl.co.in", "nsdl.com")
}

DOMAIN_CANDIDATE_REGEX = re.compile(
    r'^(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)(?:[/:?#].*)?$',
    re.IGNORECASE
)

def get_registrable_domain(hostname: str) -> str:
    """
    Extracts the registrable root domain, properly handling multi-part public suffixes
    (e.g., nse.co.in -> nse.co.in, news.bbc.co.uk -> bbc.co.uk, click.glassdoor.com -> glassdoor.com).
    """
    if not hostname:
        return ""
    h = hostname.lower().strip().rstrip('.')
    if ':' in h:
        h = h.split(':')[0]
    parts = h.split('.')
    if len(parts) <= 2:
        return h
    two_part_tld = f"{parts[-2]}.{parts[-1]}"
    if two_part_tld in COMMON_MULTI_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def extract_anchor_spoofs(text: str) -> List[Dict[str, str]]:
    """
    Detects deceptive links where visible anchor text displays one brand/domain,
    but href routes to a different destination (e.g. <a href="evil.com">paypal.com</a>).
    Accurately handles multi-part ccTLDs (.co.in, .gov.in) and excludes email addresses.
    """
    spoofs = []
    from urllib.parse import urlparse

    for href, anchor_text in HTML_A_REGEX.findall(text):
        refanged_href = refang_url(href.strip())
        if not refanged_href or refanged_href.lower().startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
            continue

        raw_anchor = refang_url(re.sub(r'<[^>]+>', '', anchor_text).strip())
        if not raw_anchor:
            continue

        # Do not treat email addresses as website URLs
        if '@' in raw_anchor or EMAIL_REGEX.search(raw_anchor):
            continue

        # Check if visible text looks like a URL or domain
        m = DOMAIN_CANDIDATE_REGEX.match(raw_anchor)
        if not m and not raw_anchor.lower().startswith(('http://', 'https://', 'www.')):
            continue

        try:
            anchor_url = raw_anchor if '://' in raw_anchor else 'http://' + raw_anchor
            anchor_parsed = urlparse(anchor_url)
            href_url = refanged_href if '://' in refanged_href else 'http://' + refanged_href
            href_parsed = urlparse(href_url)

            anchor_host = anchor_parsed.netloc.lower().split(':')[0].rstrip('.')
            href_host = href_parsed.netloc.lower().split(':')[0].rstrip('.')

            if not anchor_host or not href_host or anchor_host == href_host:
                continue

            # Ensure the anchor host has a valid alphabetic TLD of length >= 2
            a_parts = anchor_host.split('.')
            if len(a_parts) < 2 or not a_parts[-1].isalpha() or len(a_parts[-1]) < 2:
                continue

            # Skip version numbers or numeric hostnames
            if any(p.isdigit() for p in a_parts[-2:]):
                continue

            a_root = get_registrable_domain(anchor_host)
            h_root = get_registrable_domain(href_host)

            if not a_root or not h_root or a_root == h_root:
                continue

            # Check for known intra-organizational domain equivalence (e.g. nse.co.in <-> nseindia.com)
            if (a_root, h_root) in INTRA_ORG_PAIRS or (h_root, a_root) in INTRA_ORG_PAIRS:
                continue

            spoofs.append({
                "visible_text": raw_anchor,
                "actual_destination": refanged_href,
                "displayed_domain": anchor_host,
                "displayed_root": a_root,
                "actual_domain": href_host,
                "actual_root": h_root
            })
        except Exception:
            pass

    return spoofs

def extract_urls(text: str) -> List[str]:
    raw_urls = URL_REGEX.findall(text)
    # Also capture URLs from HTML href attributes
    for href, _ in HTML_A_REGEX.findall(text):
        if href and not href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            raw_urls.append(href.strip())
            
    cleaned = []
    for u in raw_urls:
        refanged = refang_url(u.strip())
        u_clean = refanged.rstrip(".,;:!?)>\"'")
        if len(u_clean) > 8 and u_clean.lower().startswith(('http://', 'https://')):
            cleaned.append(u_clean)
    return list(set(cleaned))

def extract_emails(text: str) -> List[str]:
    raw_emails = EMAIL_REGEX.findall(text)
    cleaned = [refang_ioc(e) for e in raw_emails]
    return list(set(cleaned))

def extract_all_indicators(text: str) -> dict:
    return {
        "ipv4": extract_ipv4(text),
        "urls": extract_urls(text),
        "emails": extract_emails(text),
        "anchor_spoofs": extract_anchor_spoofs(text)
    }

