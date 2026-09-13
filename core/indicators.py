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

def extract_anchor_spoofs(text: str) -> List[Dict[str, str]]:
    """
    Detects deceptive links where visible anchor text displays one brand/domain,
    but href routes to a different destination (e.g. <a href="evil.com">paypal.com</a>).
    """
    spoofs = []
    for href, anchor_text in HTML_A_REGEX.findall(text):
        refanged_href = refang_url(href.strip())
        raw_anchor = refang_url(re.sub(r'<[^>]+>', '', anchor_text).strip())
        
        if any(raw_anchor.startswith(p) for p in ['http://', 'https://', 'www.']) or any(tld in raw_anchor for tld in ['.com', '.org', '.net', '.edu', '.gov', '.co']):
            try:
                from urllib.parse import urlparse
                anchor_parsed = urlparse(raw_anchor if '://' in raw_anchor else 'http://' + raw_anchor)
                href_parsed = urlparse(refanged_href if '://' in refanged_href else 'http://' + refanged_href)
                
                anchor_host = anchor_parsed.netloc.lower().split(':')[0]
                href_host = href_parsed.netloc.lower().split(':')[0]
                
                if anchor_host and href_host and anchor_host != href_host:
                    a_parts = anchor_host.split('.')
                    h_parts = href_host.split('.')
                    a_root = '.'.join(a_parts[-2:]) if len(a_parts) >= 2 else anchor_host
                    h_root = '.'.join(h_parts[-2:]) if len(h_parts) >= 2 else href_host
                    
                    if a_root != h_root:
                        spoofs.append({
                            "visible_text": raw_anchor,
                            "actual_destination": refanged_href,
                            "displayed_domain": anchor_host,
                            "actual_domain": href_host
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

