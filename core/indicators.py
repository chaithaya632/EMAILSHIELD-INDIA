import re
from typing import List, Set

# Regex patterns
IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"\'{}|\\^`]+')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

def extract_ipv4(text: str) -> List[str]:
    ips = IPV4_REGEX.findall(text)
    return list(set([ip for ip in ips if validate_ipv4(ip)]))

def validate_ipv4(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not (0 <= int(p) <= 255):
            return False
    return True

def extract_urls(text: str) -> List[str]:
    raw_urls = URL_REGEX.findall(text)
    cleaned = []
    for u in raw_urls:
        u_clean = u.rstrip(".,;:!?)>\"'")
        if len(u_clean) > 8:
            cleaned.append(u_clean)
    return list(set(cleaned))

def extract_emails(text: str) -> List[str]:
    return list(set(EMAIL_REGEX.findall(text)))

def extract_all_indicators(text: str) -> dict:
    return {
        "ipv4": extract_ipv4(text),
        "urls": extract_urls(text),
        "emails": extract_emails(text)
    }
