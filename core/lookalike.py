import difflib
import re
from typing import Dict, Any, List, Optional

# Monitored high-value target brands (Global, Enterprise, Banking & Indian Financial Institutions)
MONITORED_BRANDS = [
    # Global Tech & Enterprise
    "microsoft", "google", "apple", "amazon", "paypal", "netflix", "meta", "facebook",
    "instagram", "whatsapp", "linkedin", "twitter", "telegram", "github", "gitlab",
    "dropbox", "adobe", "zoom", "slack", "salesforce", "oracle", "cisco", "docusign",
    # Global Banking & Logistics
    "chase", "wellsfargo", "bankofamerica", "citibank", "barclays", "hsbc", "dhl", "fedex", "ups",
    # Indian Banking & Government / Tax
    "sbi", "statebankofindia", "hdfc", "hdfcbank", "icici", "icicibank", "axisbank",
    "kotak", "punjabnationalbank", "pnb", "incometax", "incometaxindia", "gov", "nic"
]

# Unicode confusable homoglyphs mapping to standard ASCII
HOMOGLYPH_MAP = {
    'а': 'a', 'а': 'a', 'ɑ': 'a', 'α': 'a',
    'с': 'c', 'ϲ': 'c',
    'е': 'e', 'е': 'e', 'ε': 'e',
    'і': 'i', 'і': 'i', '1': 'l', '|': 'l', '!': 'i',
    'ϳ': 'j',
    'о': 'o', 'о': 'o', '0': 'o', 'ο': 'o', 'ø': 'o',
    'р': 'p', 'р': 'p', 'ρ': 'p',
    'ѕ': 's', '$': 's', '5': 's',
    'х': 'x', 'χ': 'x',
    'у': 'y', 'γ': 'y',
    'rn': 'm', 'vv': 'w'
}

SUSPICIOUS_AFFIXES = [
    "-support", "-security", "-verify", "-verification", "-login", "-portal",
    "-signin", "-auth", "-update", "-alert", "-secure", "-account", "-helpdesk",
    "-billing", "-service", "-protect", "-official", "-online"
]

def normalize_homoglyphs(text: str) -> str:
    """Normalize common homoglyphs and leetspeak substitutions to base ASCII."""
    norm = text.lower()
    # First multi-char replacements
    norm = norm.replace("rn", "m").replace("vv", "w")
    # Character substitutions
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in norm)

def get_base_domain(domain: str) -> str:
    """Extract domain body without TLD, e.g. 'paypal-support.com' -> 'paypal-support'."""
    clean = domain.lower().strip()
    if clean.startswith("http://") or clean.startswith("https://"):
        clean = clean.split("://", 1)[1]
    clean = clean.split("/")[0].split(":")[0]
    parts = clean.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return clean

OFFICIAL_EXEMPT_DOMAINS = {
    "google.com", "google.co.in", "gmail.com", "microsoft.com", "outlook.com",
    "apple.com", "amazon.com", "amazon.in", "paypal.com", "paypal.in",
    "sbi.co.in", "statebankofindia.com", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com", "pnbindia.in", "rbi.org.in",
    "youtube.com", "linkedin.com", "twitter.com", "x.com", "instagram.com",
    "facebook.com", "netflix.com", "github.com", "substack.com", "growthschool.io",
    "yahoo.com", "zoho.com", "zoho.in", "swiggy.in", "zomato.com", "flipkart.com"
}

def detect_lookalike_domain(domain: str) -> Dict[str, Any]:
    """
    Forensic detection of Punycode, homoglyphs, typosquatting,
    and brand impersonation without any external API calls.
    """
    if not domain:
        return {
            "domain": "",
            "is_lookalike": False,
            "impersonated_brand": None,
            "technique": "None",
            "similarity_score": 0.0,
            "risk_level": "LOW",
            "reasons": []
        }

    domain_lower = domain.lower().strip()
    if domain_lower.startswith("http://") or domain_lower.startswith("https://"):
        domain_lower = domain_lower.split("://", 1)[1]
    domain_lower = domain_lower.split("/")[0].split(":")[0]

    # Quick exit for verified legitimate enterprise & brand domains
    if any(domain_lower == od or domain_lower.endswith(f".{od}") for od in OFFICIAL_EXEMPT_DOMAINS):
        return {
            "domain": domain,
            "base_name": get_base_domain(domain_lower),
            "is_lookalike": False,
            "impersonated_brand": None,
            "technique": "None",
            "similarity_score": 0.0,
            "risk_level": "LOW",
            "reasons": ["Verified official enterprise domain."]
        }

    base_name = get_base_domain(domain_lower)
    reasons = []
    technique = "None"
    impersonated_brand = None
    similarity_score = 0.0
    is_lookalike = False

    # 1. Punycode Check (Internationalized Domain Names spoofing)
    if "xn--" in domain_lower:
        is_lookalike = True
        technique = "Punycode (IDN Homograph Attack)"
        try:
            decoded = domain_lower.encode('ascii').decode('idna')
            reasons.append(f"Punycode encoded domain detected: '{domain_lower}' decodes visually to '{decoded}'")
        except Exception:
            reasons.append(f"Punycode encoded domain detected: '{domain_lower}'")

    # 2. Homoglyph Normalization
    normalized_name = normalize_homoglyphs(base_name)
    if normalized_name != base_name:
        for brand in MONITORED_BRANDS:
            if brand in normalized_name and brand not in base_name:
                is_lookalike = True
                technique = "Homoglyph Character Substitution"
                impersonated_brand = brand
                reasons.append(f"Homoglyph character substitution mimics '{brand}' (e.g., Cyrillic/leetspeak characters)")
                break

    # 3. Brand Affix Squatting (e.g. paypal-security-update.com, sbi-verify.net)
    for brand in MONITORED_BRANDS:
        for affix in SUSPICIOUS_AFFIXES:
            if (f"{brand}{affix}" in base_name) or (f"{affix[1:]}-{brand}" in base_name):
                is_lookalike = True
                technique = "Combo-squatting / Brand Affix Impersonation"
                impersonated_brand = brand
                reasons.append(f"Domain uses brand '{brand}' with deception affix '{affix}' to fake institutional support")
                break
        if is_lookalike and technique == "Combo-squatting / Brand Affix Impersonation":
            break

    # 4. Levenshtein / Sequence Distance Typosquatting (e.g. paypai, paypa1, mircosoft, g00gle)
    if not is_lookalike:
        for brand in MONITORED_BRANDS:
            # Skip if domain is exact brand (e.g. google.com or microsoft.com)
            if base_name == brand:
                continue

            # Compare similarity ratio
            ratio = difflib.SequenceMatcher(None, base_name, brand).ratio()
            if ratio >= 0.80 and len(base_name) >= len(brand) - 1:
                is_lookalike = True
                technique = "Typosquatting (Levenshtein Edit Distance)"
                impersonated_brand = brand
                similarity_score = round(ratio * 100, 1)
                reasons.append(f"High lexical similarity ({similarity_score}%) to legitimate brand '{brand}'")
                break

    # Risk level determination
    risk_level = "LOW"
    if is_lookalike:
        risk_level = "HIGH" if technique != "Typosquatting (Levenshtein Edit Distance)" or similarity_score >= 85 else "MEDIUM"

    return {
        "domain": domain,
        "base_name": base_name,
        "is_lookalike": is_lookalike,
        "impersonated_brand": impersonated_brand,
        "technique": technique,
        "similarity_score": similarity_score,
        "risk_level": risk_level,
        "reasons": reasons
    }
