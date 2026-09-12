"""
core/indian_banking.py
Specialized Financial Intelligence & Route Extractor for Indian Cyber Threats.
Detects UPI Virtual Payment Addresses (VPAs), RBI IFSC codes, Bank Account routes,
and Indian-context financial extortion/BEC payment lures.
"""

import re
from typing import Dict, Any, List

# Common Indian Bank Code to Name Mapping
BANK_CODE_MAP = {
    "SBIN": "State Bank of India (SBI)",
    "HDFC": "HDFC Bank",
    "ICIC": "ICICI Bank",
    "PUNB": "Punjab National Bank (PNB)",
    "BARB": "Bank of Baroda",
    "UTIB": "Axis Bank",
    "KKBK": "Kotak Mahindra Bank",
    "CNRB": "Canara Bank",
    "UBIN": "Union Bank of India",
    "IDIB": "Indian Bank",
    "BKID": "Bank of India",
    "IOBA": "Indian Overseas Bank",
    "YESB": "Yes Bank",
    "IDFB": "IDFC FIRST Bank",
    "INDB": "IndusInd Bank",
    "FDRL": "Federal Bank",
    "MAHB": "Bank of Maharashtra",
    "PSIB": "Punjab & Sind Bank",
    "UCOB": "UCO Bank",
    "CORP": "Union Bank of India (Corp)",
    "ALLA": "Indian Bank (Allahabad)",
    "ANDB": "Union Bank of India (Andhra)",
    "SYNB": "Canara Bank (Syndicate)",
    "PYTM": "Paytm Payments Bank",
    "AIRP": "Airtel Payments Bank",
    "IPOS": "India Post Payments Bank (IPPB)"
}

# Major Indian UPI Handles / PSP Suffixes
UPI_PSP_SUFFIXES = [
    "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "ybl", "ibl", "axl",
    "upi", "apl", "fbl", "sbi", "postbank", "icici", "hdfcbank", "kotak",
    "barodampay", "federal", "indus", "idfcbank", "aubank", "unionbank", "pnb",
    "airtel", "gpay", "phonepe", "amazonpay", "freecharge", "mobikwik", "slice", "jupiteraxis"
]

UPI_PATTERN = re.compile(
    r'\b([a-zA-Z0-9.\-_]{2,64}@(?:' + '|'.join(UPI_PSP_SUFFIXES) + r'))\b',
    re.IGNORECASE
)

# Standard RBI 11-character IFSC: 4 letters + '0' + 6 alphanumeric
IFSC_PATTERN = re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b')

# Bank Account Patterns (9 to 18 digits with contextual keywords)
ACCOUNT_KEYWORD_PATTERN = re.compile(
    r'(?:account\s*(?:no|number|#)?|a/c\s*(?:no|number|#)?|acc\s*(?:no|number)?|beneficiary\s*(?:a/c|account)?|bank\s*a/c)[\s:]*([0-9]{9,18})\b',
    re.IGNORECASE
)

# Indian Financial Threat Lures & Phishing Keywords
INDIAN_FINANCIAL_LURES = [
    (r'\belectricity\b.*?\b(?:disconnected|power\s*cut|suspended|pending\s*bill)', "Electricity Disconnection Scam"),
    (r'\b(?:traffic|police|court|e-?challan)\b.*?\b(?:pending|unpaid|penalty|fine|notice)', "Traffic / Court E-Challan Scam"),
    (r'\bincome\s*tax\b.*?\b(?:refund|demand|notice|audit|penalty|scrutiny)', "Income Tax Refund / Demand Notice"),
    (r'\bkyc\b.*?\b(?:update|expired|suspended|verify|block|mandatory)', "Banking KYC Expiry / Suspension Scam"),
    (r'\bpan\b.*?\b(?:link|aadhaar|deactivate|blocked)', "PAN-Aadhaar Deactivation Warning"),
    (r'\blottery\b.*?\b(?:winner|kbc|prize|claim|reward)', "Lottery / KBC Reward Scam"),
    (r'\b(?:cbi|police|customs|narcotics)\b.*?\b(?:arrest|summons|warrant|seizure|parcel)', "Law Enforcement / Customs Parcel Impersonation"),
    (r'\bdigital\s*arrest\b', "Digital Arrest Threat Extortion"),
    (r'\bfastag\b.*?\b(?:blocked|recharge|deactivated|blacklist)', "FASTag Deactivation Alert"),
    (r'\b(?:urgent|immediate)\b.*?\b(?:wire\s*transfer|rtgs|neft|beneficiary\s*update)', "Urgent Payment / Beneficiary Diversion")
]


def extract_indian_financial_indicators(text: str) -> Dict[str, Any]:
    """
    Extracts Indian-specific financial artifacts including UPI IDs, IFSC codes,
    bank account numbers, and identifies Indian cyber financial extortion lures.
    """
    if not text:
        return {
            "upi_handles": [],
            "ifsc_codes": [],
            "bank_accounts": [],
            "identified_banks": [],
            "financial_lures": [],
            "has_indian_financial_iocs": False,
            "threat_score": 0
        }

    # 1. Extract UPI IDs
    upi_matches = set(UPI_PATTERN.findall(text))
    upi_handles = sorted([u.lower() for u in upi_matches])

    # 2. Extract IFSC Codes & Resolve Bank Names
    ifsc_matches = set(IFSC_PATTERN.findall(text.upper()))
    ifsc_codes = sorted(list(ifsc_matches))
    
    identified_banks = []
    for ifsc in ifsc_codes:
        bank_code = ifsc[:4]
        bank_name = BANK_CODE_MAP.get(bank_code, f"Indian Bank ({bank_code})")
        identified_banks.append({
            "ifsc": ifsc,
            "bank_code": bank_code,
            "bank_name": bank_name
        })

    # 3. Extract Bank Account Numbers
    acct_matches = set(ACCOUNT_KEYWORD_PATTERN.findall(text))
    bank_accounts = sorted(list(acct_matches))

    # 4. Scan for Indian Cyber Financial Extortion & Phishing Lures
    detected_lures = []
    for pattern, label in INDIAN_FINANCIAL_LURES:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            detected_lures.append(label)

    # 5. Risk Assessment
    threat_score = 0
    if upi_handles:
        threat_score += 25 * len(upi_handles)
    if ifsc_codes:
        threat_score += 30 * len(ifsc_codes)
    if bank_accounts:
        threat_score += 25 * len(bank_accounts)
    if detected_lures:
        threat_score += 35 * len(detected_lures)

    threat_score = min(100, threat_score)
    has_iocs = bool(upi_handles or ifsc_codes or bank_accounts or detected_lures)

    return {
        "upi_handles": upi_handles,
        "ifsc_codes": ifsc_codes,
        "bank_accounts": bank_accounts,
        "identified_banks": identified_banks,
        "financial_lures": detected_lures,
        "has_indian_financial_iocs": has_iocs,
        "threat_score": threat_score
    }
