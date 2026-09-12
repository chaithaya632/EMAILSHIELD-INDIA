"""
core/header_diff.py
Forensic Header Diff & Baseline Comparator for EMAILSHIELD INDIA.
Compares suspect email headers against verified legitimate enterprise brand baselines
(e.g., SBI, HDFC, Google, Microsoft, PayPal, Amazon) or analyst-provided reference emails
to expose forged infrastructure, spoofed authentication, and unauthorized relay hops.
"""

import re
from typing import Dict, Any, List, Optional

# Verified Legitimate Brand Header Baselines
BRAND_BASELINES = {
    "sbi.co.in": {
        "brand_name": "State Bank of India (SBI)",
        "expected_from_domain": "sbi.co.in",
        "expected_return_path": r'@(?:[a-zA-Z0-9-]+\.)*sbi\.co\.in$',
        "expected_dkim_domain": r'sbi\.co\.in$',
        "expected_outbound_mta": r'(?:sbi\.co\.in|tatacommunications|airtel|sify)',
        "expected_spf_result": "Pass",
        "expected_dkim_result": "Pass",
        "expected_dmarc_result": "Pass",
        "strict_alignment": True
    },
    "hdfcbank.com": {
        "brand_name": "HDFC Bank",
        "expected_from_domain": "hdfcbank.com",
        "expected_return_path": r'@(?:[a-zA-Z0-9-]+\.)*hdfcbank\.(?:com|net)$',
        "expected_dkim_domain": r'hdfcbank\.(?:com|net)$',
        "expected_outbound_mta": r'(?:hdfcbank\.com|netcore\.co\.in|hdfc)',
        "expected_spf_result": "Pass",
        "expected_dkim_result": "Pass",
        "expected_dmarc_result": "Pass",
        "strict_alignment": True
    },
    "icicibank.com": {
        "brand_name": "ICICI Bank",
        "expected_from_domain": "icicibank.com",
        "expected_return_path": r'@(?:[a-zA-Z0-9-]+\.)*icicibank\.com$',
        "expected_dkim_domain": r'icicibank\.com$',
        "expected_outbound_mta": r'icicibank\.com',
        "expected_spf_result": "Pass",
        "expected_dkim_result": "Pass",
        "expected_dmarc_result": "Pass",
        "strict_alignment": True
    },
    "paypal.com": {
        "brand_name": "PayPal Inc.",
        "expected_from_domain": "paypal.com",
        "expected_return_path": r'@(?:[a-zA-Z0-9-]+\.)*paypal\.com$',
        "expected_dkim_domain": r'paypal\.com$',
        "expected_outbound_mta": r'(?:paypal\.com|corp\.ebay\.com)',
        "expected_spf_result": "Pass",
        "expected_dkim_result": "Pass",
        "expected_dmarc_result": "Pass",
        "strict_alignment": True
    },
    "google.com": {
        "brand_name": "Google / Gmail",
        "expected_from_domain": "google.com",
        "expected_return_path": r'@(?:[a-zA-Z0-9-]+\.)*google\.com$',
        "expected_dkim_domain": r'google\.com$',
        "expected_outbound_mta": r'(?:google\.com|1e100\.net)',
        "expected_spf_result": "Pass",
        "expected_dkim_result": "Pass",
        "expected_dmarc_result": "Pass",
        "strict_alignment": True
    },
    "microsoft.com": {
        "brand_name": "Microsoft Corporation",
        "expected_from_domain": "microsoft.com",
        "expected_return_path": r'@(?:[a-zA-Z0-9-]+\.)*microsoft\.com$',
        "expected_dkim_domain": r'microsoft\.com$',
        "expected_outbound_mta": r'(?:outbound\.protection\.outlook\.com|microsoft\.com)',
        "expected_spf_result": "Pass",
        "expected_dkim_result": "Pass",
        "expected_dmarc_result": "Pass",
        "strict_alignment": True
    },
    "amazon.in": {
        "brand_name": "Amazon India",
        "expected_from_domain": "amazon.in",
        "expected_return_path": r'@(?:[a-zA-Z0-9-]+\.)*amazon\.(?:in|com)$',
        "expected_dkim_domain": r'amazon\.(?:in|com)$',
        "expected_outbound_mta": r'(?:amazon\.(?:in|com)|amazonses\.com)',
        "expected_spf_result": "Pass",
        "expected_dkim_result": "Pass",
        "expected_dmarc_result": "Pass",
        "strict_alignment": True
    }
}


def find_matching_brand_baseline(from_address: str, display_name: str = "") -> Optional[Dict[str, Any]]:
    """Identifies if the email claims to be from a known monitored brand."""
    combined = f"{from_address} {display_name}".lower()
    for domain, baseline in BRAND_BASELINES.items():
        brand_short = domain.split('.')[0]
        if domain in combined or brand_short in combined:
            return baseline
    return None


def compare_headers_against_baseline(suspect_headers: Dict[str, Any], baseline_domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs forensic discrepancy analysis comparing suspect headers against
    the selected brand baseline.
    """
    from_addr = suspect_headers.get("from", "")
    from_domain = from_addr.split("@")[-1].strip(">").lower() if "@" in from_addr else ""
    return_path = suspect_headers.get("return_path", "")
    rp_domain = return_path.split("@")[-1].strip(">").lower() if "@" in return_path else ""
    dkim_domain = suspect_headers.get("dkim_domain", "")
    spf_res = suspect_headers.get("spf", "None")
    dkim_res = suspect_headers.get("dkim", "None")
    dmarc_res = suspect_headers.get("dmarc", "None")
    first_hop = suspect_headers.get("first_hop", "")

    # Select baseline
    baseline = None
    if baseline_domain and baseline_domain in BRAND_BASELINES:
        baseline = BRAND_BASELINES[baseline_domain]
    else:
        baseline = find_matching_brand_baseline(from_addr, suspect_headers.get("sender_name", ""))
        
    if not baseline:
        # Fallback to generic legitimate baseline using the sender's own domain
        baseline = {
            "brand_name": f"Domain Baseline ({from_domain or 'Generic'})",
            "expected_from_domain": from_domain,
            "expected_return_path": rf'@{re.escape(from_domain)}$',
            "expected_dkim_domain": rf'{re.escape(from_domain)}$',
            "expected_outbound_mta": rf'{re.escape(from_domain)}',
            "expected_spf_result": "Pass",
            "expected_dkim_result": "Pass",
            "expected_dmarc_result": "Pass",
            "strict_alignment": True
        }

    discrepancies = []
    
    # Check 1: Return-Path (Envelope-From) Alignment
    rp_match = bool(re.search(baseline["expected_return_path"], return_path, re.IGNORECASE))
    discrepancies.append({
        "checkpoint": "Return-Path Alignment",
        "legitimate_norm": f"@{baseline['expected_from_domain']}",
        "suspect_actual": return_path or "Missing",
        "status": "MATCH" if rp_match else "FORGERY_DETECTED",
        "severity": "LOW" if rp_match else "HIGH",
        "finding": "Envelope matches legitimate sender domain." if rp_match else f"Mismatched Return-Path: Mail actually originated from '{rp_domain}', not '{baseline['expected_from_domain']}'."
    })

    # Check 2: DKIM Signing Domain (d=)
    dkim_match = bool(re.search(baseline["expected_dkim_domain"], dkim_domain, re.IGNORECASE)) if dkim_domain else False
    discrepancies.append({
        "checkpoint": "DKIM Signing Key (d=)",
        "legitimate_norm": f"Signed by {baseline['expected_from_domain']}",
        "suspect_actual": f"d={dkim_domain}" if dkim_domain else "No DKIM Signature",
        "status": "MATCH" if dkim_match else "FORGERY_DETECTED",
        "severity": "LOW" if dkim_match else "CRITICAL",
        "finding": f"Legitimate DKIM signature from {baseline['expected_from_domain']}." if dkim_match else f"Cryptographic key mismatch: Signed by third-party '{dkim_domain}' rather than '{baseline['expected_from_domain']}'."
    })

    # Check 3: SPF Verification
    spf_match = (spf_res.lower() == "pass")
    discrepancies.append({
        "checkpoint": "SPF Authentication",
        "legitimate_norm": "Pass",
        "suspect_actual": spf_res,
        "status": "MATCH" if spf_match else "FORGERY_DETECTED",
        "severity": "LOW" if spf_match else "HIGH",
        "finding": "Sender MTA authorized in SPF record." if spf_match else f"SPF result '{spf_res}': Relay IP not authorized to send for domain."
    })

    # Check 4: DMARC Alignment & Policy
    dmarc_match = (dmarc_res.lower() == "pass")
    discrepancies.append({
        "checkpoint": "DMARC Alignment",
        "legitimate_norm": "Pass (Aligned)",
        "suspect_actual": dmarc_res,
        "status": "MATCH" if dmarc_match else "FORGERY_DETECTED",
        "severity": "LOW" if dmarc_match else "CRITICAL",
        "finding": "Fully aligned RFC 7489 DMARC pass." if dmarc_match else "DMARC failed or alignment bypass detected."
    })

    # Check 5: Outbound Relay Host (First Hop)
    mta_match = bool(re.search(baseline["expected_outbound_mta"], first_hop, re.IGNORECASE)) if first_hop else True
    discrepancies.append({
        "checkpoint": "Outbound MTA Gateway",
        "legitimate_norm": f"Authorized brand MTAs ({baseline['brand_name']})",
        "suspect_actual": first_hop[:40] if first_hop else "Direct / Unreported",
        "status": "MATCH" if mta_match else "ANOMALY",
        "severity": "LOW" if mta_match else "MEDIUM",
        "finding": "Outbound server belongs to known brand infrastructure." if mta_match else f"Unusual transit server: '{first_hop[:35]}' does not match standard brand mail cluster."
    })

    forgery_count = sum(1 for d in discrepancies if d["status"] == "FORGERY_DETECTED")
    anomaly_count = sum(1 for d in discrepancies if d["status"] == "ANOMALY")

    verdict = "LEGITIMATE / ALIGNED"
    if forgery_count >= 2:
        verdict = "CRITICAL SPOOFING / FORGERY DETECTED"
    elif forgery_count == 1 or anomaly_count >= 2:
        verdict = "SUSPICIOUS / UNVERIFIED INFRASTRUCTURE"

    return {
        "baseline_brand": baseline["brand_name"],
        "baseline_domain": baseline["expected_from_domain"],
        "verdict": verdict,
        "forgery_count": forgery_count,
        "anomaly_count": anomaly_count,
        "checkpoints": discrepancies
    }
