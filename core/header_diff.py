"""
core/header_diff.py
Forensic Header Diff & Baseline Comparator for EMAILSHIELD INDIA.
Compares suspect email headers against verified legitimate enterprise brand baselines
(e.g., SBI, HDFC, Google, Microsoft, PayPal, Amazon) or analyst-provided reference emails
to expose forged infrastructure, spoofed authentication, and unauthorized relay hops.
"""

import re
from typing import Dict, Any, List, Optional
from core.auth_claims import extract_domain, get_org_domain, KNOWN_LEGIT_ESPS

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
        if domain in combined:
            return baseline
        if re.search(rf'\b{re.escape(brand_short)}\b', combined):
            return baseline
    return None


def compare_headers_against_baseline(suspect_headers: Dict[str, Any], baseline_domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs forensic discrepancy analysis comparing suspect headers against
    the selected brand baseline.
    """
    from_addr = str(suspect_headers.get("from", "")).strip()
    from_domain = extract_domain(from_addr)
    if not from_domain and "@" in from_addr:
        from_domain = from_addr.split("@")[-1].strip("<> ").lower()

    return_path = str(suspect_headers.get("return_path", "")).strip()
    rp_domain = extract_domain(return_path)
    if not rp_domain and "@" in return_path:
        rp_domain = return_path.split("@")[-1].strip("<> ").lower()

    dkim_domain = str(suspect_headers.get("dkim_domain", "")).strip().lower()
    spf_res = str(suspect_headers.get("spf", "None")).strip()
    dkim_res = str(suspect_headers.get("dkim", "None")).strip()
    dmarc_res = str(suspect_headers.get("dmarc", "None")).strip()
    first_hop = str(suspect_headers.get("first_hop", "")).strip()

    # Select baseline
    baseline = None
    if baseline_domain and baseline_domain in BRAND_BASELINES:
        baseline = BRAND_BASELINES[baseline_domain]
    elif baseline_domain and baseline_domain != "Auto-Detect from Sender":
        baseline = BRAND_BASELINES.get(baseline_domain)

    if not baseline:
        baseline = find_matching_brand_baseline(from_addr, suspect_headers.get("sender_name", ""))
        
    is_generic_baseline = False
    if not baseline:
        is_generic_baseline = True
        base_org = get_org_domain(from_domain) or from_domain
        baseline = {
            "brand_name": f"Domain Baseline ({from_domain or 'Generic'})",
            "expected_from_domain": from_domain,
            "expected_return_path": rf'@(?:[a-zA-Z0-9-]+\.)*{re.escape(base_org)}$',
            "expected_dkim_domain": rf'(?:[a-zA-Z0-9-]+\.)*{re.escape(base_org)}$',
            "expected_outbound_mta": rf'(?:{re.escape(base_org)}|google|1e100|outlook|microsoft|amazonses|sendgrid|mailgun|2002:)',
            "expected_spf_result": "Pass",
            "expected_dkim_result": "Pass",
            "expected_dmarc_result": "Pass",
            "strict_alignment": False
        }

    expected_from_dom = baseline["expected_from_domain"].lower()
    expected_org = get_org_domain(expected_from_dom) or expected_from_dom

    discrepancies = []

    # Check 1: Return-Path (Envelope-From) Alignment
    rp_clean = return_path.strip("<> ")
    rp_match = False
    rp_status = "FORGERY_DETECTED"
    rp_severity = "HIGH"
    rp_finding = ""

    if not return_path or not rp_domain:
        rp_status = "UNCONFIGURED"
        rp_severity = "LOW"
        rp_finding = "Return-Path envelope header missing or not recorded in transit."
    elif rp_domain == expected_from_dom:
        rp_match = True
        rp_status = "MATCH"
        rp_severity = "LOW"
        rp_finding = f"Envelope matches legitimate sender domain '{expected_from_dom}'."
    elif expected_org and get_org_domain(rp_domain) == expected_org:
        rp_match = True
        rp_status = "MATCH"
        rp_severity = "LOW"
        rp_finding = f"Envelope domain '{rp_domain}' is organizationally aligned with '{expected_from_dom}'."
    elif re.search(baseline["expected_return_path"], rp_clean, re.IGNORECASE) or re.search(baseline["expected_return_path"], f"@{rp_domain}", re.IGNORECASE):
        rp_match = True
        rp_status = "MATCH"
        rp_severity = "LOW"
        rp_finding = "Envelope matches legitimate sender domain pattern."
    elif any(rp_domain.endswith(esp) for esp in KNOWN_LEGIT_ESPS) and not baseline.get("strict_alignment"):
        rp_status = "ANOMALY"
        rp_severity = "LOW"
        rp_finding = f"Mail routed via third-party Email Service Provider bounce address ('{rp_domain}')."
    else:
        rp_status = "FORGERY_DETECTED"
        rp_severity = "HIGH"
        rp_finding = f"Mismatched Return-Path: Mail actually originated from '{rp_domain}', not '{expected_from_dom}'."

    discrepancies.append({
        "checkpoint": "Return-Path Alignment",
        "legitimate_norm": f"@{baseline['expected_from_domain']}",
        "suspect_actual": return_path or "Missing",
        "status": rp_status,
        "severity": rp_severity,
        "finding": rp_finding
    })

    # Check 2: DKIM Signing Domain (d=)
    dkim_status = "NONE"
    dkim_severity = "LOW"
    dkim_finding = ""

    if not dkim_domain or dkim_domain in ["none", ""]:
        if baseline.get("strict_alignment") and not is_generic_baseline:
            dkim_status = "ANOMALY"
            dkim_severity = "MEDIUM"
            dkim_finding = f"No DKIM signature present; {baseline['brand_name']} typically signs all outbound mail."
        else:
            dkim_status = "NONE"
            dkim_severity = "LOW"
            dkim_finding = "No DKIM cryptographic signature present on email."
    elif dkim_domain == expected_from_dom:
        dkim_status = "MATCH"
        dkim_severity = "LOW"
        dkim_finding = f"Legitimate DKIM signature from '{expected_from_dom}'."
    elif expected_org and get_org_domain(dkim_domain) == expected_org:
        dkim_status = "MATCH"
        dkim_severity = "LOW"
        dkim_finding = f"DKIM signing domain '{dkim_domain}' is organizationally aligned with '{expected_from_dom}'."
    elif re.search(baseline["expected_dkim_domain"], dkim_domain, re.IGNORECASE):
        dkim_status = "MATCH"
        dkim_severity = "LOW"
        dkim_finding = f"Legitimate DKIM signature from '{dkim_domain}'."
    elif dkim_domain.endswith("gappssmtp.com"):
        gw_prefix = dkim_domain.split(".gappssmtp.com")[0].split(".")[0].replace("-", ".")
        if gw_prefix == expected_from_dom or (expected_org and get_org_domain(gw_prefix) == expected_org):
            dkim_status = "MATCH"
            dkim_severity = "LOW"
            dkim_finding = f"Legitimate Google Workspace DKIM signature provisioned for '{expected_from_dom}'."
        elif not baseline.get("strict_alignment"):
            dkim_status = "ANOMALY"
            dkim_severity = "LOW"
            dkim_finding = f"DKIM signature delegated to Google Workspace relay '{dkim_domain}'."
        else:
            dkim_status = "FORGERY_DETECTED"
            dkim_severity = "CRITICAL"
            dkim_finding = f"Cryptographic key mismatch: Signed by unauthorized third-party '{dkim_domain}' rather than '{expected_from_dom}'."
    elif any(dkim_domain.endswith(esp) for esp in KNOWN_LEGIT_ESPS) and not baseline.get("strict_alignment"):
        dmarc_low = dmarc_res.lower()
        if dmarc_low in ["pass", "pass (delegated esp)"] or spf_res.lower() == "pass":
            dkim_status = "MATCH"
            dkim_severity = "LOW"
            dkim_finding = f"DKIM signature delegated to authorized email provider '{dkim_domain}' (DMARC/SPF satisfied)."
        else:
            dkim_status = "ANOMALY"
            dkim_severity = "LOW"
            dkim_finding = f"DKIM signature delegated to third-party ESP '{dkim_domain}'."
    elif dmarc_res.lower() in ["pass", "pass (delegated esp)"] or (spf_res.lower() == "pass" and rp_match):
        dkim_status = "ANOMALY"
        dkim_severity = "LOW"
        dkim_finding = f"Third-party DKIM signature '{dkim_domain}' on email with passing domain authentication."
    else:
        dkim_status = "FORGERY_DETECTED"
        dkim_severity = "CRITICAL"
        dkim_finding = f"Cryptographic key mismatch: Signed by unauthorized third-party '{dkim_domain}' rather than '{expected_from_dom}'."

    discrepancies.append({
        "checkpoint": "DKIM Signing Key (d=)",
        "legitimate_norm": f"Signed by {baseline['expected_from_domain']}",
        "suspect_actual": f"d={dkim_domain}" if dkim_domain and dkim_domain != "none" else "No DKIM Signature",
        "status": dkim_status,
        "severity": dkim_severity,
        "finding": dkim_finding
    })

    # Check 3: SPF Verification
    spf_low = spf_res.lower()
    spf_status = "UNCONFIGURED"
    spf_severity = "LOW"
    spf_finding = ""

    if spf_low == "pass":
        spf_status = "MATCH"
        spf_severity = "LOW"
        spf_finding = "Sender MTA authorized in SPF record."
    elif spf_low == "softfail":
        spf_status = "ANOMALY"
        spf_severity = "MEDIUM"
        spf_finding = "SPF softfail (~all): Sending host not strongly authorized by domain policy."
    elif spf_low == "fail":
        spf_status = "FORGERY_DETECTED"
        spf_severity = "HIGH"
        spf_finding = "SPF hard fail (-all): Relay IP explicitly rejected by domain SPF policy."
    elif spf_low in ["none", "temperror", "permerror", "neutral", ""]:
        spf_status = "UNCONFIGURED"
        spf_severity = "LOW"
        spf_finding = f"SPF result '{spf_res}': No authoritative SPF pass or unconfigured SPF policy."
    else:
        spf_status = "ANOMALY"
        spf_severity = "LOW"
        spf_finding = f"SPF returned status '{spf_res}'."

    discrepancies.append({
        "checkpoint": "SPF Authentication",
        "legitimate_norm": "Pass",
        "suspect_actual": spf_res,
        "status": spf_status,
        "severity": spf_severity,
        "finding": spf_finding
    })

    # Check 4: DMARC Alignment & Policy
    dmarc_low = dmarc_res.lower()
    dmarc_status = "UNCONFIGURED"
    dmarc_severity = "LOW"
    dmarc_finding = ""

    if dmarc_low in ["pass", "pass (delegated esp)"]:
        dmarc_status = "MATCH"
        dmarc_severity = "LOW"
        dmarc_finding = f"Fully aligned RFC 7489 DMARC pass ({dmarc_res})."
    elif "alignment bypass" in dmarc_low:
        dmarc_status = "FORGERY_DETECTED"
        dmarc_severity = "CRITICAL"
        dmarc_finding = "DMARC alignment failure: Sender passed third-party SPF/DKIM but domain is unaligned."
    elif dmarc_low in ["fail", "reject", "quarantine"]:
        dmarc_status = "FORGERY_DETECTED"
        dmarc_severity = "CRITICAL"
        dmarc_finding = f"DMARC policy failure (result: '{dmarc_res}')."
    elif dmarc_low in ["none", "none / unconfigured", "not evaluated", ""]:
        dmarc_status = "UNCONFIGURED"
        dmarc_severity = "LOW"
        dmarc_finding = "No DMARC policy published by domain or authentication claims unconfigured."
    else:
        dmarc_status = "ANOMALY"
        dmarc_severity = "MEDIUM"
        dmarc_finding = f"DMARC evaluation inconclusive (result: '{dmarc_res}')."

    discrepancies.append({
        "checkpoint": "DMARC Alignment",
        "legitimate_norm": "Pass (Aligned)",
        "suspect_actual": dmarc_res,
        "status": dmarc_status,
        "severity": dmarc_severity,
        "finding": dmarc_finding
    })

    # Check 5: Outbound Relay Host (First Hop)
    COMMON_ENTERPRISE_RELAYS = (
        r'(?:google\.com|googlemail\.com|1e100\.net|gmail\.com|'
        r'outbound\.protection\.outlook\.com|office365\.com|microsoft\.com|'
        r'amazonses\.com|amazonaws\.com|'
        r'sendgrid\.net|mailgun\.org|mandrillapp\.com|postmarkapp\.com|'
        r'2002:[0-9a-fA-F:]+|'
        r'2607:[0-9a-fA-F:]+)'
    )

    mta_match = False
    if not first_hop:
        mta_match = True
        mta_status = "MATCH"
        mta_severity = "LOW"
        mta_finding = "Direct / internal submission (no transit relay recorded)."
    elif re.search(baseline["expected_outbound_mta"], first_hop, re.IGNORECASE):
        mta_match = True
        mta_status = "MATCH"
        mta_severity = "LOW"
        mta_finding = "Outbound server belongs to known brand infrastructure."
    elif expected_org and expected_org in first_hop.lower():
        mta_match = True
        mta_status = "MATCH"
        mta_severity = "LOW"
        mta_finding = f"Outbound relay belongs to domain infrastructure ('{expected_org}')."
    elif is_generic_baseline and re.search(COMMON_ENTERPRISE_RELAYS, first_hop, re.IGNORECASE):
        mta_match = True
        mta_status = "MATCH"
        mta_severity = "LOW"
        mta_finding = "Outbound relay routed through authorized enterprise mail infrastructure."
    else:
        mta_status = "ANOMALY"
        mta_severity = "MEDIUM"
        mta_finding = f"Transit server '{first_hop[:60]}' does not match standard brand mail cluster."

    hop_display = first_hop[:80] if first_hop else "Direct / Unreported"

    discrepancies.append({
        "checkpoint": "Outbound MTA Gateway",
        "legitimate_norm": f"Authorized brand MTAs ({baseline['brand_name']})",
        "suspect_actual": hop_display,
        "status": mta_status,
        "severity": mta_severity,
        "finding": mta_finding
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

