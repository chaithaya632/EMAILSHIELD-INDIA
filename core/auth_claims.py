import re
from typing import Dict, Any, List, Optional

def extract_domain(email_address: str) -> str:
    """Extract domain from email address or header string."""
    if not email_address:
        return ""
    match = re.search(r'@([\w\.-]+)', email_address)
    if match:
        return match.group(1).lower().strip('.')
    return ""

def get_org_domain(domain: str) -> str:
    """Extract organizational base domain (e.g. sub.example.com -> example.com)."""
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def parse_auth_results(auth_header: str) -> List[Dict[str, str]]:
    """
    Parse Authentication-Results header to extract SPF, DKIM, DMARC claims.
    Maintains backward compatibility.
    """
    results = []
    if not auth_header:
        return results

    spf_match = re.search(r'spf=(pass|fail|neutral|softfail|none|permerror|temperror)', auth_header, re.IGNORECASE)
    if spf_match:
        results.append({
            "mechanism": "SPF",
            "result": spf_match.group(1).lower(),
            "evidence_source": "Authentication-Results Header"
        })

    dkim_match = re.search(r'dkim=(pass|fail|none|permerror|temperror)', auth_header, re.IGNORECASE)
    if dkim_match:
        results.append({
            "mechanism": "DKIM",
            "result": dkim_match.group(1).lower(),
            "evidence_source": "Authentication-Results Header"
        })

    dmarc_match = re.search(r'dmarc=(pass|fail|none|permerror|temperror)', auth_header, re.IGNORECASE)
    if dmarc_match:
        results.append({
            "mechanism": "DMARC",
            "result": dmarc_match.group(1).lower(),
            "evidence_source": "Authentication-Results Header"
        })

    return results

def evaluate_auth_and_alignment(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive Cryptographic Authentication & DMARC Alignment Verification.
    Validates Header-From domain against:
      - Envelope-From (Return-Path) domain for SPF alignment
      - DKIM signing domain (d= tag) for DKIM alignment
    Determines effective DMARC evaluation and flags SPF/DKIM bypass attacks.
    """
    from_header = ""
    return_path = ""
    auth_header = ""
    dkim_header = ""

    for k, v in headers.items():
        k_low = k.lower()
        val_str = " ".join(v) if isinstance(v, list) else str(v)
        if k_low == "from":
            from_header = val_str
        elif k_low == "return-path":
            return_path = val_str
        elif k_low == "authentication-results":
            auth_header = val_str
        elif k_low == "dkim-signature":
            dkim_header = val_str

    header_from_domain = extract_domain(from_header)
    envelope_from_domain = extract_domain(return_path)

    dkim_signing_domain = ""
    dkim_d_match = re.search(r'\bd=([\w\.-]+)', dkim_header, re.IGNORECASE)
    if dkim_d_match:
        dkim_signing_domain = dkim_d_match.group(1).lower()
    else:
        auth_d_match = re.search(r'header\.d=([\w\.-]+)', auth_header, re.IGNORECASE)
        if auth_d_match:
            dkim_signing_domain = auth_d_match.group(1).lower()

    auth_claims = parse_auth_results(auth_header)
    spf_result = "none"
    dkim_result = "none"
    dmarc_recorded = "none"

    for claim in auth_claims:
        mech = claim["mechanism"]
        res = claim["result"]
        if mech == "SPF":
            spf_result = res
        elif mech == "DKIM":
            dkim_result = res
        elif mech == "DMARC":
            dmarc_recorded = res

    received_spf = headers.get("received-spf", "")
    if spf_result == "none" and received_spf:
        rec_str = " ".join(received_spf) if isinstance(received_spf, list) else str(received_spf)
        spf_m = re.search(r'^(pass|fail|neutral|softfail|none)', rec_str.strip(), re.IGNORECASE)
        if spf_m:
            spf_result = spf_m.group(1).lower()

    # SPF Alignment (Relaxed)
    spf_aligned = False
    if header_from_domain and envelope_from_domain:
        spf_aligned = (header_from_domain == envelope_from_domain) or (
            get_org_domain(header_from_domain) == get_org_domain(envelope_from_domain)
        )

    # DKIM Alignment (Relaxed)
    dkim_aligned = False
    if header_from_domain and dkim_signing_domain:
        dkim_aligned = (header_from_domain == dkim_signing_domain) or (
            get_org_domain(header_from_domain) == get_org_domain(dkim_signing_domain)
        )

    # Check if this email is a recognized newsletter or bulk mailing
    is_bulk_newsletter = bool(
        headers.get("list-unsubscribe") or
        headers.get("list-id") or
        str(headers.get("precedence", "")).lower() == "bulk" or
        headers.get("feedback-id")
    )

    # Known legitimate ESP domains that send on behalf of creators / organizations
    KNOWN_LEGIT_ESPS = {
        "sendgrid.net", "mailgun.org", "substack.com", "convertkit.com", "beehiiv.com",
        "mailchimp.com", "mcsv.net", "mcdlv.net", "amazonses.com", "brevo.com",
        "hubspot.com", "hubspotemail.net", "klaviyo.com", "activehosted.com",
        "sparkpostmail.com", "constantcontact.com", "campaignmonitor.com", "cmail1.com",
        "cmail2.com", "acems1.com", "acems2.com", "intercom-mail.com", "mailerlite.com",
        "postmarkapp.com", "infusionsoft.com", "dripemail2.com"
    }

    is_esp_delegated = any(
        dkim_signing_domain.endswith(esp) or envelope_from_domain.endswith(esp)
        for esp in KNOWN_LEGIT_ESPS
    )

    # Effective DMARC Verdict
    spf_valid_for_dmarc = (spf_result == "pass" and spf_aligned)
    dkim_valid_for_dmarc = (dkim_result == "pass" and dkim_aligned)
    
    if dmarc_recorded == "pass" or spf_valid_for_dmarc or dkim_valid_for_dmarc:
        effective_dmarc = "PASS"
        dmarc_reason = "Email passed cryptographic authentication aligned with visible From domain."
        threat_detected = False
    elif dmarc_recorded == "fail":
        effective_dmarc = "FAIL"
        dmarc_reason = "Authentication-Results header records explicit DMARC failure."
        threat_detected = True
    elif (spf_result == "pass" or dkim_result == "pass") and (is_bulk_newsletter or is_esp_delegated):
        # Legitimate newsletter or creator update sent via authorized third-party ESP
        effective_dmarc = "PASS (Delegated ESP)"
        dmarc_reason = f"Authorized bulk email/newsletter delivery via Email Service Provider ('{dkim_signing_domain or envelope_from_domain}')."
        threat_detected = False
    elif (spf_result == "pass" or dkim_result == "pass") and not (spf_aligned or dkim_aligned):
        effective_dmarc = "FAIL (Alignment Bypass)"
        dmarc_reason = (
            f"Sender passed SPF/DKIM on third-party domain "
            f"(Envelope: '{envelope_from_domain or 'N/A'}', DKIM-d: '{dkim_signing_domain or 'N/A'}'), "
            f"but domain is unaligned with visible Header-From ('{header_from_domain}')."
        )
        threat_detected = True
    elif spf_result == "fail" or dkim_result == "fail":
        effective_dmarc = "FAIL"
        dmarc_reason = "Cryptographic signature or SPF verification explicitly failed."
        threat_detected = True
    else:
        effective_dmarc = "NONE / UNCONFIGURED"
        dmarc_reason = "No valid SPF/DKIM cryptographic records published or available."
        threat_detected = False

    advisories = []
    if threat_detected:
        advisories.append("⚠️ Potential Domain Spoofing: Visible sender differs from cryptographic signing identity.")
    if spf_result == "pass" and not spf_aligned and envelope_from_domain:
        advisories.append(f"ℹ️ SPF Passed for '{envelope_from_domain}', but NOT for Header-From '{header_from_domain}'.")
    if dkim_result == "pass" and not dkim_aligned and dkim_signing_domain:
        advisories.append(f"ℹ️ DKIM Passed for '{dkim_signing_domain}', but NOT for Header-From '{header_from_domain}'.")

    return {
        "header_from_domain": header_from_domain,
        "envelope_from_domain": envelope_from_domain,
        "dkim_signing_domain": dkim_signing_domain,
        "spf_result": spf_result.upper(),
        "dkim_result": dkim_result.upper(),
        "dmarc_recorded": dmarc_recorded.upper(),
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "effective_dmarc": effective_dmarc,
        "dmarc_reason": dmarc_reason,
        "threat_detected": threat_detected,
        "advisories": advisories
    }

