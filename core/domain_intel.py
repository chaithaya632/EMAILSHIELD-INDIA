"""
core/domain_intel.py
Inspected Domain Intelligence (MVI) for EMAILSHIELD INDIA.

Inspects all domains found across email identity headers, URLs, visible anchors,
QR code destinations, and attachment metadata to provide structured,
evidence-backed domain intelligence and role classification.
"""

import re
import socket
import urllib.parse
import ipaddress
from typing import Dict, Any, List, Optional, Set, Tuple

from core.schemas import DomainRole, DomainVerdict, InspectedDomain
from core.indicators import (
    extract_urls,
    extract_anchor_spoofs,
    get_registrable_domain,
    refang_ioc,
    refang_url,
    INTRA_ORG_PAIRS
)
from core.lookalike import (
    detect_lookalike_domain,
    MONITORED_BRANDS,
    OFFICIAL_EXEMPT_DOMAINS
)
from core.domain_reputation import (
    KNOWN_REPUTABLE_DOMAINS,
    OFFICIAL_BRAND_DOMAINS,
    resolve_whois_and_rdap
)
from core.url_forensics import is_verified_service, SHORTENER_DOMAINS

# Authoritative recognized third-party ESP / bulk delivery infrastructure
KNOWN_ESP_DOMAINS = {
    "sendgrid.net", "sendgrid.com", "mailchimp.com", "list-manage.com",
    "convertkit.com", "convertkit-mail.com", "ck.page", "substack.com",
    "beehiiv.com", "hubspot.com", "hubspotlinks.com", "salesforce.com",
    "exacttarget.com", "awstrack.me", "amazonses.com", "createsend.com",
    "klaviyo.com", "mandrillapp.com", "sparkpostmail.com", "brevo.com",
    "sendinblue.com", "constantcontact.com", "postmarkapp.com", "intercom-mail.com",
    "sparkpost.com", "mailgun.org", "mailgun.net", "mailjet.com"
}

# Sensitive financial, institutional, cloud, and logistics brands
SENSITIVE_TARGET_BRANDS = {
    "microsoft", "office", "live", "outlook", "google", "gmail", "apple", "icloud",
    "paypal", "chase", "wellsfargo", "bankofamerica", "citi", "sbi", "hdfc", "icici",
    "axisbank", "kotak", "pnbindia", "incometax", "dhl", "fedex", "ups", "amazon",
    "netflix", "dropbox", "onedrive"
}


def normalize_domain(raw: str) -> Optional[str]:
    """
    Normalizes a domain or URL candidate into a clean, lowercased FQDN or IP string.
    Handles security defanging (hxxps://, [.], etc.), strips schemes, paths,
    ports, query parameters, fragments, and userinfo.
    """
    if not raw or not isinstance(raw, str):
        return None

    clean = refang_ioc(raw.strip())

    # Strip scheme if present
    if "://" in clean:
        try:
            parsed = urllib.parse.urlparse(clean)
            clean = parsed.netloc or parsed.path
        except Exception:
            clean = clean.split("://", 1)[1].split("/")[0]

    # If email address pattern (user@domain.com), extract domain part
    if "@" in clean:
        clean = clean.split("@")[-1]

    # Strip path, query, fragment
    clean = clean.split("/")[0].split("?")[0].split("#")[0]

    # Strip port if present
    clean = clean.split(":")[0]

    # Clean whitespace and brackets/quotes
    clean = clean.lower().strip(" \t\r\n'\"<>[](){},;:")
    clean = clean.rstrip(".")

    if not clean or "." not in clean:
        return None

    # Check for direct IPv4 address
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', clean):
        parts = clean.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return clean
        return None

    parts = clean.split(".")
    if len(parts) < 2:
        return None

    # Ensure TLD is alphabetic or IDN/punycode
    tld = parts[-1]
    if not (tld.isalpha() or tld.startswith("xn--")):
        return None

    if len(tld) < 2:
        return None

    # Validate each label
    for part in parts:
        if not part or len(part) > 63:
            return None
        if not re.match(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$', part):
            return None

    return clean


def extract_header_domain(header_val: Any) -> Optional[str]:
    """Safely extracts a clean domain from an email header string."""
    if not header_val:
        return None
    val_str = " ".join(header_val) if isinstance(header_val, list) else str(header_val)
    match = re.search(r'<([^>]+)>', val_str)
    addr = match.group(1) if match else val_str
    addr = addr.strip().strip('"\' ')
    if "@" in addr:
        dom = addr.split("@")[-1].strip()
        return normalize_domain(dom)
    return normalize_domain(addr)


def extract_dkim_domains(headers: Dict[str, Any]) -> List[str]:
    """Extracts unique DKIM signing domains from DKIM-Signature and Authentication-Results."""
    dkim_doms = []

    def _get_vals(k: str) -> List[str]:
        val = headers.get(k.lower(), "")
        if isinstance(val, list):
            return [str(v) for v in val if v]
        elif val:
            return [str(val)]
        return []

    # From DKIM-Signature: d=...
    for val in _get_vals("dkim-signature"):
        match = re.search(r'\bd=([\w\.-]+)', val, re.IGNORECASE)
        if match:
            d = normalize_domain(match.group(1))
            if d:
                dkim_doms.append(d)

    # From Authentication-Results: header.d=...
    for val in _get_vals("authentication-results"):
        match = re.search(r'header\.d=([\w\.-]+)', val, re.IGNORECASE)
        if match:
            d = normalize_domain(match.group(1))
            if d:
                dkim_doms.append(d)

    return list(dict.fromkeys(dkim_doms))


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Checks if a string is an IP address residing in private/reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False


def extract_all_domains_with_roles(parsed_email: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Extracts all domains found across email identity headers, URLs, visible anchors,
    QR code destinations, and attachment metadata. Deduplicates by normalized FQDN
    and accumulates multiple roles and occurrence counts.
    """
    domains_map: Dict[str, Dict[str, Any]] = {}

    def _add_domain(raw_dom: Optional[str], role: DomainRole, displayed_anchor: Optional[str] = None):
        dom = normalize_domain(raw_dom)
        if not dom:
            return
        if dom not in domains_map:
            reg_dom = get_registrable_domain(dom) or dom
            domains_map[dom] = {
                "domain": dom,
                "registrable_domain": reg_dom,
                "roles": set(),
                "occurrence_count": 0,
                "displayed_anchors": set()
            }
        domains_map[dom]["roles"].add(role)
        domains_map[dom]["occurrence_count"] += 1
        if displayed_anchor:
            domains_map[dom]["displayed_anchors"].add(displayed_anchor)

    headers = parsed_email.get("headers", {})
    body = parsed_email.get("body", "")

    # 1. Identity Headers
    from_dom = extract_header_domain(headers.get("from", ""))
    if from_dom:
        _add_domain(from_dom, DomainRole.SENDER_IDENTITY)

    reply_to_dom = extract_header_domain(headers.get("reply-to", ""))
    if reply_to_dom:
        _add_domain(reply_to_dom, DomainRole.REPLY_TO)

    return_path_dom = extract_header_domain(headers.get("return-path", ""))
    if return_path_dom:
        _add_domain(return_path_dom, DomainRole.RETURN_PATH)

    for dkim_dom in extract_dkim_domains(headers):
        _add_domain(dkim_dom, DomainRole.DKIM)

    # 2. Body Hyperlinks
    for url in extract_urls(body):
        _add_domain(url, DomainRole.URL_DESTINATION)

    # 3. Visible Link Anchors
    anchor_spoofs = extract_anchor_spoofs(body)
    for sp in anchor_spoofs:
        disp = sp.get("displayed_domain")
        act = sp.get("actual_domain")
        if disp:
            _add_domain(disp, DomainRole.VISIBLE_ANCHOR)
        if act:
            _add_domain(act, DomainRole.URL_DESTINATION, displayed_anchor=disp)

    # 4. QR Code Decoded Destinations
    quishing_findings = parsed_email.get("quishing_findings", [])
    if not quishing_findings and (parsed_email.get("attachments") or parsed_email.get("html_body")):
        try:
            from core.quishing import scan_for_quishing
            quishing_findings = scan_for_quishing(
                parsed_email.get("attachments", []),
                parsed_email.get("html_body", "")
            )
        except Exception:
            quishing_findings = []

    for q in quishing_findings:
        q_url = q.get("decoded_url") or q.get("url")
        if q_url:
            _add_domain(q_url, DomainRole.QR_DESTINATION)

    # 5. Attachment Metadata
    for att in parsed_email.get("attachments", []):
        for emb in att.get("embedded_urls", []) + att.get("domains", []):
            _add_domain(emb, DomainRole.ATTACHMENT_METADATA)

    # 6. Third-Party Infrastructure Tagging
    for dom, data in domains_map.items():
        reg_dom = data["registrable_domain"]
        is_sender = DomainRole.SENDER_IDENTITY in data["roles"]
        if reg_dom in KNOWN_ESP_DOMAINS or (is_verified_service(dom) and not is_sender and reg_dom not in OFFICIAL_BRAND_DOMAINS):
            data["roles"].add(DomainRole.THIRD_PARTY_INFRASTRUCTURE)

    return domains_map


def inspect_domain(
    domain: str,
    roles: List[DomainRole],
    occurrence_count: int = 1,
    auth_alignment: Optional[Dict[str, Any]] = None,
    content_type: Optional[str] = None,
    sender_domain: Optional[str] = None,
    displayed_anchor_map: Optional[Dict[str, Set[str]]] = None,
    per_scan_cache: Optional[Dict[str, InspectedDomain]] = None,
    skip_network: bool = False
) -> InspectedDomain:
    """
    Performs multi-tiered forensic domain inspection.
    Integrates RDAP/WHOIS, DNS A records, lookalike detection, brand alignment,
    and third-party infrastructure context into an evidence-backed DomainVerdict.
    """
    if per_scan_cache is not None and domain in per_scan_cache:
        cached = per_scan_cache[domain]
        # Update occurrence count and roles if needed
        merged_roles = list(dict.fromkeys(cached.roles + roles))
        return cached.model_copy(update={
            "occurrence_count": cached.occurrence_count + occurrence_count - 1,
            "roles": merged_roles
        })

    reg_dom = get_registrable_domain(domain) or domain
    risk_signals: List[str] = []
    evidence_references: List[str] = []

    # 1. Registration Intelligence (RDAP / WHOIS)
    rdap_available = False
    registration_date = "Unknown"
    domain_age_days: Optional[int] = None
    registrar = "Unknown"
    is_nrd = False

    lookup_target = domain if domain in KNOWN_REPUTABLE_DOMAINS else (
        reg_dom if reg_dom in KNOWN_REPUTABLE_DOMAINS else None
    )

    if lookup_target:
        info = KNOWN_REPUTABLE_DOMAINS[lookup_target]
        rdap_available = True
        registration_date = info.get("created", "2000-01-01")
        registrar = info.get("reg", "Verified Registrar")
        domain_age_days = info.get("age", 5000)
        is_nrd = False
        evidence_references.append(f"Pre-verified reputable domain ({domain_age_days} days old | Registrar: {registrar})")
    elif not skip_network:
        try:
            reg, cdate, age = resolve_whois_and_rdap(reg_dom if reg_dom != domain else domain)
            if reg != "Unknown" or cdate != "Unknown":
                rdap_available = True
                registrar = reg
                registration_date = cdate
                domain_age_days = age
                if domain_age_days is not None:
                    if domain_age_days < 30:
                        is_nrd = True
                        risk_signals.append(f"Newly Registered Domain (NRD): Registered {domain_age_days} days ago")
                        evidence_references.append(f"Registered {domain_age_days} days ago (NRD)")
                    elif domain_age_days < 180:
                        risk_signals.append(f"Young Domain: Registered {domain_age_days} days ago")
                        evidence_references.append(f"Young domain ({domain_age_days} days old)")
                    else:
                        evidence_references.append(f"Established domain ({domain_age_days} days old | Registrar: {registrar})")
        except Exception:
            rdap_available = False

    # 2. DNS Intelligence
    dns_resolved = False
    resolved_ips: List[str] = []
    is_private = False

    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain):
        dns_resolved = True
        resolved_ips = [domain]
        if is_private_or_reserved_ip(domain):
            is_private = True
            risk_signals.append("Private / reserved IP address destination (RFC 1918 / loopback)")
            evidence_references.append(f"Host '{domain}' is a private or reserved IP address")
        else:
            evidence_references.append(f"Direct public numeric IP host: {domain}")
    elif not skip_network:
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2.5)
            try:
                _, _, ips = socket.gethostbyname_ex(domain)
                dns_resolved = True
                resolved_ips = ips[:5]
                evidence_references.append(f"DNS A record verified ({len(ips)} IP addresses)")
                if any(is_private_or_reserved_ip(ip) for ip in ips):
                    is_private = True
                    risk_signals.append("DNS resolves to private / reserved IP range")
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.gaierror, socket.timeout, OSError):
            dns_resolved = False
            risk_signals.append("DNS A query unresolvable")
            evidence_references.append("DNS A record query unresolvable")

    # 3. Lookalike Analysis
    lookalike_res = detect_lookalike_domain(domain)
    is_lookalike = bool(lookalike_res.get("is_lookalike", False))
    lookalike_technique = lookalike_res.get("technique") if is_lookalike else None
    impersonated_brand = lookalike_res.get("impersonated_brand") if is_lookalike else None
    similarity_score = float(lookalike_res.get("similarity_score", 0.0)) if is_lookalike else 0.0

    if is_lookalike:
        risk_signals.append(
            f"Lookalike detected ({lookalike_technique}) targeting '{impersonated_brand}' "
            f"(Similarity: {similarity_score}%)"
        )
        evidence_references.append(
            f"Lookalike technique: {lookalike_technique} mimicking '{impersonated_brand}'"
        )

    # 4. Identity & Brand Alignment
    sender_root = get_registrable_domain(sender_domain) if sender_domain else ""
    is_sender_aligned = bool(
        sender_root and (
            sender_root == reg_dom or
            (sender_root, reg_dom) in INTRA_ORG_PAIRS or
            (reg_dom, sender_root) in INTRA_ORG_PAIRS
        )
    )
    if is_sender_aligned:
        evidence_references.append(f"Sender-aligned domain ('{sender_root}')")

    is_auth_aligned = False
    auth_ok = False
    if auth_alignment:
        eff_dmarc = auth_alignment.get("effective_dmarc", "")
        auth_ok = eff_dmarc in ["PASS", "PASS (Delegated ESP)"]
        dkim_signing = auth_alignment.get("dkim_signing_domain", "")
        envelope_from = auth_alignment.get("envelope_from_domain", "")
        dkim_root = get_registrable_domain(dkim_signing) if dkim_signing else ""
        env_root = get_registrable_domain(envelope_from) if envelope_from else ""

        if auth_ok and (is_sender_aligned or (dkim_root and dkim_root == reg_dom) or (env_root and env_root == reg_dom)):
            is_auth_aligned = True
            evidence_references.append(f"Authenticated email dispatch (DMARC: {eff_dmarc})")

    is_claimed_brand_aligned = False
    for brand, legit_doms in OFFICIAL_BRAND_DOMAINS.items():
        if domain in legit_doms or any(domain.endswith("." + ld) for ld in legit_doms) or reg_dom in legit_doms:
            is_claimed_brand_aligned = True
            evidence_references.append(f"Verified official brand domain for '{brand.upper()}'")
            break

    # 5. Third-Party Infrastructure Context
    is_esp_infrastructure = (
        DomainRole.THIRD_PARTY_INFRASTRUCTURE in roles or
        reg_dom in KNOWN_ESP_DOMAINS or
        is_verified_service(domain)
    )
    if is_esp_infrastructure:
        evidence_references.append("Recognized bulk email delivery / tracking infrastructure")

    # 6. Verdict Decision Engine (Conservative & Deterministic)
    verdict = DomainVerdict.UNKNOWN

    # Check anchor spoofing map if this domain is a destination
    displayed_anchors = (displayed_anchor_map or {}).get(domain, set())
    has_sensitive_anchor_spoof = False
    for disp in displayed_anchors:
        disp_root = get_registrable_domain(disp) or disp
        is_sensitive = any(b in disp_root for b in SENSITIVE_TARGET_BRANDS)
        is_brand_dest_aligned = bool(disp_root and (disp_root in reg_dom or reg_dom in disp_root))
        is_sender_brand_aligned = bool(sender_root and (disp_root in sender_root or sender_root in disp_root))
        if is_sensitive and not is_brand_dest_aligned and not is_sender_brand_aligned and not is_sender_aligned:
            has_sensitive_anchor_spoof = True
            risk_signals.append(f"Adversary masked sensitive brand '{disp_root}' using unrelated target '{domain}'")
            evidence_references.append(f"Visible anchor displayed '{disp_root}' while link routes to '{domain}'")
            break

    # Rule 1: Confirmed strong brand lookalike / impersonation
    if is_lookalike and (
        lookalike_technique in [
            "Punycode (IDN Homograph Attack)",
            "Homoglyph Character Substitution",
            "Combo-squatting / Brand Affix Impersonation"
        ] or similarity_score >= 80.0
    ):
        verdict = DomainVerdict.LOOKALIKE_IMPERSONATION

    # Rule 2: Strong malicious alignment mismatch (Sensitive Brand Target Masking)
    elif has_sensitive_anchor_spoof:
        verdict = DomainVerdict.HIGH_RISK

    # Rule 3: Newly Registered Domain (< 30 days) on unestablished domain
    elif is_nrd and not lookup_target and not is_claimed_brand_aligned:
        verdict = DomainVerdict.SUSPICIOUS

    # Rule 4: Established / official / aligned corporate domain
    elif (
        is_sender_aligned or
        is_claimed_brand_aligned or
        domain in KNOWN_REPUTABLE_DOMAINS or
        reg_dom in KNOWN_REPUTABLE_DOMAINS or
        domain in OFFICIAL_EXEMPT_DOMAINS
    ):
        verdict = DomainVerdict.LIKELY_LEGITIMATE

    # Rule 5: Known third-party infrastructure / ESP
    elif is_esp_infrastructure and not is_lookalike:
        verdict = DomainVerdict.THIRD_PARTY_INFRASTRUCTURE

    # Rule 6: Other supporting suspicious evidence
    elif (DomainRole.URL_DESTINATION in roles) and (not dns_resolved) and (not is_private):
        verdict = DomainVerdict.SUSPICIOUS

    elif is_lookalike:
        verdict = DomainVerdict.SUSPICIOUS

    elif is_private:
        verdict = DomainVerdict.SUSPICIOUS

    # Rule 7: Insufficient evidence
    else:
        verdict = DomainVerdict.UNKNOWN

    # Deduplicate evidence references
    evidence_references = list(dict.fromkeys(evidence_references))

    result = InspectedDomain(
        domain=domain,
        registrable_domain=reg_dom,
        roles=sorted(list(set(roles)), key=lambda r: str(r.value)),
        occurrence_count=occurrence_count,
        rdap_available=rdap_available,
        registration_date=registration_date,
        domain_age_days=domain_age_days,
        registrar=registrar,
        is_nrd=is_nrd,
        dns_resolved=dns_resolved,
        resolved_ips=resolved_ips,
        is_sender_aligned=is_sender_aligned,
        is_auth_aligned=is_auth_aligned,
        is_claimed_brand_aligned=is_claimed_brand_aligned,
        is_lookalike=is_lookalike,
        lookalike_technique=lookalike_technique,
        impersonated_brand=impersonated_brand,
        similarity_score=similarity_score,
        risk_signals=risk_signals,
        verdict=verdict,
        evidence_references=evidence_references
    )

    if per_scan_cache is not None:
        per_scan_cache[domain] = result

    return result


def evaluate_email_domains(
    parsed_email: Dict[str, Any],
    auth_alignment: Optional[Dict[str, Any]] = None,
    content_type: Optional[str] = None,
    skip_network: bool = False
) -> List[InspectedDomain]:
    """
    Evaluates all domains found within an email message.
    Extracts, normalizes, deduplicates, and inspects domains once per scan using
    a per-scan cache. Returns a structured List[InspectedDomain].
    """
    raw_domains = extract_all_domains_with_roles(parsed_email)
    per_scan_cache: Dict[str, InspectedDomain] = {}

    headers = parsed_email.get("headers", {})
    sender_dom = extract_header_domain(headers.get("from", ""))

    # Prepare displayed anchor mapping
    displayed_anchor_map: Dict[str, Set[str]] = {}
    for d_name, d_meta in raw_domains.items():
        if d_meta["displayed_anchors"]:
            displayed_anchor_map[d_name] = d_meta["displayed_anchors"]

    inspected_results: List[InspectedDomain] = []

    for d_name, d_meta in raw_domains.items():
        res = inspect_domain(
            domain=d_name,
            roles=list(d_meta["roles"]),
            occurrence_count=d_meta["occurrence_count"],
            auth_alignment=auth_alignment,
            content_type=content_type,
            sender_domain=sender_dom,
            displayed_anchor_map=displayed_anchor_map,
            per_scan_cache=per_scan_cache,
            skip_network=skip_network
        )
        inspected_results.append(res)

    # Sort deterministically: SENDER_IDENTITY first, then by occurrence count descending, then domain name
    def _sort_key(item: InspectedDomain):
        has_sender = 0 if DomainRole.SENDER_IDENTITY in item.roles else 1
        return (has_sender, -item.occurrence_count, item.domain)

    inspected_results.sort(key=_sort_key)
    return inspected_results
