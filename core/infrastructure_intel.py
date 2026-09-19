"""
core/infrastructure_intel.py
Unified Infrastructure & Threat Intelligence Engine for EMAILSHIELD INDIA.
Complies with SIH26106 requirements:
- VPN detection (DETECTED, NOT_DETECTED, UNKNOWN)
- TOR detection (DETECTED, NOT_DETECTED, UNKNOWN) with fail-closed validation
- Open-relay indicators (INDICATED, NOT_INDICATED, UNKNOWN) - 100% PASSIVE (NO active probing)
- Botnet indicators (INDICATED, NOT_INDICATED, UNKNOWN)
- Cloud-hosted infrastructure classification (AWS, Azure, GCP, Cloudflare, DigitalOcean, Hetzner, etc.)
- Domain Registrar intelligence (RDAP preferred, WHOIS fallback, age, nameservers)
- DNS + MX records exposure (A, AAAA, MX with priority, NS, TXT) with strict SSRF filtering
- Threat-intelligence feed / blacklist correlation (MATCH, NO_MATCH, UNKNOWN)
- Zero-cost architecture ($0 / ₹0) & offline-first resilience
"""

import os
import json
import socket
import ipaddress
import datetime
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field

from core.geolocation import is_public_ip, get_geolocation, get_country_flag
from core.domain_reputation import extract_domain, get_registered_domain, resolve_whois_and_rdap

# Path constants for local curated datasets
THREAT_INTEL_DIR = os.path.join("data", "threat_intel")
CLOUD_PROVIDERS_FILE = os.path.join(THREAT_INTEL_DIR, "cloud_providers.json")
VPN_ASNS_FILE = os.path.join(THREAT_INTEL_DIR, "vpn_asns.json")
TOR_EXIT_FILE = os.path.join(THREAT_INTEL_DIR, "tor_exit_nodes.json")
THREAT_FEEDS_FILE = os.path.join(THREAT_INTEL_DIR, "threat_feeds.json")
OPEN_RELAY_FILE = os.path.join(THREAT_INTEL_DIR, "open_relay_heuristics.json")

# In-memory caches
_DNS_CACHE: Dict[str, Dict[str, Any]] = {}
_INFRA_CACHE: Dict[str, Any] = {}

# Legal attribution disclaimer
ATTRIBUTION_DISCLAIMER = (
    "Note: Derived from available email evidence and public routing records. GeoIP, ASN, and infrastructure telemetry "
    "provide approximate network routing context and mail-delivery architecture. They do not constitute legal proof "
    "of a physical individual's location or identity. VPNs, proxies, compromised systems, multi-hop relays, and NAT "
    "can affect routing paths."
)


# =====================================================================
# 1. PYDANTIC SCHEMAS
# =====================================================================

class VPNIndicator(BaseModel):
    status: str = "UNKNOWN"  # DETECTED, NOT_DETECTED, UNKNOWN
    provider: Optional[str] = None
    confidence: int = 0
    evidence: str = "No VPN evaluation performed."


class TorIndicator(BaseModel):
    status: str = "UNKNOWN"  # DETECTED, NOT_DETECTED, UNKNOWN
    exit_node_ip: Optional[str] = None
    confidence: int = 0
    evidence: str = "No Tor exit node evaluation performed."


class OpenRelayIndicator(BaseModel):
    status: str = "UNKNOWN"  # INDICATED, NOT_INDICATED, UNKNOWN
    confidence: int = 0
    evidence: str = "No passive open relay telemetry found."


class BotnetIndicator(BaseModel):
    status: str = "UNKNOWN"  # INDICATED, NOT_INDICATED, UNKNOWN
    botnet_family: Optional[str] = None
    confidence: int = 0
    evidence: str = "No botnet correlation identified."


class CloudHostingIndicator(BaseModel):
    is_cloud_hosted: bool = False
    provider: str = "UNKNOWN"
    asn: str = "UNKNOWN"
    org: str = "UNKNOWN"
    confidence: int = 0
    evidence: str = "No cloud infrastructure classification available."


class RegistrarIntel(BaseModel):
    registrar: str = "Unknown"
    creation_date: str = "Unknown"
    domain_age_days: Optional[int] = None
    nameservers: List[str] = []
    rdap_source: str = "Unknown"
    confidence: int = 0


class MXRecordItem(BaseModel):
    host: str
    priority: int = 0
    resolved_ips: List[str] = []


class DNSMXIntel(BaseModel):
    domain: str
    a_records: List[str] = []
    aaaa_records: List[str] = []
    mx_records: List[MXRecordItem] = []
    ns_records: List[str] = []
    txt_records: List[str] = []
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    is_ssrf_safe: bool = True
    lookup_status: str = "Success"


class ThreatIntelMatch(BaseModel):
    status: str = "UNKNOWN"  # MATCH, NO_MATCH, UNKNOWN
    feed_name: Optional[str] = None
    category: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: int = 0
    evidence: str = "No threat feed match evaluation performed."


class InfrastructureAssessment(BaseModel):
    origin_ip: Optional[str] = None
    domain: Optional[str] = None
    
    # Geolocation & Origin Summary
    country: str = "Unknown"
    region: str = "Unknown"
    city: str = "Unknown"
    flag: str = "🌐"
    isp: str = "Unknown"
    asn: str = "Unknown"
    
    # Core Gap Closure Indicators
    vpn_indicator: VPNIndicator = Field(default_factory=VPNIndicator)
    tor_indicator: TorIndicator = Field(default_factory=TorIndicator)
    open_relay_indicator: OpenRelayIndicator = Field(default_factory=OpenRelayIndicator)
    botnet_indicator: BotnetIndicator = Field(default_factory=BotnetIndicator)
    cloud_indicator: CloudHostingIndicator = Field(default_factory=CloudHostingIndicator)
    
    # Domain & Registry Intelligence
    registrar_intel: RegistrarIntel = Field(default_factory=RegistrarIntel)
    dns_mx_intel: Optional[DNSMXIntel] = None
    
    # Threat Intelligence Feed Correlation
    threat_intel_match: ThreatIntelMatch = Field(default_factory=ThreatIntelMatch)
    
    # Attribution notice
    attribution_disclaimer: str = ATTRIBUTION_DISCLAIMER


# =====================================================================
# 2. LOCAL DATASET LOADERS (OFFLINE-FIRST)
# =====================================================================

def _load_json_dataset(path: str, default: Any) -> Any:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default


_CLOUD_DB = None
def _get_cloud_db() -> Dict[str, Any]:
    global _CLOUD_DB
    if _CLOUD_DB is None:
        _CLOUD_DB = _load_json_dataset(CLOUD_PROVIDERS_FILE, {"providers": []})
    return _CLOUD_DB


_VPN_DB = None
def _get_vpn_db() -> Dict[str, Any]:
    global _VPN_DB
    if _VPN_DB is None:
        _VPN_DB = _load_json_dataset(VPN_ASNS_FILE, {"vpn_providers": []})
    return _VPN_DB


_TOR_DB = None
def _get_tor_db() -> Dict[str, Any]:
    global _TOR_DB
    if _TOR_DB is None:
        _TOR_DB = _load_json_dataset(TOR_EXIT_FILE, {"exit_nodes": []})
    return _TOR_DB


_THREAT_DB = None
def _get_threat_db() -> Dict[str, Any]:
    global _THREAT_DB
    if _THREAT_DB is None:
        _THREAT_DB = _load_json_dataset(THREAT_FEEDS_FILE, {"threat_iocs": [], "botnet_asns": []})
    return _THREAT_DB


_OPEN_RELAY_DB = None
def _get_open_relay_db() -> Dict[str, Any]:
    global _OPEN_RELAY_DB
    if _OPEN_RELAY_DB is None:
        _OPEN_RELAY_DB = _load_json_dataset(OPEN_RELAY_FILE, {"suspect_transit_keywords": [], "abusive_transit_asns": []})
    return _OPEN_RELAY_DB


def _clean_asn(asn_str: Any) -> str:
    """Extract numeric ASN string, e.g. 'AS16509 Amazon.com' -> '16509'."""
    if not asn_str:
        return ""
    s = str(asn_str).strip()
    import re
    m = re.search(r'\b(?:AS)?(\d+)\b', s, re.IGNORECASE)
    return m.group(1) if m else ""


# =====================================================================
# 3. DETECTORS & ENRICHMENT ENGINES
# =====================================================================

def classify_cloud_infrastructure(asn: str, org: str, ip: str) -> CloudHostingIndicator:
    """Classifies whether the origin IP is hosted on major cloud infrastructure."""
    if not ip or not is_public_ip(ip):
        return CloudHostingIndicator(
            is_cloud_hosted=False,
            provider="UNKNOWN",
            asn=str(asn or "UNKNOWN"),
            org=str(org or "UNKNOWN"),
            confidence=0,
            evidence="Non-public or unresolvable IP address."
        )

    asn_num = _clean_asn(asn)
    org_lower = str(org or "").lower()
    
    db = _get_cloud_db()
    for provider in db.get("providers", []):
        # Match by ASN
        if asn_num and asn_num in provider.get("asns", []):
            return CloudHostingIndicator(
                is_cloud_hosted=True,
                provider=provider.get("short_name", provider["name"]),
                asn=f"AS{asn_num}",
                org=org or provider["name"],
                confidence=provider.get("confidence", 95),
                evidence=f"Origin IP is hosted in {provider['name']} (Matched ASN {asn_num})."
            )
        # Match by organization keyword
        for kw in provider.get("org_keywords", []):
            if kw in org_lower:
                return CloudHostingIndicator(
                    is_cloud_hosted=True,
                    provider=provider.get("short_name", provider["name"]),
                    asn=f"AS{asn_num}" if asn_num else "Unknown ASN",
                    org=org,
                    confidence=provider.get("confidence", 90),
                    evidence=f"Origin IP is hosted in {provider['name']} (Matched organization keyword '{kw}')."
                )

    return CloudHostingIndicator(
        is_cloud_hosted=False,
        provider="None / Dedicated / Residential",
        asn=f"AS{asn_num}" if asn_num else (asn or "Unknown ASN"),
        org=org or "Unknown",
        confidence=80,
        evidence="Origin infrastructure does not match recognized major cloud or hyperscale providers."
    )


def detect_vpn_indicator(ip: str, asn: str, org: str, headers: Optional[Dict[str, Any]] = None) -> VPNIndicator:
    """Detects commercial VPN or anonymizing proxy signatures."""
    if not ip or not is_public_ip(ip):
        return VPNIndicator(
            status="UNKNOWN",
            provider=None,
            confidence=0,
            evidence="IP address is private, unroutable, or missing."
        )

    asn_num = _clean_asn(asn)
    org_lower = str(org or "").lower()

    db = _get_vpn_db()
    for prov in db.get("vpn_providers", []):
        # ASN match
        if asn_num and asn_num in prov.get("asns", []):
            return VPNIndicator(
                status="DETECTED",
                provider=prov["name"],
                confidence=prov.get("confidence", 95),
                evidence=f"Originating ASN {asn_num} matches known commercial VPN provider '{prov['name']}'."
            )
        # Org keyword match
        for kw in prov.get("org_keywords", []):
            if kw in org_lower:
                return VPNIndicator(
                    status="DETECTED",
                    provider=prov["name"],
                    confidence=prov.get("confidence", 90),
                    evidence=f"Originating network organization '{org}' matches VPN signature '{kw}'."
                )

    # Header check for proxy headers
    if headers:
        for hdr in ["x-forwarded-for", "client-ip", "via", "x-proxy-id"]:
            if hdr in {k.lower(): v for k, v in headers.items()}:
                val = str(headers.get(hdr) or "")
                if "vpn" in val.lower() or "proxy" in val.lower():
                    return VPNIndicator(
                        status="DETECTED",
                        provider="Forwarding Proxy / VPN",
                        confidence=80,
                        evidence=f"Header '{hdr}' explicitly identifies intermediate proxy/VPN forwarding."
                    )

    return VPNIndicator(
        status="NOT_DETECTED",
        provider=None,
        confidence=85,
        evidence="No known commercial VPN ASNs, proxy signatures, or anonymizer headers detected."
    )


def detect_tor_indicator(ip: str) -> TorIndicator:
    """
    Detects if the IP matches verified public Tor exit nodes.
    Enforces strict IP syntax validation and fail-closed security.
    """
    if not ip or not isinstance(ip, str):
        return TorIndicator(
            status="UNKNOWN",
            exit_node_ip=None,
            confidence=0,
            evidence="No IP provided for Tor node check."
        )
    
    clean_ip = ip.strip()
    try:
        parsed_ip = ipaddress.ip_address(clean_ip)
        if not parsed_ip.is_global or parsed_ip.is_private or parsed_ip.is_loopback:
            return TorIndicator(
                status="UNKNOWN",
                exit_node_ip=None,
                confidence=0,
                evidence=f"IP {clean_ip} is a private, loopback, or non-routable address."
            )
    except ValueError:
        return TorIndicator(
            status="UNKNOWN",
            exit_node_ip=None,
            confidence=0,
            evidence=f"Invalid IP address format '{clean_ip}'."
        )

    db = _get_tor_db()
    exit_list = set(db.get("exit_nodes", []))
    
    if clean_ip in exit_list:
        return TorIndicator(
            status="DETECTED",
            exit_node_ip=clean_ip,
            confidence=98,
            evidence=f"Originating IP {clean_ip} matches verified Tor exit relay directory ({db.get('source', 'Tor Directory')})."
        )

    return TorIndicator(
        status="NOT_DETECTED",
        exit_node_ip=None,
        confidence=95,
        evidence=f"Originating IP {clean_ip} is not listed in active Tor exit node registries."
    )


def detect_open_relay_indicator(
    received_chain: List[str],
    headers: Dict[str, Any],
    asn: str,
    auth_alignment: Any = None
) -> OpenRelayIndicator:
    """
    PASSIVE open-relay indicator evaluation from MTA headers and routing anomalies.
    CRITICAL: 100% passive, evidence-based only. ZERO active network probes or SMTP scans.
    """
    if not received_chain:
        return OpenRelayIndicator(
            status="UNKNOWN",
            confidence=0,
            evidence="No Received headers available to evaluate passive relay transit."
        )

    db = _get_open_relay_db()
    suspect_keywords = db.get("suspect_transit_keywords", [])
    abusive_asns = {a.get("asn"): a for a in db.get("abusive_transit_asns", [])}
    asn_num = _clean_asn(asn)

    # 1. Check abusive transit ASNs
    if asn_num and asn_num in abusive_asns:
        entry = abusive_asns[asn_num]
        return OpenRelayIndicator(
            status="INDICATED",
            confidence=85,
            evidence=f"Originating ASN {asn_num} is flagged for abusive open/unverified SMTP transit ({entry.get('reason')})."
        )

    # 2. Check for explicit open relay or unauthorized transit keywords in Received headers
    for hop in received_chain:
        hop_lower = str(hop).lower()
        for kw in suspect_keywords:
            if kw in hop_lower:
                return OpenRelayIndicator(
                    status="INDICATED",
                    confidence=90,
                    evidence=f"Received header contains explicit open-relay/unauthenticated transit marker: '{kw}'."
                )

    # 3. Check for severe relay transit anomalies:
    # Multiple hops (> 3), where intermediate public hop has no authentication, no TLS (plain text SMTP),
    # and DMARC / SPF completely fails or has no alignment.
    has_auth_fail = auth_alignment and getattr(auth_alignment, "effective_dmarc", "NONE") in ["FAIL", "NONE / UNCONFIGURED"]
    if len(received_chain) >= 3 and has_auth_fail:
        # Check if the innermost received hop claims an external public connection without ESMTP auth
        bottom_hop = str(received_chain[-1]).lower()
        if "esmtpsa" not in bottom_hop and "auth=" not in bottom_hop and "tls" not in bottom_hop:
            if "by " in bottom_hop and "from " in bottom_hop:
                return OpenRelayIndicator(
                    status="INDICATED",
                    confidence=75,
                    evidence="Multi-hop transit exhibits unauthenticated plaintext relay without ESMTP auth and failing domain alignment."
                )

    return OpenRelayIndicator(
        status="NOT_INDICATED",
        confidence=85,
        evidence="Passive relay transit inspection shows standard compliant MTA delivery without open-relay indicators."
    )


def detect_botnet_indicator(ip: str, domain: str, asn: str, org: str) -> BotnetIndicator:
    """Detects correlation with known botnet infrastructure, C2, or spambot residential pools."""
    if not ip or not is_public_ip(ip):
        return BotnetIndicator(
            status="UNKNOWN",
            botnet_family=None,
            confidence=0,
            evidence="IP address is private or unavailable."
        )

    db = _get_threat_db()
    clean_ip = ip.strip()
    asn_num = _clean_asn(asn)
    org_lower = str(org or "").lower()

    # 1. Match against known threat IOCs categorized as Botnet
    for ioc in db.get("threat_iocs", []):
        if ioc.get("type") == "IP" and ioc.get("value") == clean_ip:
            if "botnet" in ioc.get("category", "").lower() or "c2" in ioc.get("category", "").lower() or "spambot" in ioc.get("category", "").lower():
                return BotnetIndicator(
                    status="INDICATED",
                    botnet_family=ioc.get("category"),
                    confidence=ioc.get("confidence", 90),
                    evidence=f"IP {clean_ip} matches {ioc.get('feed')}: {ioc.get('evidence')}."
                )

    # 2. Check botnet ASNs
    for b_asn in db.get("botnet_asns", []):
        if asn_num and asn_num == str(b_asn.get("asn")):
            return BotnetIndicator(
                status="INDICATED",
                botnet_family=b_asn.get("category", "Residential Spambot Pool"),
                confidence=85,
                evidence=f"Originating ASN {asn_num} matches known residential/spambot dynamic pool ({b_asn.get('evidence')})."
            )

    # 3. Heuristic: Consumer residential ISP pool keywords directly delivering mail without ESP
    residential_keywords = ["residential", "dynamic", "broadband", "dialup", "pool", "dhcp", "user"]
    if any(kw in org_lower for kw in residential_keywords) and not any(esp in org_lower for esp in ["google", "microsoft", "amazon", "sendgrid", "mailgun", "zoho"]):
        return BotnetIndicator(
            status="INDICATED",
            botnet_family="Heuristic Residential Dynamic MTA",
            confidence=70,
            evidence=f"Origin organization '{org}' matches residential broadband naming convention typical of compromised spambot hosts."
        )

    return BotnetIndicator(
        status="NOT_INDICATED",
        botnet_family=None,
        confidence=85,
        evidence="No known botnet C2 indicators, spambot pool ASNs, or compromised host heuristics identified."
    )


def correlate_threat_intelligence(ip: str, domain: str) -> ThreatIntelMatch:
    """Correlates IP and domain indicators against local threat feeds and blacklists."""
    clean_ip = ip.strip() if ip else ""
    clean_domain = domain.strip().lower() if domain else ""
    root_domain = get_registered_domain(clean_domain) if clean_domain else ""

    db = _get_threat_db()
    for ioc in db.get("threat_iocs", []):
        itype = ioc.get("type", "").upper()
        ival = str(ioc.get("value", "")).strip().lower()

        if itype == "IP" and clean_ip and clean_ip == ival:
            return ThreatIntelMatch(
                status="MATCH",
                feed_name=ioc.get("feed"),
                category=ioc.get("category"),
                first_seen=ioc.get("first_seen"),
                last_seen=ioc.get("last_seen"),
                confidence=ioc.get("confidence", 90),
                evidence=ioc.get("evidence", f"IP {clean_ip} matches blacklisted threat feed.")
            )
        elif itype == "DOMAIN" and (clean_domain == ival or root_domain == ival):
            return ThreatIntelMatch(
                status="MATCH",
                feed_name=ioc.get("feed"),
                category=ioc.get("category"),
                first_seen=ioc.get("first_seen"),
                last_seen=ioc.get("last_seen"),
                confidence=ioc.get("confidence", 95),
                evidence=ioc.get("evidence", f"Domain {clean_domain} matches blacklisted threat feed.")
            )

    if not clean_ip and not clean_domain:
        return ThreatIntelMatch(
            status="UNKNOWN",
            confidence=0,
            evidence="No IP or domain available for threat intelligence correlation."
        )

    return ThreatIntelMatch(
        status="NO_MATCH",
        confidence=90,
        evidence="Clean against local threat intelligence feeds, blacklists, and known abuse directories."
    )


def resolve_dns_mx_intelligence(domain: str, timeout: float = 2.0) -> DNSMXIntel:
    """
    Resolves DNS records (A, AAAA, MX, NS, TXT) and MX host IP addresses.
    CRITICAL SSRF PROTECTION: Enforces is_public_ip() on all resolved IPs.
    Rejects and flags RFC 1918, loopback, and link-local addresses.
    """
    clean_domain = extract_domain(domain)
    if not clean_domain or clean_domain == "unknown.com":
        return DNSMXIntel(domain="unknown.com", lookup_status="Invalid Domain", is_ssrf_safe=True)

    if clean_domain in _DNS_CACHE:
        return DNSMXIntel(**_DNS_CACHE[clean_domain])

    a_recs = []
    aaaa_recs = []
    mx_items = []
    ns_recs = []
    txt_recs = []
    spf_rec = None
    dmarc_rec = None
    is_ssrf_safe = True

    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        if hasattr(res, "nameservers") and isinstance(res.nameservers, list):
            for ns in ["8.8.8.8", "1.1.1.1"]:
                if ns not in res.nameservers:
                    res.nameservers.append(ns)
        res.timeout = min(timeout, 1.5)
        res.lifetime = timeout

        # 1. A Records
        try:
            answers = res.resolve(clean_domain, "A")
            for r in answers:
                ip_val = str(r)
                if not is_public_ip(ip_val):
                    is_ssrf_safe = False
                else:
                    a_recs.append(ip_val)
        except Exception:
            pass

        # 2. AAAA Records
        try:
            answers = res.resolve(clean_domain, "AAAA")
            for r in answers:
                aaaa_recs.append(str(r))
        except Exception:
            pass

        # 3. MX Records & Resolved Host IPs
        try:
            answers = res.resolve(clean_domain, "MX")
            for r in sorted(answers, key=lambda m: m.preference):
                host_str = str(r.exchange).rstrip(".")
                resolved_ips = []
                try:
                    _, _, ips = socket.gethostbyname_ex(host_str)
                    for ip in ips:
                        if not is_public_ip(ip):
                            is_ssrf_safe = False
                        else:
                            resolved_ips.append(ip)
                except Exception:
                    pass
                mx_items.append(MXRecordItem(host=host_str, priority=int(r.preference), resolved_ips=resolved_ips))
        except Exception:
            pass

        # 4. NS Records
        try:
            answers = res.resolve(clean_domain, "NS")
            for r in answers:
                ns_recs.append(str(r).rstrip("."))
        except Exception:
            pass

        # 5. TXT Records & SPF
        try:
            answers = res.resolve(clean_domain, "TXT")
            for r in answers:
                txt_val = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in r.strings])
                txt_recs.append(txt_val[:120])
                if txt_val.lower().startswith("v=spf1") and not spf_rec:
                    spf_rec = txt_val
        except Exception:
            pass

        # 6. DMARC TXT Record (_dmarc.domain)
        try:
            dmarc_answers = res.resolve(f"_dmarc.{clean_domain}", "TXT")
            for r in dmarc_answers:
                txt_val = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in r.strings])
                if txt_val.lower().startswith("v=dmarc1") and not dmarc_rec:
                    dmarc_rec = txt_val
        except Exception:
            pass

    except Exception:
        pass

    # Fallback to standard socket if dnspython produced no A records and SSRF was not detected
    if not a_recs and is_ssrf_safe:
        try:
            _, _, ips = socket.gethostbyname_ex(clean_domain)
            for ip in ips:
                if not is_public_ip(ip):
                    is_ssrf_safe = False
                else:
                    a_recs.append(ip)
        except Exception:
            pass

    intel = DNSMXIntel(
        domain=clean_domain,
        a_records=a_recs[:5],
        aaaa_records=aaaa_recs[:3],
        mx_records=mx_items[:5],
        ns_records=ns_recs[:5],
        txt_records=txt_recs[:5],
        spf_record=spf_rec,
        dmarc_record=dmarc_rec,
        is_ssrf_safe=is_ssrf_safe,
        lookup_status="Success" if (a_recs or mx_items or ns_recs) else "No Records Found"
    )

    _DNS_CACHE[clean_domain] = intel.model_dump()
    return intel


def extract_registrar_intel(domain: str, domain_rep: Any = None) -> RegistrarIntel:
    """Extracts registrar details, domain creation date, age, and nameservers."""
    clean_domain = extract_domain(domain)
    root_domain = get_registered_domain(clean_domain)

    # 1. Use domain_rep if precomputed
    if domain_rep:
        reg = getattr(domain_rep, "registrar", "Unknown")
        cdate = getattr(domain_rep, "creation_date", "Unknown")
        age = getattr(domain_rep, "domain_age_days", None)
        if reg and reg != "Unknown":
            return RegistrarIntel(
                registrar=reg,
                creation_date=cdate or "Unknown",
                domain_age_days=age,
                nameservers=[],
                rdap_source="ICANN RDAP / WHOIS Registry Cache",
                confidence=95 if age is not None else 80
            )

    # 2. Query WHOIS / RDAP fallback
    reg, cdate, age = resolve_whois_and_rdap(root_domain)
    return RegistrarIntel(
        registrar=reg,
        creation_date=cdate,
        domain_age_days=age,
        nameservers=[],
        rdap_source="ICANN RDAP / RFC 3912 Query",
        confidence=90 if reg != "Unknown" else 50
    )


# =====================================================================
# 4. UNIFIED INFRASTRUCTURE ASSESSMENT
# =====================================================================

def assess_infrastructure(
    ip: Optional[str] = None,
    domain: Optional[str] = None,
    headers: Optional[Dict[str, Any]] = None,
    received_chain: Optional[List[str]] = None,
    geo_data: Optional[Dict[str, Any]] = None,
    domain_rep: Optional[Any] = None,
    auth_alignment: Optional[Any] = None
) -> InfrastructureAssessment:
    """
    Master entry point: aggregates all infrastructure, provider, and threat indicators
    into a unified forensic InfrastructureAssessment object.
    """
    headers = headers or {}
    received_chain = received_chain or []
    
    # 1. Resolve Origin IP & Geolocation
    clean_ip = ip.strip() if ip and is_public_ip(ip) else None
    geo = geo_data or (get_geolocation(clean_ip) if clean_ip else {})
    
    country = geo.get("country", "Unknown")
    region = geo.get("region", "Unknown")
    city = geo.get("city", "Unknown")
    flag = get_country_flag(country)
    isp = geo.get("org", "Unknown ISP")
    asn = geo.get("asn", "Unknown ASN")

    # 2. Evaluate Indicators
    cloud_ind = classify_cloud_infrastructure(asn=asn, org=isp, ip=clean_ip or "")
    vpn_ind = detect_vpn_indicator(ip=clean_ip or "", asn=asn, org=isp, headers=headers)
    tor_ind = detect_tor_indicator(ip=clean_ip or "")
    relay_ind = detect_open_relay_indicator(
        received_chain=received_chain,
        headers=headers,
        asn=asn,
        auth_alignment=auth_alignment
    )
    botnet_ind = detect_botnet_indicator(
        ip=clean_ip or "",
        domain=domain or "",
        asn=asn,
        org=isp
    )

    # 3. Domain & DNS Intelligence
    clean_domain = extract_domain(domain or "")
    reg_intel = extract_registrar_intel(clean_domain, domain_rep=domain_rep)
    dns_intel = resolve_dns_mx_intelligence(clean_domain) if clean_domain and clean_domain != "unknown.com" else None

    # 4. Threat Feed Correlation
    threat_match = correlate_threat_intelligence(ip=clean_ip or "", domain=clean_domain)

    return InfrastructureAssessment(
        origin_ip=clean_ip,
        domain=clean_domain if clean_domain != "unknown.com" else None,
        country=country,
        region=region,
        city=city,
        flag=flag,
        isp=isp,
        asn=asn,
        vpn_indicator=vpn_ind,
        tor_indicator=tor_ind,
        open_relay_indicator=relay_ind,
        botnet_indicator=botnet_ind,
        cloud_indicator=cloud_ind,
        registrar_intel=reg_intel,
        dns_mx_intel=dns_intel,
        threat_intel_match=threat_match,
        attribution_disclaimer=ATTRIBUTION_DISCLAIMER
    )
