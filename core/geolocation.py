import ipaddress
import os
import datetime
import re
from typing import Dict, Any, Optional, Tuple, List
import requests

__all__ = [
    "get_geolocation",
    "get_sender_location",
    "is_public_ip",
    "derive_authoritative_location",
    "extract_originating_sender_ip",
    "extract_originating_sender_telemetry",
    "resolve_hostname_supplementary",
]

# Supported local offline databases
MMDB_CANDIDATES = [
    os.path.join("data", "geoip", "GeoLite2-City.mmdb"),
    os.path.join("data", "geoip", "dbip-city-lite.mmdb"),
    os.path.join("data", "geoip", "dbip-country-lite.mmdb"),
    os.path.join("data", "geoip", "GeoLite2-Country.mmdb")
]

_GEO_CACHE: Dict[str, Dict[str, Any]] = {}
_READER = None
_DB_INFO = {"provider": "None", "version": "None"}

def _get_reader():
    """Lazily load the MMDB reader if available."""
    global _READER, _DB_INFO
    if _READER is not None:
        return _READER
    
    import geoip2.database
    for path in MMDB_CANDIDATES:
        if os.path.exists(path):
            try:
                reader = geoip2.database.Reader(path)
                meta = reader.metadata()
                build_time = datetime.datetime.fromtimestamp(
                    meta.build_epoch, tz=datetime.timezone.utc
                ).strftime("%Y-%m-%d")
                _DB_INFO = {
                    "provider": f"MaxMind {meta.database_type}",
                    "version": f"v{build_time}"
                }
                _READER = reader
                return _READER
            except Exception:
                continue
    return None

def is_public_ip(ip_str: str) -> bool:
    """Check if the IP is a valid public routable address."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_reserved and not ip.is_link_local
    except ValueError:
        return False

def get_geolocation(ip_str: str) -> Dict[str, Any]:
    """
    Resolve high-accuracy geolocation for an IP address.
    Uses offline MaxMind GeoLite2 City database combined with live open-source enrichment
    to provide exact Country, Region/State, City, Lat/Long, and ISP/Organization.
    """
    cleaned_ip = ip_str.strip() if isinstance(ip_str, str) else ""
    
    if cleaned_ip in _GEO_CACHE:
        return _GEO_CACHE[cleaned_ip]

    # Handle non-public / internal / reserved IPs
    if not is_public_ip(cleaned_ip):
        res = {
            "ip": cleaned_ip,
            "country": "Local / Private Network",
            "region": "Internal",
            "city": "Internal Infrastructure",
            "latitude": None,
            "longitude": None,
            "org": "Private / RFC 1918 / Loopback",
            "asn": "None",
            "db_provider": "RFC Standard",
            "db_version": "N/A",
            "status": "Private/Reserved IP"
        }
        _GEO_CACHE[cleaned_ip] = res
        return res

    country = "UNKNOWN"
    region = "UNKNOWN"
    city = "UNKNOWN"
    lat = None
    lon = None
    org = "UNKNOWN"
    asn = "UNKNOWN"
    db_provider = "MaxMind GeoLite2 City"
    db_version = "2026.09 (Offline)"
    status = "Success"

    # Step 1: Query local offline MMDB
    reader = _get_reader()
    if reader:
        try:
            db_provider = _DB_INFO.get("provider", "MaxMind GeoLite2")
            db_version = _DB_INFO.get("version", "Offline MMDB")
            
            # Try city lookup
            try:
                c = reader.city(cleaned_ip)
                country = c.country.name or c.registered_country.name or "UNKNOWN"
                if c.subdivisions.most_specific.name:
                    region = c.subdivisions.most_specific.name
                if c.city.name:
                    city = c.city.name
                if c.location.latitude is not None:
                    lat = float(c.location.latitude)
                if c.location.longitude is not None:
                    lon = float(c.location.longitude)
            except AttributeError:
                # If database only supports country
                c = reader.country(cleaned_ip)
                country = c.country.name or c.registered_country.name or "UNKNOWN"
        except Exception as e:
            status = f"MMDB error: {str(e)}"

    # Step 2: Live enrichment for exact city/region/ISP if city is unknown or offline DB was coarse
    # Enforces HTTPS and respects optional zero-outbound environment guard
    if (city == "UNKNOWN" or region == "UNKNOWN" or country == "UNKNOWN") and os.environ.get("ENABLE_LIVE_GEOIP", "1").lower() in ("1", "true"):
        try:
            resp = requests.get(
                f"https://ip-api.com/json/{cleaned_ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query",
                timeout=2.0
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    country = data.get("country") or country
                    region = data.get("regionName") or region
                    city = data.get("city") or city
                    if data.get("lat") is not None:
                        lat = float(data["lat"])
                    if data.get("lon") is not None:
                        lon = float(data["lon"])
                    org = data.get("org") or data.get("isp") or org
                    asn = data.get("as") or asn
                    db_provider = f"{db_provider} + IP-API Live" if reader else "IP-API Open-Source Resolver"
                    db_version = "Exact City-Level v2.1"
                    status = "Success (Enriched)"
        except Exception:
            pass  # Fall back gracefully to MMDB results

    res = {
        "ip": cleaned_ip,
        "country": country,
        "region": region,
        "city": city,
        "latitude": lat,
        "longitude": lon,
        "org": org,
        "asn": asn,
        "db_provider": db_provider,
        "db_version": db_version,
        "status": status
    }
    
    _GEO_CACHE[cleaned_ip] = res
    return res

COUNTRY_FLAGS = {
    "India": "🇮🇳", "United States": "🇺🇸", "United Kingdom": "🇬🇧", "Germany": "🇩🇪",
    "France": "🇫🇷", "Singapore": "🇸🇬", "Canada": "🇨🇦", "Australia": "🇦🇺",
    "Netherlands": "🇳🇱", "Ireland": "🇮🇪", "China": "🇨🇳", "Japan": "🇯🇵",
    "Russia": "🇷🇺", "Brazil": "🇧🇷", "United Arab Emirates": "🇦🇪", "Switzerland": "🇨🇭",
    "Italy": "🇮🇹", "Spain": "🇪🇸", "Sweden": "🇸🇪", "South Korea": "🇰🇷",
    "Hong Kong": "🇭🇰", "Taiwan": "🇹🇼", "Israel": "🇮🇱", "South Africa": "🇿🇦",
    "Thailand": "🇹🇭", "Indonesia": "🇮🇩", "Malaysia": "🇲🇾", "Vietnam": "🇻🇳",
    "Philippines": "🇵🇭", "Nigeria": "🇳🇬", "Kenya": "🇰🇪", "Pakistan": "🇵🇰",
    "Bangladesh": "🇧🇩", "Sri Lanka": "🇱🇰", "Ukraine": "🇺🇦", "Poland": "🇵🇱",
    "Romania": "🇷🇴", "Chile": "🇨🇱", "Mexico": "🇲🇽", "Argentina": "🇦🇷"
}

def get_country_flag(country_name: str) -> str:
    if not country_name or country_name == "UNKNOWN":
        return "🌐"
    return COUNTRY_FLAGS.get(country_name, "🌐")

import socket
from email.utils import parseaddr

def extract_originating_sender_telemetry(
    headers: Dict[str, Any],
    received_chain: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Forensically analyzes email headers and relay metadata using an evidence hierarchy:
    - Priority 1: Explicit client/originating IP headers (X-Originating-IP, X-Sender-IP, etc.)
    - Priority 2: Authentication evidence (Authentication-Results, Received-SPF client-ip=)
    - Priority 3: Chronological Received chain (earliest public IP in external connection)
    - Fallback: Hostname candidate for supplementary DNS intelligence
    """
    hdr_lower = {k.lower(): v for k, v in headers.items()}
    
    # Priority 1: Explicit client/originating IP headers
    explicit_headers = [
        "x-originating-ip", "x-sender-ip", "x-real-ip", "x-client-ip",
        "x-original-client-ip", "x-source-ip"
    ]
    for h in explicit_headers:
        val = hdr_lower.get(h)
        if val:
            val_str = " ".join(val) if isinstance(val, list) else str(val)
            matches = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', val_str)
            ipv6_candidates = re.findall(r'\[?([0-9a-fA-F:]{3,39})\]?', val_str)
            for cand in ipv6_candidates:
                if ":" in cand:
                    try:
                        ip_obj = ipaddress.ip_address(cand)
                        if ip_obj.version == 6:
                            matches.append(str(ip_obj))
                    except ValueError:
                        pass
            for ip in matches:
                if is_public_ip(ip):
                    return {
                        "ip": ip,
                        "source": f"Header '{h}'",
                        "classification": "Originating/Client IP Evidence",
                        "raw_evidence": f"{h}: {val_str}",
                        "is_client_ip": True,
                        "hostname_candidate": None
                    }

    # Priority 2: Authentication evidence (client-ip= in Received-SPF / Authentication-Results)
    auth_fields = [
        ("received-spf", hdr_lower.get("received-spf")),
        ("authentication-results", hdr_lower.get("authentication-results"))
    ]
    for auth_hdr_name, auth_val in auth_fields:
        if auth_val:
            auth_str = " ".join(auth_val) if isinstance(auth_val, list) else str(auth_val)
            matches = re.findall(
                r'(?:client-ip\s*=\s*|designates\s+|sender\s+ip\s+is\s+)\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                auth_str,
                re.IGNORECASE
            )
            for ip in matches:
                if is_public_ip(ip):
                    return {
                        "ip": ip,
                        "source": f"Authentication Evidence ({auth_hdr_name}: client-ip={ip})",
                        "classification": "Originating/Client IP Evidence (Authentication client-ip)",
                        "raw_evidence": auth_str[:120],
                        "is_client_ip": True,
                        "hostname_candidate": None
                    }

    # Priority 3: Received chain - chronological earliest (bottom-most) public hop
    chain = received_chain or hdr_lower.get("received", [])
    if isinstance(chain, str):
        chain = [chain]
    
    hostname_candidate = None
    if chain:
        for rec in reversed(chain):
            rec_str = str(rec)
            # Find public IPs in this Received hop
            ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', rec_str)
            for ip in ips:
                if is_public_ip(ip):
                    return {
                        "ip": ip,
                        "source": "Earliest Public Relay IP (Originating MTA Hop)",
                        "classification": "Earliest Public Relay IP",
                        "raw_evidence": rec_str[:150],
                        "is_client_ip": False,
                        "hostname_candidate": None
                    }
            
            # If no IP was found, look for hostname following 'from'
            if not hostname_candidate:
                h_match = re.search(r'(?i)\bfrom\s+([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\b', rec_str)
                if h_match:
                    h_val = h_match.group(1).lower()
                    if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', h_val) and "local" not in h_val:
                        hostname_candidate = h_val

    # Priority 4: Fallback header scan for any public IP
    all_hdr_text = " ".join([str(v) for v in headers.values()])
    fallback_ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', all_hdr_text)
    for ip in reversed(fallback_ips):
        if is_public_ip(ip):
            return {
                "ip": ip,
                "source": "Header Inspection Candidate",
                "classification": "Earliest Public Relay IP",
                "raw_evidence": f"Found in header values: {ip}",
                "is_client_ip": False,
                "hostname_candidate": hostname_candidate
            }

    # No reliable public IP found
    return {
        "ip": None,
        "source": "No public sender IP in headers",
        "classification": "Relay-masked",
        "raw_evidence": "",
        "is_client_ip": False,
        "hostname_candidate": hostname_candidate
    }

def extract_originating_sender_ip(
    headers: Dict[str, Any],
    received_chain: Optional[List[str]] = None
) -> Tuple[Optional[str], str]:
    """
    Forensically derives the originating public IP from available email headers and relay metadata.
    Returns 2-tuple (ip, source) for backward compatibility.
    """
    telem = extract_originating_sender_telemetry(headers, received_chain)
    return telem["ip"], telem["source"]

def resolve_hostname_supplementary(hostname: Optional[str]) -> Dict[str, Any]:
    """
    DNS Hostname Resolution (Supplementary Intelligence).
    If a Received: header contains only a hostname and no IP (e.g., 'from mail.attacker-server.com'),
    DNS resolution may be used as supplementary infrastructure intelligence.
    
    IMPORTANT: A DNS-resolved IP MUST NOT be labeled 'Attacker IP' or 'Sender's actual IP'.
    Instead, it is displayed separately as 'Resolved Host IP — DNS Intelligence'.
    """
    if not hostname or "." not in hostname:
        return {
            "hostname": hostname or "Unavailable",
            "resolved_ip": None,
            "status": "Unavailable",
            "display_label": "DNS Intelligence: Unavailable",
            "explanation": "DNS resolution identifies the current IP associated with the hostname; it does not prove the historical originating IP used to send this email."
        }

    clean_host = hostname.strip("[]() :")
    try:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.5)
        try:
            resolved_ip = socket.gethostbyname(clean_host)
        finally:
            socket.setdefaulttimeout(orig_timeout)

        if is_public_ip(resolved_ip):
            geo = get_geolocation(resolved_ip)
            city = geo.get("city") or "Unknown"
            country = geo.get("country") or "Unknown"
            flag = get_country_flag(country)
            return {
                "hostname": clean_host,
                "resolved_ip": resolved_ip,
                "status": "Resolved",
                "display_label": f"Resolved Host IP: {resolved_ip}",
                "city": city,
                "country": country,
                "flag": flag,
                "org": geo.get("org") or "Unknown ISP",
                "asn": geo.get("asn") or "Unknown ASN",
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "explanation": "DNS resolution identifies the current IP associated with the hostname; it does not prove the historical originating IP used to send this email."
            }
    except Exception:
        pass

    return {
        "hostname": clean_host,
        "resolved_ip": None,
        "status": "Unavailable",
        "display_label": "DNS Intelligence: Unavailable",
        "explanation": "DNS resolution identifies the current IP associated with the hostname; it does not prove the historical originating IP used to send this email."
    }

def get_sender_location(
    headers: Dict[str, Any],
    received_chain: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Resolves approximate originating infrastructure geolocation context from available email evidence.
    Returns comprehensive forensic sender dictionary including:
    - Sender Address (From: display name + email)
    - Return-Path / Envelope Sender comparison
    - Originating / Client IP evidence and classification
    - Approximate infrastructure location
    - Supplementary DNS intelligence (if applicable)
    """
    from_raw = str(headers.get("from", "Unknown Sender"))
    display_name, sender_email = parseaddr(from_raw)
    sender_address_disp = from_raw if from_raw != "Unknown Sender" else (f'"{display_name}" <{sender_email}>' if display_name else sender_email)

    return_path_raw = str(headers.get("return-path", ""))
    _, return_path_email = parseaddr(return_path_raw)
    return_path_disp = return_path_email or (return_path_raw if return_path_raw else "Not specified")

    return_path_differs = False
    if return_path_email and sender_email:
        return_path_differs = (return_path_email.lower() != sender_email.lower())

    telem = extract_originating_sender_telemetry(headers, received_chain)
    sender_ip = telem["ip"]

    # Supplementary DNS intelligence if hostname candidate was found
    dns_intel = resolve_hostname_supplementary(telem.get("hostname_candidate"))

    attribution_disclaimer = (
        "Geo-IP provides approximate geographic/infrastructure context for the identified IP. "
        "It does not prove the physical location or identity of the human sender. "
        "VPNs, proxies, shared infrastructure, webmail providers and relays may obscure the original client location."
    )

    relay_masked_explanation = (
        "The available email telemetry does not expose a reliable public client/originating IP. "
        "The displayed relay/domain information represents mail infrastructure rather than proof of the sender's device IP."
    )

    if not sender_ip:
        return {
            "sender_address": sender_address_disp,
            "sender_email": sender_email or "Unknown",
            "sender_display_name": display_name,
            "return_path": return_path_disp,
            "return_path_differs": return_path_differs,
            "sender_ip": "Not available / Relay-masked",
            "ip_classification": "Relay-masked",
            "ip_source": telem["source"],
            "raw_header_evidence": telem["raw_evidence"],
            "is_identified": False,
            "is_client_ip": False,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "flag": "🌐",
            "display_location": "Sender Location Unavailable",
            "latitude": None,
            "longitude": None,
            "org": "Unknown Network",
            "asn": "None",
            "db_provider": "N/A",
            "status": "No public sender IP found",
            "dns_intelligence": dns_intel,
            "attribution_disclaimer": attribution_disclaimer,
            "relay_masked_explanation": relay_masked_explanation
        }

    geo = get_geolocation(sender_ip)
    city = geo.get("city") or "Unknown"
    region = geo.get("region") or "Unknown"
    country = geo.get("country") or "Unknown"
    flag = get_country_flag(country)

    loc_parts = [p for p in [city, region, country] if p and p != "UNKNOWN"]
    display_loc = f"{', '.join(loc_parts)} {flag}" if loc_parts else f"Unknown Location {flag}"

    return {
        "sender_address": sender_address_disp,
        "sender_email": sender_email or "Unknown",
        "sender_display_name": display_name,
        "return_path": return_path_disp,
        "return_path_differs": return_path_differs,
        "sender_ip": sender_ip,
        "ip_classification": telem["classification"],
        "ip_source": telem["source"],
        "raw_header_evidence": telem["raw_evidence"],
        "is_identified": True,
        "is_client_ip": telem["is_client_ip"],
        "country": country,
        "region": region,
        "city": city,
        "flag": flag,
        "display_location": display_loc,
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
        "org": geo.get("org") or "Unknown ISP",
        "asn": geo.get("asn") or "Unknown ASN",
        "db_provider": geo.get("db_provider"),
        "status": geo.get("status"),
        "dns_intelligence": dns_intel,
        "attribution_disclaimer": attribution_disclaimer,
        "relay_masked_explanation": relay_masked_explanation
    }


def derive_authoritative_location(case_data: Any) -> Dict[str, Any]:
    """
    Derives the authoritative sender and origin infrastructure location dictionary
    from a CaseReport instance or case dictionary without duplicate GeoIP queries.

    Preserves all SIH26106 infrastructure indicators and fields:
    - is_identified: bool
    - display_location: str (e.g., "City, Region, Country 🇮🇳" or "Unavailable")
    - sender_ip: originating public IP or relay-masked status
    - country, region, city
    - latitude, longitude
    - ISP / organization (org / isp)
    - ASN
    - hosting provider / cloud provider
    - confidence score
    - attribution limitations & relay-masked disclaimers
    """
    attribution_disclaimer = (
        "Geo-IP provides approximate geographic/infrastructure context for the identified IP. "
        "It does not prove the physical location or identity of the human sender. "
        "VPNs, proxies, shared infrastructure, webmail providers and relays may obscure the original client location."
    )
    relay_masked_explanation = (
        "The available email telemetry does not expose a reliable public client/originating IP. "
        "The displayed relay/domain information represents mail infrastructure rather than proof of the sender's device IP."
    )

    res: Dict[str, Any] = {
        "sender_address": "Unknown",
        "sender_email": "Unknown",
        "sender_display_name": "",
        "return_path": "Not specified",
        "return_path_differs": False,
        "sender_ip": "Unavailable / Relay-masked",
        "ip_classification": "Relay-masked",
        "ip_source": "No public sender IP in headers",
        "raw_header_evidence": "",
        "is_identified": False,
        "is_client_ip": False,
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "flag": "🌐",
        "display_location": "Unavailable",
        "latitude": None,
        "longitude": None,
        "org": "Unknown Network",
        "asn": "Unknown ASN",
        "cloud_provider": "None",
        "hosting_provider": "None",
        "confidence": 0,
        "db_provider": "N/A",
        "status": "No public sender IP found",
        "dns_intelligence": {},
        "attribution_disclaimer": attribution_disclaimer,
        "relay_masked_explanation": relay_masked_explanation,
    }

    if not case_data:
        return res

    if isinstance(case_data, dict):
        raw_sloc = case_data.get("sender_location")
        infra = case_data.get("infrastructure_intel")
    else:
        raw_sloc = getattr(case_data, "sender_location", None)
        infra = getattr(case_data, "infrastructure_intel", None)

    if hasattr(raw_sloc, "model_dump"):
        raw_sloc = raw_sloc.model_dump()

    if hasattr(infra, "model_dump"):
        infra_dict = infra.model_dump()
    elif isinstance(infra, dict):
        infra_dict = infra
    elif infra is not None:
        try:
            infra_dict = infra.__dict__
        except Exception:
            infra_dict = None
    else:
        infra_dict = None

    if isinstance(raw_sloc, dict) and raw_sloc:
        res.update(raw_sloc)
        if raw_sloc.get("is_identified"):
            res["is_identified"] = True
            if not res.get("display_location") or res.get("display_location") == "Unavailable":
                parts = [p for p in [res.get("city"), res.get("region"), res.get("country")] if p and p != "Unknown"]
                res["display_location"] = f"{', '.join(parts)} {res.get('flag', '🌐')}".strip() if parts else "Unknown Location 🌐"
        else:
            res["is_identified"] = False
            if res.get("display_location") in [None, "", "Sender Location Unavailable"]:
                res["display_location"] = "Unavailable"

    if isinstance(infra_dict, dict) and infra_dict:
        if not res.get("is_identified"):
            orig_ip = infra_dict.get("origin_ip")
            cntry = infra_dict.get("country", "Unknown")
            if orig_ip and orig_ip not in ["Unavailable", "None", "0.0.0.0", ""] and cntry != "Unknown":
                res["is_identified"] = True
                res["sender_ip"] = orig_ip
                res["country"] = cntry
                res["region"] = infra_dict.get("region", "Unknown")
                res["city"] = infra_dict.get("city", "Unknown")
                flag = infra_dict.get("flag", "🌐")
                res["flag"] = flag
                parts = [p for p in [res["city"], res["region"], res["country"]] if p and p != "Unknown"]
                res["display_location"] = f"{', '.join(parts)} {flag}".strip() if parts else f"Unknown Location {flag}"
                res["org"] = infra_dict.get("isp") or "Unknown ISP"
                res["asn"] = infra_dict.get("asn") or "Unknown ASN"
                res["latitude"] = infra_dict.get("latitude")
                res["longitude"] = infra_dict.get("longitude")

        c_ind = infra_dict.get("cloud_indicator")
        if isinstance(c_ind, dict):
            p = c_ind.get("provider")
            if p and p not in ["UNKNOWN", "None / Dedicated / Residential"]:
                res["cloud_provider"] = p
                res["hosting_provider"] = p
        elif hasattr(c_ind, "provider"):
            p = getattr(c_ind, "provider")
            if p and p not in ["UNKNOWN", "None / Dedicated / Residential"]:
                res["cloud_provider"] = p
                res["hosting_provider"] = p

        if "confidence" in infra_dict and infra_dict["confidence"] is not None:
            res["confidence"] = infra_dict["confidence"]

        if infra_dict.get("attribution_disclaimer"):
            res["attribution_disclaimer"] = infra_dict["attribution_disclaimer"]

        if infra_dict.get("asn") and res.get("asn") in [None, "None", "Unknown ASN", "N/A"]:
            res["asn"] = infra_dict["asn"]

        if infra_dict.get("isp") and res.get("org") in [None, "None", "Unknown Network", "Unknown ISP", "N/A"]:
            res["org"] = infra_dict["isp"]

        for ind_key in ["vpn_indicator", "tor_indicator", "open_relay_indicator", "botnet_indicator", "threat_intel_match"]:
            if ind_key in infra_dict:
                res[ind_key] = infra_dict[ind_key]

    return res


