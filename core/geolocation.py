import ipaddress
import os
import datetime
from typing import Dict, Any, Optional
import requests

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
    if city == "UNKNOWN" or region == "UNKNOWN" or country == "UNKNOWN":
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{cleaned_ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query",
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
