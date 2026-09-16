import socket
import ipaddress
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Union
import requests
import urllib3
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import PoolManager
from urllib3.util.connection import _set_socket_options
from requests.adapters import HTTPAdapter

from core.schemas import URLAnalysisResult
from core.domain_reputation import OFFICIAL_BRAND_DOMAINS, KNOWN_REPUTABLE_DOMAINS

# ---------------------------------------------------------------------------
# SSRF Exceptions
# ---------------------------------------------------------------------------

class SSRFSecurityError(requests.exceptions.RequestException):
    """Base exception for SSRF security violations."""
    pass

class SSRFBlockedError(SSRFSecurityError):
    """Raised when an outbound probe targets a restricted, private, or dangerous IP/host."""
    def __init__(self, message: str, destination_url: Optional[str] = None, redirect_count: int = 0):
        super().__init__(message)
        self.destination_url = destination_url
        self.redirect_count = redirect_count

class SSRFResolutionError(SSRFSecurityError):
    """Raised when DNS resolution fails or returns no addresses for a target host."""
    pass

# ---------------------------------------------------------------------------
# IP Address Validation & SSRF Guardrails
# ---------------------------------------------------------------------------

BLOCKED_METADATA_IPS = {
    "169.254.169.254",   # AWS / Azure / GCP / DigitalOcean IMDS
    "100.100.100.200",   # Alibaba Cloud IMDS
    "fd00:ec2::254",     # AWS IPv6 IMDS
}

def is_safe_ip(ip_obj_or_str: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """
    Validates that an IP address is a publicly routable, global IP address.
    Blocks:
    - Loopback (127.0.0.0/8, ::1)
    - RFC1918 Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Link-Local (169.254.0.0/16, fe80::/10)
    - Unspecified (0.0.0.0, ::)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Reserved / Non-global (240.0.0.0/4, 100.64.0.0/10, etc.)
    - IPv4-mapped IPv6 addresses targeting private/loopback spaces (::ffff:127.0.0.1)
    - 6to4 / Teredo embedded addresses targeting private spaces
    - Explicit Cloud Metadata addresses
    """
    try:
        if isinstance(ip_obj_or_str, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = ip_obj_or_str
        else:
            s = str(ip_obj_or_str).strip()
            if s.startswith("[") and s.endswith("]"):
                s = s[1:-1]
            ip = ipaddress.ip_address(s)

        # Check IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if getattr(ip, "ipv4_mapped", None) is not None:
            if not is_safe_ip(ip.ipv4_mapped):
                return False

        # 6to4 addresses (2002::/16) embed IPv4
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.sixtofour:
                if not is_safe_ip(ip.sixtofour):
                    return False
            if ip.teredo:
                if not is_safe_ip(ip.teredo[1]):
                    return False

        # Core RFC checks
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
            or not ip.is_global
        ):
            return False

        # Cloud metadata explicit checks
        str_ip = str(ip).lower()
        if str_ip in BLOCKED_METADATA_IPS:
            return False

        return True
    except (ValueError, TypeError):
        return False

# ---------------------------------------------------------------------------
# Target URL Pre-Flight Validation
# ---------------------------------------------------------------------------

def validate_url_target(url: str) -> Tuple[str, List[str]]:
    """
    Validates a URL before making any network probe:
    1. Enforces http / https schemes only (blocks file://, ftp://, gopher://, dict://, etc.)
    2. Ensures a valid hostname is present
    3. Resolves hostname and validates that ALL resolved IP addresses are safe public IPs.
    Returns: (cleaned_hostname, list_of_validated_ips)
    Raises SSRFBlockedError or SSRFResolutionError on safety or resolution failures.
    """
    if not url or not isinstance(url, str):
        raise SSRFBlockedError(f"Invalid or empty URL: '{url}'")

    parsed = urllib.parse.urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SSRFBlockedError(f"Prohibited URL scheme '{parsed.scheme}': only http and https are allowed")

    host = parsed.hostname
    if not host:
        raise SSRFBlockedError(f"Malformed URL missing hostname: '{url}'")

    host = host.lower().strip().strip("[]")

    # Integer IPv4 representation check (e.g. 2130706433)
    if host.isdigit():
        try:
            int_ip = ipaddress.ip_address(int(host))
            if not is_safe_ip(int_ip):
                raise SSRFBlockedError(f"SSRF blocked: numeric host '{host}' converts to unsafe IP '{int_ip}'")
            return host, [str(int_ip)]
        except ValueError:
            raise SSRFBlockedError(f"SSRF blocked: invalid numeric host '{host}'")

    # Direct IP check
    try:
        direct_ip = ipaddress.ip_address(host)
        if not is_safe_ip(direct_ip):
            raise SSRFBlockedError(f"SSRF blocked: host '{host}' is a non-routable/restricted IP address")
        return host, [str(direct_ip)]
    except ValueError:
        pass  # Host is a domain name, proceed to DNS resolution

    # Resolve hostname to verify ALL returned IPs
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFResolutionError(f"DNS resolution failed for '{host}': {e}") from e

    if not addr_info:
        raise SSRFResolutionError(f"DNS resolution returned no records for '{host}'")

    resolved_ips = []
    for entry in addr_info:
        ip_addr = entry[4][0]
        if not is_safe_ip(ip_addr):
            raise SSRFBlockedError(f"SSRF blocked: host '{host}' resolves to unsafe IP '{ip_addr}'")
        resolved_ips.append(ip_addr)

    return host, resolved_ips

# ---------------------------------------------------------------------------
# DNS-Rebinding Safe Connection Classes & Adapter
# ---------------------------------------------------------------------------

def _safe_create_connection(
    address: tuple,
    timeout: Any = 3.5,
    source_address: Optional[tuple] = None,
    socket_options: Any = None,
) -> socket.socket:
    """
    Socket factory that validates all resolved IPs immediately before opening a TCP connection.
    Guarantees that DNS rebinding occurring between pre-flight and connection cannot connect
    to an unsafe IP address.
    """
    host, port = address
    if host.startswith("["):
        host = host.strip("[]")

    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFResolutionError(f"DNS resolution failed at connection time for '{host}': {e}") from e

    if not addr_info:
        raise SSRFResolutionError(f"DNS resolution returned no addresses for '{host}'")

    for res in addr_info:
        target_ip = res[4][0]
        if not is_safe_ip(target_ip):
            raise SSRFBlockedError(f"SSRF blocked: host '{host}' resolves to unsafe IP '{target_ip}'")

    err = None
    for res in addr_info:
        af, socktype, proto, canonname, sa = res
        target_ip = sa[0]
        if not is_safe_ip(target_ip):
            raise SSRFBlockedError(f"SSRF blocked: connection target '{target_ip}' is unsafe")

        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if socket_options:
                _set_socket_options(sock, socket_options)
            if isinstance(timeout, (int, float)):
                sock.settimeout(timeout)
            elif hasattr(timeout, "connect_timeout") and timeout.connect_timeout:
                sock.settimeout(timeout.connect_timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    raise OSError("Failed to establish connection to any resolved IP")

class SafeHTTPConnection(HTTPConnection):
    def _new_conn(self) -> socket.socket:
        return _safe_create_connection(
            (getattr(self, "_dns_host", self.host), self.port),
            self.timeout,
            source_address=self.source_address,
            socket_options=self.socket_options,
        )

class SafeHTTPSConnection(HTTPSConnection):
    def _new_conn(self) -> socket.socket:
        return _safe_create_connection(
            (getattr(self, "_dns_host", self.host), self.port),
            self.timeout,
            source_address=self.source_address,
            socket_options=self.socket_options,
        )

class SafeHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = SafeHTTPConnection

class SafeHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = SafeHTTPSConnection

class SafePoolManager(PoolManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": SafeHTTPConnectionPool,
            "https": SafeHTTPSConnectionPool,
        }

class SafeHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = SafePoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)

def get_safe_session() -> requests.Session:
    """Returns a requests.Session equipped with SSRF-safe connection adapters."""
    session = requests.Session()
    adapter = SafeHTTPAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# ---------------------------------------------------------------------------
# Safe Redirect-Aware Unshortening Function
# ---------------------------------------------------------------------------

def safe_unshorten_url(
    url: str,
    timeout: float = 3.5,
    max_redirects: int = 5,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EMAILSHIELD-Forensic-Probe/2.0"
) -> Tuple[str, int, List[str]]:
    """
    Safely resolves HTTP HEAD redirects with multi-stage SSRF defense:
    1. Validates the URL scheme (http/https only) and target IP addresses pre-flight.
    2. Utilizes custom socket factories validating all resolved IPs at connect time (anti-DNS-rebinding).
    3. Manually evaluates each redirect hop, re-validating destinations before making subsequent requests.
    4. Limits redirect hops to max_redirects (default: 5) to prevent infinite redirect loops.
    Returns: (final_url, redirect_count, hops_history)
    """
    current_url = url
    redirect_count = 0
    hops_history = []
    session = get_safe_session()

    for hop in range(max_redirects):
        # 1. Pre-flight validate current URL target
        try:
            validate_url_target(current_url)
        except SSRFBlockedError as e:
            raise SSRFBlockedError(str(e), destination_url=current_url, redirect_count=redirect_count) from e

        # 2. Make outbound HEAD request with allow_redirects=False
        try:
            resp = session.head(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                headers={"User-Agent": user_agent, "Accept": "*/*", "Connection": "close"}
            )
        except requests.exceptions.RequestException as e:
            # Check if inner cause was SSRFSecurityError
            inner = e.args[0] if e.args else None
            if isinstance(inner, tuple) and len(inner) > 1 and isinstance(inner[1], SSRFSecurityError):
                raise SSRFBlockedError(str(inner[1]), destination_url=current_url, redirect_count=redirect_count) from e
            if isinstance(getattr(e, "__cause__", None), SSRFSecurityError):
                cause = getattr(e, "__cause__", None)
                raise SSRFBlockedError(str(cause), destination_url=current_url, redirect_count=redirect_count) from e
            raise

        # 3. Check for HTTP redirect response
        if resp.status_code in (301, 302, 303, 307, 308) or resp.is_redirect:
            location = resp.headers.get("Location")
            if not location:
                break
            next_url = urllib.parse.urljoin(current_url, location)
            redirect_count += 1
            hops_history.append(next_url)

            # Re-validate the redirect destination target before next hop
            try:
                validate_url_target(next_url)
            except SSRFBlockedError as e:
                raise SSRFBlockedError(str(e), destination_url=next_url, redirect_count=redirect_count) from e

            current_url = next_url
        else:
            break

    return current_url, redirect_count, hops_history

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorte.st", "rebrand.ly", "rotf.lol",
    "v.gd", "shorturl.at", "bl.ink", "tiny.cc", "lnkd.in"
}

PAYLOAD_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".msi", ".jar",
    ".apk", ".iso", ".img", ".vhd", ".zip", ".rar", ".7z", ".tar.gz",
    ".docm", ".xlsm", ".pptm", ".dotm", ".dll", ".pif"
}

PHISHING_KEYWORDS = [
    "login", "signin", "log-in", "sign-in", "verify", "verification",
    "security-check", "authenticate", "password", "reset-password",
    "update-account", "banking", "secure-account", "webscr", "checkpoint",
    "wallet", "seedphrase", "claim-reward", "invoice-review",
    "unlock-account", "reactivate", "account-alert", "session-expired"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work",
    ".icu", ".monster", ".ru", ".cn", ".pw", ".cc", ".space", ".bid", ".club"
}

MAJOR_BRANDS = [
    "paypal", "microsoft", "office365", "outlook", "google", "apple",
    "amazon", "netflix", "chase", "wellsfargo", "bankofamerica", "sbi",
    "hdfc", "icici", "dhl", "fedex", "usps", "facebook", "instagram"
]

VERIFIED_LEGIT_SERVICES = {
    "youtube.com", "youtu.be", "google.com", "google.co.in", "gmail.com",
    "substack.com", "beehiiv.com", "convertkit.com", "mailchimp.com", "medium.com",
    "growthschool.io", "sisinty.com", "linkedin.com", "twitter.com", "x.com",
    "instagram.com", "facebook.com", "github.com", "apple.com", "microsoft.com",
    "whatsapp.com", "telegram.org", "zoom.us", "calendly.com", "notion.so",
    "luma.com", "lu.ma", "hubspot.com", "stripe.com", "razorpay.com", "eventbrite.com",
    "sbicard.com", "hdfcbank.com", "hdfcbank.net", "icicibank.com", "sbi.co.in", "amazon.in"
}

def is_verified_service(host_str: str) -> bool:
    if not host_str:
        return False
    h = host_str.lower().strip()
    return any(h == s or h.endswith(f".{s}") for s in VERIFIED_LEGIT_SERVICES)

def is_official_brand_destination(host_str: str) -> bool:
    if not host_str:
        return False
    h = host_str.lower().strip()
    if h in KNOWN_REPUTABLE_DOMAINS or any(h.endswith(f".{kd}") for kd in KNOWN_REPUTABLE_DOMAINS):
        return True
    for brand, legit_domains in OFFICIAL_BRAND_DOMAINS.items():
        if any(h == ld or h.endswith(f".{ld}") for ld in legit_domains):
            return True
    return False

def defang_url(url: str) -> str:
    """Converts a live URL into a defanged safe string (e.g., hxxps[://]bad[.]com)."""
    defanged = url.replace("https://", "hxxps[://]").replace("http://", "hxxp[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged

def analyze_url(url: str, resolve_redirects: bool = True) -> URLAnalysisResult:
    """
    Performs comprehensive forensic background analysis on an extracted hyperlink:
    1. Defangs the URL for safe SOC logging
    2. Follows safe HTTP HEAD redirects to discover hidden landing endpoints
    3. Detects malware droppers, credential harvesting, brand spoofing, and tracking beacons
    4. Provides concrete 'What This Link May Cause' impact and 'What You Should Do' remediation
    """
    defanged = defang_url(url)
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower().split(":")[0]  # strip port if present
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_lower = url.lower()

    reasons = []
    suspicious_indicators = []
    threat_category = "Clean / Low Risk"
    risk_level = "LOW"
    potential_impact = "Standard web destination. No explicit malicious indicators identified."
    recommended_action = "Standard vigilance. Ensure the sender domain aligns with your expectations."

    # 1. Shortener & Safe Redirect Resolution
    is_shortener = host in SHORTENER_DOMAINS
    final_destination = url
    redirect_count = 0

    if is_shortener or resolve_redirects:
        try:
            final_destination, redirect_count, hops_history = safe_unshorten_url(url, timeout=3.5)
            if redirect_count > 0:
                reasons.append(f"Redirect chain detected: Passed through {redirect_count} hops to '{defang_url(final_destination)}'")
                suspicious_indicators.append(f"HTTP Redirects ({redirect_count} hops)")
        except SSRFBlockedError as e:
            if e.destination_url:
                final_destination = e.destination_url
                redirect_count = e.redirect_count
            if redirect_count > 0:
                reasons.append(f"Redirect chain detected: Passed through {redirect_count} hops to '{defang_url(final_destination)}'")
                suspicious_indicators.append(f"HTTP Redirects ({redirect_count} hops)")
            reasons.append(f"SSRF Protection: Outbound probe blocked to restricted/private destination: {e}")
            suspicious_indicators.append("Restricted/Internal Network Destination (SSRF Blocked)")
            if is_shortener:
                reasons.append("URL shortener redirected to a restricted internal address.")
                suspicious_indicators.append("Obfuscated URL Shortener")
        except Exception:
            # Network blocked, expired domain, or server rejected probe
            if is_shortener:
                reasons.append("URL shortener used; remote destination could not be safely unshortened.")
                suspicious_indicators.append("Obfuscated URL Shortener")

    # Update parsed parts to final destination if redirected
    final_parsed = urllib.parse.urlparse(final_destination)
    final_host = final_parsed.netloc.lower().split(":")[0]
    final_path = final_parsed.path.lower()
    final_query = final_parsed.query.lower()

    # 2. Check for Direct IP Hostname
    is_ip_host = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', final_host))
    if is_ip_host:
        suspicious_indicators.append("Direct IP Hostname")
        reasons.append(f"Host uses raw numeric IP '{final_host}' instead of a registered domain name.")

    # 3. Check for Dangerous File Extensions (Malware Dropper)
    detected_payload_ext = None
    for ext in PAYLOAD_EXTENSIONS:
        if final_path.endswith(ext) or f"{ext}?" in final_query:
            detected_payload_ext = ext
            break

    if detected_payload_ext:
        threat_category = "Malware Payload Dropper"
        risk_level = "CRITICAL"
        suspicious_indicators.append(f"Weaponized Payload Extension ({detected_payload_ext})")
        reasons.append(f"URL directly links to executable or weaponized container '{detected_payload_ext}'.")
        potential_impact = (
            f"CRITICAL MALWARE THREAT: This link attempts to deliver a weaponized '{detected_payload_ext}' payload. "
            f"If downloaded and opened, it may deploy ransomware, Trojans, info-stealers, or remote access backdoors (C2) onto your computer."
        )
        recommended_action = (
            "🚨 DO NOT CLICK OR DOWNLOAD. If already downloaded, immediately disconnect your device from Wi-Fi/Ethernet, "
            "do NOT open the file, delete it immediately, and run an endpoint antivirus scan."
        )
        return URLAnalysisResult(
            url=url,
            defanged_url=defanged,
            domain=host,
            is_shortener=is_shortener,
            final_destination=final_destination,
            redirect_count=redirect_count,
            threat_category=threat_category,
            risk_level=risk_level,
            potential_impact=potential_impact,
            recommended_action=recommended_action,
            reasons=reasons,
            suspicious_indicators=suspicious_indicators
        )

    # Check if destination is a verified legitimate service or official brand platform
    has_ssrf_block = "Restricted/Internal Network Destination (SSRF Blocked)" in suspicious_indicators
    is_official_dest = is_official_brand_destination(final_host) or is_official_brand_destination(host)
    is_verified_dest = (is_verified_service(final_host) or is_verified_service(host) or is_official_dest) and not has_ssrf_block

    if is_verified_dest and not detected_payload_ext:
        # Known legitimate platform or official banking/enterprise domain
        threat_category = "Clean / Verified Platform Link"
        risk_level = "LOW"
        potential_impact = f"Directs to verified platform or legitimate service ('{final_host}')."
        recommended_action = "Standard vigilance. Link is hosted on an authentic platform."
        return URLAnalysisResult(
            url=url,
            defanged_url=defanged,
            domain=host,
            is_shortener=is_shortener,
            final_destination=final_destination,
            redirect_count=redirect_count,
            threat_category=threat_category,
            risk_level=risk_level,
            potential_impact=potential_impact,
            recommended_action=recommended_action,
            reasons=reasons,
            suspicious_indicators=suspicious_indicators
        )

    # 4. Check for Brand Impersonation & Typosquatting (for non-verified hosts)
    impersonated_brand = None
    if not is_official_dest:
        for brand in MAJOR_BRANDS:
            # Check if non-official domain is trying to mimic this brand in its hostname
            if brand in final_host:
                impersonated_brand = brand
                break

    # 5. Check for Credential Harvesting Keywords
    harvesting_keywords_found = [kw for kw in PHISHING_KEYWORDS if kw in final_path or kw in final_query]

    # 6. Check for Suspicious TLDs
    has_suspicious_tld = any(final_host.endswith(tld) for tld in SUSPICIOUS_TLDS)
    if has_suspicious_tld:
        suspicious_indicators.append("Suspicious / High-Abuse TLD")
        reasons.append("Domain uses an abuse-prone top-level domain frequently used in throwaway phishing attacks.")

    # 7. Check for Tracking / Reconnaissance Beacons
    is_tracking_beacon = any(trk in final_path or trk in final_query for trk in ["/track", "pixel.gif", "open.php", "beacon", "stat.php"])

    # 8. Synthesize Threat Category & Impact
    if impersonated_brand and harvesting_keywords_found:
        threat_category = f"Credential Harvesting ({impersonated_brand.title()} Impersonation)"
        risk_level = "CRITICAL"
        suspicious_indicators.append(f"Deceptive Brand Spoofing ({impersonated_brand})")
        suspicious_indicators.extend([f"Lure: {kw}" for kw in harvesting_keywords_found[:3]])
        reasons.append(f"Deceptively impersonates '{impersonated_brand}' while hosted on unauthorized domain '{final_host}'.")
        potential_impact = (
            f"PHISHING & ACCOUNT TAKEOVER: This link directs to a counterfeit {impersonated_brand.title()} login portal. "
            f"Entering credentials will harvest your password, 2FA OTP codes, and credit card data for unauthorized account access."
        )
        recommended_action = (
            f"🚫 DO NOT ENTER CREDENTIALS. If credentials were submitted, go immediately to the authentic {impersonated_brand.title()} "
            f"website in a separate browser, change your password immediately, and terminate all active sessions."
        )

    elif (is_ip_host and harvesting_keywords_found) or (has_suspicious_tld and harvesting_keywords_found):
        threat_category = "Credential Harvesting Phishing"
        risk_level = "HIGH"
        suspicious_indicators.extend([f"Auth Lure: {kw}" for kw in harvesting_keywords_found[:3]])
        reasons.append(f"Contains credential harvesting lures on unverified host: {', '.join(harvesting_keywords_found[:3])}")
        potential_impact = (
            "ACCOUNT COMPROMISE: Hosted on raw IP or high-abuse TLD designed to capture login credentials."
        )
        recommended_action = (
            "⚠️ DO NOT SUBMIT PASSWORDS. Mark the email as Phishing in your email client. Block the domain on your organization's DNS/firewall."
        )

    elif has_ssrf_block:
        threat_category = "Restricted / Internal Network Destination (SSRF Blocked)"
        risk_level = "HIGH"
        potential_impact = (
            "INTERNAL RECONNAISSANCE / SSRF: Destination points to loopback, private RFC1918 network, "
            "or cloud metadata infrastructure. Outbound network probe was safely blocked to prevent server-side request forgery."
        )
        recommended_action = (
            "🚨 POTENTIAL SSRF ATTACK: Do NOT interact with this link. Investigate why this email references internal/cloud metadata services."
        )

    elif is_ip_host:
        threat_category = "Unverified Raw IP Destination"
        risk_level = "HIGH"
        potential_impact = "Evades standard domain reputation filters; typically indicates an unmanaged bulletproof server or temporary phishing kit."
        recommended_action = "Do NOT interact with this link. Block the destination IP address on the network edge."

    elif harvesting_keywords_found:
        # Standard domain with a login endpoint
        threat_category = "External Authentication Endpoint"
        risk_level = "LOW"
        reasons.append(f"Directs to standard login or verification URL: {', '.join(harvesting_keywords_found[:2])}")
        potential_impact = "Standard authentication portal. Ensure you intended to access this service."
        recommended_action = "Standard vigilance when signing in."

    elif has_suspicious_tld:
        threat_category = "Suspicious Domain TLD"
        risk_level = "MEDIUM"
        potential_impact = "Hosted on an unverified, high-abuse TLD known for disposable phishing campaigns."
        recommended_action = "Exercise caution. Verify the sender's identity through an out-of-band communication channel."

    elif is_tracking_beacon:
        threat_category = "Email Tracking / Reconnaissance"
        risk_level = "LOW"
        suspicious_indicators.append("Tracking Web Beacon")
        reasons.append("Contains telemetry identifiers and tracking beacon patterns.")
        potential_impact = (
            "PRIVACY RECONNAISSANCE: Signals to the sender that your email address is active, recording your IP address, "
            "location, and opening timestamp to facilitate targeted future attacks."
        )
        recommended_action = "Disable automatic remote image loading in your email client to prevent beacon callbacks."

    elif is_shortener:
        threat_category = "Obfuscated URL Shortener"
        risk_level = "MEDIUM"
        reasons.append("URL shortener used to conceal final destination.")
        potential_impact = "Obfuscates destination; may redirect to malicious content without user preview."
        recommended_action = "Inspect the destination preview before following shortened links."

    return URLAnalysisResult(
        url=url,
        defanged_url=defanged,
        domain=host,
        is_shortener=is_shortener,
        final_destination=final_destination,
        redirect_count=redirect_count,
        threat_category=threat_category,
        risk_level=risk_level,
        potential_impact=potential_impact,
        recommended_action=recommended_action,
        reasons=reasons,
        suspicious_indicators=suspicious_indicators
    )

def analyze_all_urls(urls: List[str]) -> List[URLAnalysisResult]:
    """Runs background forensic analysis on all extracted URLs in the email."""
    results = []
    for u in urls[:15]:  # Process up to 15 URLs safely
        try:
            results.append(analyze_url(u))
        except Exception:
            results.append(URLAnalysisResult(
                url=u,
                defanged_url=defang_url(u),
                domain=urllib.parse.urlparse(u).netloc,
                threat_category="Analysis Error",
                risk_level="MEDIUM",
                potential_impact="Unable to complete probe.",
                recommended_action="Treat unverified link with caution."
            ))
    return results
