import re
import urllib.parse
from typing import Dict, Any, List, Optional
import requests
from core.schemas import URLAnalysisResult

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
    "luma.com", "lu.ma", "hubspot.com", "stripe.com", "razorpay.com", "eventbrite.com"
}

def is_verified_service(host_str: str) -> bool:
    if not host_str:
        return False
    h = host_str.lower().strip()
    return any(h == s or h.endswith(f".{s}") for s in VERIFIED_LEGIT_SERVICES)

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
            # Safe HEAD request with 3.5s timeout, avoiding body downloads
            resp = requests.head(
                url,
                allow_redirects=True,
                timeout=3.5,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EMAILSHIELD-Forensic-Probe/2.0"}
            )
            final_destination = resp.url
            redirect_count = len(resp.history)
            if redirect_count > 0:
                reasons.append(f"Redirect chain detected: Passed through {redirect_count} hops to '{defang_url(final_destination)}'")
                suspicious_indicators.append(f"HTTP Redirects ({redirect_count} hops)")
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

    # 4. Check for Brand Impersonation & Typosquatting
    impersonated_brand = None
    for brand in MAJOR_BRANDS:
        if brand in final_host:
            # Check if it is the official root domain (e.g. paypal.com vs paypal.com.verify-billing.xyz)
            if not final_host.endswith(f".{brand}.com") and final_host != f"{brand}.com":
                impersonated_brand = brand
                break
        elif brand in final_path or brand in final_query:
            if not final_host.endswith(f".{brand}.com") and final_host != f"{brand}.com":
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

    # Check if destination is a verified legitimate service or platform
    is_verified_dest = is_verified_service(final_host) or is_verified_service(host)

    if is_verified_dest and not detected_payload_ext:
        # Known legitimate platform (YouTube, Substack, GrowthSchool, LinkedIn, Google, etc.)
        threat_category = "Clean / Verified Platform Link"
        risk_level = "LOW"
        potential_impact = f"Directs to verified platform or creator service ('{final_host}')."
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
