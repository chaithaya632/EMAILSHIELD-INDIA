/**
 * web/lib/geoip.ts
 * Server-side GeoIP resolution for EMAILSHIELD INDIA.
 *
 * Uses ip-api.com (free, server-side only) — the same data source
 * validated and deployed in the Python backend (core/geolocation.py lines 205–228).
 *
 * SECURITY:
 * - Server-side only — never imported in client components.
 * - Private/loopback/link-local IPs return null coordinates (never fabricated).
 * - 2-second timeout with graceful fallback.
 * - No paid API required.
 */

export interface GeoIPResult {
  ip: string;
  country: string;
  region: string;
  city: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
  accuracy_radius_km: number | null;
  status: "Success" | "Private/Reserved IP" | "Unavailable";
  is_identified: boolean;
  flag: string;
  network_type: string;
}

// Country flag emoji lookup (mirrors core/geolocation.py COUNTRY_FLAGS)
const COUNTRY_FLAGS: Record<string, string> = {
  "United States": "🇺🇸",
  "India": "🇮🇳",
  "United Kingdom": "🇬🇧",
  "Germany": "🇩🇪",
  "France": "🇫🇷",
  "Russia": "🇷🇺",
  "China": "🇨🇳",
  "Japan": "🇯🇵",
  "Brazil": "🇧🇷",
  "Canada": "🇨🇦",
  "Australia": "🇦🇺",
  "Singapore": "🇸🇬",
  "Netherlands": "🇳🇱",
  "South Korea": "🇰🇷",
  "Italy": "🇮🇹",
  "Spain": "🇪🇸",
  "Mexico": "🇲🇽",
  "Indonesia": "🇮🇩",
  "Turkey": "🇹🇷",
  "Thailand": "🇹🇭",
  "Vietnam": "🇻🇳",
  "Pakistan": "🇵🇰",
  "Bangladesh": "🇧🇩",
  "Nigeria": "🇳🇬",
  "Egypt": "🇪🇬",
  "South Africa": "🇿🇦",
  "Ukraine": "🇺🇦",
  "Poland": "🇵🇱",
  "Romania": "🇷🇴",
  "Malaysia": "🇲🇾",
  "Philippines": "🇵🇭",
  "United Arab Emirates": "🇦🇪",
  "Saudi Arabia": "🇸🇦",
  "Israel": "🇮🇱",
  "Iran": "🇮🇷",
  "Ireland": "🇮🇪",
  "Sweden": "🇸🇪",
  "Switzerland": "🇨🇭",
  "Finland": "🇫🇮",
  "Norway": "🇳🇴",
  "Denmark": "🇩🇰",
  "Hong Kong": "🇭🇰",
  "Taiwan": "🇹🇼",
  "Argentina": "🇦🇷",
  "Chile": "🇨🇱",
  "Colombia": "🇨🇴",
};

/**
 * Validates whether an IP address is publicly routable.
 * Mirrors Python `is_public_ip()` from core/geolocation.py:105–119.
 */
export function isPublicIP(ip: string): boolean {
  if (!ip || typeof ip !== "string") return false;
  const trimmed = ip.trim().replace(/^\[|\]$/g, "");

  // IPv6 loopback
  if (trimmed === "::1") return false;

  // IPv4 check
  const parts = trimmed.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => parseInt(p, 10));
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return false;

  // RFC 1918 private
  if (nums[0] === 10) return false;
  if (nums[0] === 172 && nums[1] >= 16 && nums[1] <= 31) return false;
  if (nums[0] === 192 && nums[1] === 168) return false;

  // Loopback
  if (nums[0] === 127) return false;

  // Link-local
  if (nums[0] === 169 && nums[1] === 254) return false;

  // Multicast
  if (nums[0] >= 224 && nums[0] <= 239) return false;

  // Reserved/broadcast
  if (nums[0] === 0) return false;
  if (nums[0] === 255) return false;

  // CGNAT (100.64.0.0/10)
  if (nums[0] === 100 && nums[1] >= 64 && nums[1] <= 127) return false;

  // Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  if (nums[0] === 192 && nums[1] === 0 && nums[2] === 2) return false;
  if (nums[0] === 198 && nums[1] === 51 && nums[2] === 100) return false;
  if (nums[0] === 203 && nums[1] === 0 && nums[2] === 113) return false;

  return true;
}

/**
 * Returns a safe default result for private/unresolvable IPs.
 * NEVER fabricates coordinates — latitude and longitude are strictly null.
 */
function privateIpResult(ip: string): GeoIPResult {
  return {
    ip,
    country: "Local / Private Network",
    region: "N/A",
    city: "N/A",
    latitude: null,
    longitude: null,
    isp: "Private Network",
    org: "Private Network",
    asn: "N/A",
    accuracy_radius_km: null,
    status: "Private/Reserved IP",
    is_identified: false,
    flag: "🌐",
    network_type: "Private / Internal",
  };
}

/**
 * Returns a safe fallback result when GeoIP lookup fails.
 */
function unavailableResult(ip: string): GeoIPResult {
  return {
    ip,
    country: "Unknown",
    region: "Unknown",
    city: "Unknown",
    latitude: null,
    longitude: null,
    isp: "Unknown",
    org: "Unknown",
    asn: "Unknown",
    accuracy_radius_km: null,
    status: "Unavailable",
    is_identified: false,
    flag: "🌐",
    network_type: "Unknown",
  };
}

/**
 * Resolves GeoIP data for a given IP address.
 *
 * Uses ip-api.com (free, server-side only) — the same data source
 * used as enrichment fallback in core/geolocation.py.
 *
 * Fields endpoint: http://ip-api.com/json/{ip}?fields=...
 *
 * @param ip - IPv4 address string
 * @returns GeoIPResult with coordinates and infrastructure metadata
 */
export async function resolveGeoIP(ip: string): Promise<GeoIPResult> {
  const trimmed = (ip || "").trim().replace(/^\[|\]$/g, "");

  if (!trimmed) {
    return unavailableResult(trimmed);
  }

  if (!isPublicIP(trimmed)) {
    return privateIpResult(trimmed);
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(trimmed)}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query`,
      {
        signal: controller.signal,
        headers: { "Accept": "application/json" },
      }
    );

    clearTimeout(timeout);

    if (!response.ok) {
      return unavailableResult(trimmed);
    }

    const data = await response.json();

    if (data.status !== "success") {
      return unavailableResult(trimmed);
    }

    const country = data.country || "Unknown";
    const flag = COUNTRY_FLAGS[country] || "🌐";

    // Determine network type heuristic from org/isp
    const orgLower = (data.org || "").toLowerCase() + " " + (data.isp || "").toLowerCase();
    let networkType = "Residential / Enterprise";
    if (
      orgLower.includes("cloud") ||
      orgLower.includes("hosting") ||
      orgLower.includes("amazon") ||
      orgLower.includes("google") ||
      orgLower.includes("microsoft") ||
      orgLower.includes("azure") ||
      orgLower.includes("digitalocean") ||
      orgLower.includes("linode") ||
      orgLower.includes("vultr") ||
      orgLower.includes("ovh") ||
      orgLower.includes("hetzner")
    ) {
      networkType = "Cloud / Hosting";
    }

    return {
      ip: data.query || trimmed,
      country,
      region: data.regionName || "Unknown",
      city: data.city || "Unknown",
      latitude: typeof data.lat === "number" ? data.lat : null,
      longitude: typeof data.lon === "number" ? data.lon : null,
      isp: data.isp || "Unknown",
      org: data.org || data.isp || "Unknown",
      asn: data.as || "Unknown",
      accuracy_radius_km: null, // ip-api.com does not provide accuracy radius
      status: "Success",
      is_identified: true,
      flag,
      network_type: networkType,
    };
  } catch {
    return unavailableResult(trimmed);
  }
}

/**
 * Resolve GeoIP for multiple IPs (e.g., relay hops).
 * Processes sequentially to respect ip-api.com rate limits (45/min).
 */
export async function resolveMultipleGeoIP(
  ips: string[]
): Promise<GeoIPResult[]> {
  const results: GeoIPResult[] = [];
  for (const ip of ips) {
    results.push(await resolveGeoIP(ip));
  }
  return results;
}
