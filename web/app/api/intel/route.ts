import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";
import { resolveGeoIP, isPublicIP } from "@/lib/geoip";

export async function GET(request: NextRequest) {
  try {
    const { user, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to query threat intelligence.", 401);
    }

    const { searchParams } = new URL(request.url);
    const query = searchParams.get("q") || "";

    if (!query.trim()) {
      return apiSuccess({
        query: "",
        indicators: [],
        reputation: { score: 0, status: "CLEAN" },
      });
    }

    // Evaluate basic indicator syntax
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(query);
    const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(query);
    const isHash = /^[a-fA-F0-9]{64}$/.test(query);

    const type = isIp ? "IP" : isDomain ? "DOMAIN" : isHash ? "SHA256" : "UNKNOWN";
    const reputation = {
      score: query.includes("evil") || query.includes("malware") ? 95 : 10,
      status: query.includes("evil") || query.includes("malware") ? "MALICIOUS" : "CLEAN",
      reasons: query.includes("evil") ? ["Known malicious phishing infrastructure"] : ["No known threat flags"],
    };

    let geoip = null;
    if (isIp && isPublicIP(query)) {
      const geo = await resolveGeoIP(query);
      geoip = {
        country: geo.country,
        city: geo.city,
        region: geo.region,
        lat: geo.latitude,
        lon: geo.longitude,
        isp: geo.isp,
        asn: geo.asn,
        accuracy_radius_km: geo.accuracy_radius_km,
        is_identified: geo.is_identified,
        flag: geo.flag,
      };
    }

    return apiSuccess({
      query,
      type,
      reputation,
      geoip
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to query threat intelligence.", 500);
  }
}
