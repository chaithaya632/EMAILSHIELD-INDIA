import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function GET(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to view investigations.", 401);
    }

    const { searchParams } = new URL(request.url);
    const severity = searchParams.get("severity");
    const search = searchParams.get("search");

    let query = client
      .from("cases")
      .select("id, case_number, subject, sender, threat_verdict, risk_score, created_at, status")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(100);

    if (severity) {
      query = query.ilike("threat_verdict", `%${severity}%`);
    }

    if (search) {
      query = query.ilike("subject", `%${search}%`);
    }

    const { data: cases, error: dbError } = await query;

    if (dbError) {
      return apiError("INTERNAL_ERROR", "Failed to retrieve investigations.", 500);
    }

    return apiSuccess({
      cases: (cases || []).map((c: any) => ({
        ...c,
        case_id: c.case_number || c.id,
        verdict: c.threat_verdict || "CLEAN",
      })),
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to list cases.", 500);
  }
}
