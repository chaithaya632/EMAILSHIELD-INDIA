import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function GET(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to access reports.", 401);
    }

    const { data: cases, error: dbError } = await client
      .from("cases")
      .select("id, case_number, subject, sender, threat_verdict, risk_score, created_at, status")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(50);

    if (dbError) {
      return apiError("INTERNAL_ERROR", "Failed to retrieve reports list.", 500);
    }

    return apiSuccess({
      cases: (cases || []).map((c: any) => ({
        ...c,
        case_id: c.case_number || c.id,
        verdict: c.threat_verdict || "CLEAN",
      })),
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to list report cases.", 500);
  }
}
