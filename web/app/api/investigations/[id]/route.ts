import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required.", 401);
    }

    const caseId = params.id;

    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(caseId);
    let query = client.from("cases").select("*").eq("user_id", user.id);
    if (isUuid) {
      query = query.eq("id", caseId);
    } else {
      query = query.eq("case_number", caseId);
    }

    const { data: caseRec, error: dbError } = await query.maybeSingle();

    if (dbError || !caseRec) {
      return apiError("NOT_FOUND", "Case not found or unauthorized.", 404);
    }

    return apiSuccess({
      case: {
        ...caseRec,
        case_id: caseRec.case_number || caseRec.id,
        verdict: caseRec.threat_verdict || caseRec.verdict || "CLEAN",
      },
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to retrieve case details.", 500);
  }
}
