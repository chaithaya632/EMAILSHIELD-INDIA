import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiError } from "@/lib/api-response";

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

    // Strict owner & RLS check (lookup by case_number or UUID id; alias: .eq("case_id", caseId))
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(caseId);
    const baseQuery = client.from("cases").select("*").eq("user_id", user.id);
    const { data: caseRec, error: dbError } = await (isUuid ? baseQuery.eq("id", caseId) : baseQuery.eq("case_number", caseId)).maybeSingle();

    if (dbError || !caseRec) {
      return apiError("NOT_FOUND", "Case not found or unauthorized.", 404);
    }

    const payload = caseRec.raw_json || caseRec;

    return new NextResponse(JSON.stringify(payload, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${caseId}_forensic_report.json"`,
      },
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to export JSON report.", 500);
  }
}
