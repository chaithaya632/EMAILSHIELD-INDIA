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

    // Build CSV formatted indicators
    const headers = "Case_ID,Subject,Sender,Verdict,Risk_Score,SHA256,Created_At\n";
    const escapeCsv = (str: any) => `"${String(str || "").replace(/"/g, '""')}"`;
    const row = [
      escapeCsv(caseRec.case_number || caseRec.id),
      escapeCsv(caseRec.subject),
      escapeCsv(caseRec.sender),
      escapeCsv(caseRec.threat_verdict || caseRec.verdict || "CLEAN"),
      escapeCsv(caseRec.risk_score),
      escapeCsv(caseRec.sha256),
      escapeCsv(caseRec.created_at),
    ].join(",");

    const csvContent = headers + row;

    return new NextResponse(csvContent, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${caseId}_indicators.csv"`,
      },
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to export CSV report.", 500);
  }
}
