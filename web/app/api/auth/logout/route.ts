import { NextRequest } from "next/server";
import { cookies } from "next/headers";
import { createRouteClient } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function POST(request: NextRequest) {
  try {
    const supabase = await createRouteClient(request);
    const { error } = await supabase.auth.signOut();

    // Clear session cookies explicitly
    const cookieStore = cookies();
    cookieStore.delete("sb-access-token");
    cookieStore.delete("sb-refresh-token");

    if (error) {
      return apiError("INTERNAL_ERROR", error.message, 500);
    }

    return apiSuccess({ message: "Signed out successfully." });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to sign out.", 500);
  }
}
