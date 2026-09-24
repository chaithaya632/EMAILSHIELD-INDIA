import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function GET(request: NextRequest) {
  try {
    const { user, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "No active investigator session.", 401);
    }

    return apiSuccess({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.user_metadata?.role || "analyst",
      },
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to retrieve session.", 500);
  }
}
