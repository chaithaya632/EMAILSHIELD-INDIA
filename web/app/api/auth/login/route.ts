import { NextRequest } from "next/server";
import { cookies } from "next/headers";
import { createRouteClient } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password } = body;

    if (!email || !password) {
      return apiError("INVALID_EMAIL", "Email and password are required.", 400);
    }

    const supabase = await createRouteClient(request);
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.trim(),
      password,
    });

    if (error || !data.user || !data.session) {
      return apiError("UNAUTHENTICATED", error?.message || "Invalid login credentials.", 401);
    }

    // Set secure HTTP-only cookies for session isolation
    const cookieStore = cookies();
    cookieStore.set("sb-access-token", data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: data.session.expires_in,
    });
    cookieStore.set("sb-refresh-token", data.session.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    });

    return apiSuccess({
      user: {
        id: data.user.id,
        email: data.user.email,
        role: data.user.user_metadata?.role || "analyst",
      },
      expires_at: data.session.expires_at,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "An unexpected error occurred during authentication.", 500);
  }
}
