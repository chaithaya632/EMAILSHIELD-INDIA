/**
 * web/app/api/auth/register/route.ts
 * Secure User Registration endpoint for EMAILSHIELD INDIA.
 * Integrates with Supabase Auth, enforces client-side & server-side validation,
 * ensures default "analyst" role without privilege escalation, and sets HTTP-only session cookies.
 */

import { NextRequest } from "next/server";
import { cookies } from "next/headers";
import { createRouteClient } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { fullName, email, password, confirmPassword } = body;

    // Validate email
    if (!email || typeof email !== "string" || !EMAIL_REGEX.test(email.trim())) {
      return apiError("INVALID_EMAIL", "Enter a valid email address.", 400);
    }

    // Validate password presence
    if (!password || typeof password !== "string" || password.length === 0) {
      return apiError("INVALID_PASSWORD", "Password is required.", 400);
    }

    // Validate confirm password presence
    if (!confirmPassword || typeof confirmPassword !== "string") {
      return apiError("INVALID_PASSWORD", "Confirm password is required.", 400);
    }

    // Check passwords match
    if (password !== confirmPassword) {
      return apiError("PASSWORD_MISMATCH", "Passwords do not match.", 400);
    }

    const sanitizedFullName = (fullName || "").trim();
    const supabase = await createRouteClient(request);

    // Default role is strictly 'analyst'. User-supplied roles are rejected.
    const { data, error } = await supabase.auth.signUp({
      email: email.trim().toLowerCase(),
      password,
      options: {
        data: {
          full_name: sanitizedFullName,
          display_name: sanitizedFullName,
          role: "analyst",
        },
      },
    });

    if (error) {
      const errStr = (error.message || "").toLowerCase();
      if (
        errStr.includes("already registered") ||
        errStr.includes("already exists") ||
        errStr.includes("user_already_exists")
      ) {
        return apiError("USER_EXISTS", "An account with this email already exists.", 409);
      }
      if (errStr.includes("password")) {
        return apiError("INVALID_PASSWORD", error.message, 400);
      }
      return apiError("REGISTRATION_FAILED", "Unable to create your account right now. Please try again.", 400);
    }

    if (!data.user) {
      return apiError("REGISTRATION_FAILED", "Unable to create your account right now. Please try again.", 400);
    }

    const cookieStore = cookies();
    const sessionCreated = Boolean(data.session);

    // If session returned (email confirmation disabled or auto-confirmed), establish HTTP-only session
    if (data.session) {
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

      // Safely initialize profile under user's RLS
      try {
        await supabase.from("profiles").upsert({
          id: data.user.id,
          display_name: sanitizedFullName || data.user.email,
        });
      } catch {
        // Non-fatal if profiles table trigger or policy handles it
      }
    }

    return apiSuccess({
      user: {
        id: data.user.id,
        email: data.user.email,
        role: "analyst",
      },
      session_created: sessionCreated,
      message: sessionCreated
        ? "Account created successfully."
        : "Account created. Please check your email to confirm your account before logging in.",
    });
  } catch {
    return apiError("INTERNAL_ERROR", "Unable to create your account right now. Please try again.", 500);
  }
}
