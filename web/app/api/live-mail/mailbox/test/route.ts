/**
 * web/app/api/live-mail/mailbox/test/route.ts
 * Real IMAP TLS connection test endpoint for Gmail mailboxes.
 * Authenticated users only. Enforces hostname verification and TLS.
 */

import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";
import { testGmailImapConnection } from "@/lib/imap-test";

export async function POST(request: NextRequest) {
  try {
    const { user, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to test mailbox connection.", 401);
    }

    const body = await request.json().catch(() => ({}));
    const { email, app_password } = body;

    if (!email || typeof email !== "string" || !email.includes("@")) {
      return apiError("INVALID_EMAIL", "A valid Gmail address is required.", 400);
    }

    if (!app_password || typeof app_password !== "string" || app_password.trim().length === 0) {
      return apiError("INVALID_PASSWORD", "Google App Password is required.", 400);
    }

    const testResult = await testGmailImapConnection(email, app_password);

    if (!testResult.success) {
      return apiError(
        "INVALID_PASSWORD",
        testResult.message || "Failed to connect to Gmail IMAP.",
        400
      );
    }

    return apiSuccess({
      success: true,
      message: testResult.message,
      step: testResult.step,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Internal error running connection test: " + (err?.message || "Unknown error"), 500);
  }
}
