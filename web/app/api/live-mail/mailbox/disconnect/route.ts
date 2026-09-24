/**
 * web/app/api/live-mail/mailbox/disconnect/route.ts
 * Disconnects authenticated user's linked mailbox and halts worker polling.
 */

import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function POST(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to disconnect mailbox.", 401);
    }

    const userId = user.id;

    // Authoritatively remove worker and linked mailbox records via CASCADE
    const { error: workerDelErr } = await client
      .from("sentinel_workers")
      .delete()
      .eq("user_id", userId);

    if (workerDelErr) {
      return apiError("INTERNAL_ERROR", "Failed to disconnect worker: " + workerDelErr.message, 500);
    }

    // Also ensure direct mailbox records are purged
    await client
      .from("sentinel_mailboxes")
      .delete()
      .eq("user_id", userId);

    // Verify mailbox is completely removed from safe view
    const { data: checkMb } = await client
      .from("sentinel_mailboxes_safe")
      .select("id")
      .eq("user_id", userId)
      .limit(1)
      .maybeSingle();

    if (checkMb) {
      return apiError("INTERNAL_ERROR", "Failed to fully disconnect mailbox from database.", 500);
    }

    return apiSuccess({
      success: true,
      message: "Mailbox disconnected and Live Mail polling stopped.",
      state: "NO_MAILBOX",
      connected: false,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to disconnect mailbox: " + (err?.message || "Unknown error"), 500);
  }
}

export async function DELETE(request: NextRequest) {
  return POST(request);
}
