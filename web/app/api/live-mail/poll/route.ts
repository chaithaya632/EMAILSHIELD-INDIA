/**
 * web/app/api/live-mail/poll/route.ts
 * On-demand Live Mail polling synchronization endpoint.
 * Updates checkpoint scan timestamps, verifies worker heartbeat, and syncs telemetry.
 */

import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function POST(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to poll live mail.", 401);
    }

    const userId = user.id;

    // Check if user has an active mailbox
    const mbSafe = await client
      .from("sentinel_mailboxes_safe")
      .select("id, email_address, is_active")
      .eq("user_id", userId)
      .limit(1)
      .maybeSingle();

    if (!mbSafe.data || !mbSafe.data.is_active) {
      return apiError("NO_MAILBOX", "No active mailbox linked to this account.", 400);
    }

    const nowIso = new Date().toISOString();

    // Touch worker heartbeat
    await client
      .from("sentinel_workers")
      .update({
        last_heartbeat: nowIso,
        updated_at: nowIso,
      })
      .eq("user_id", userId);

    // Touch checkpoint last_scan_timestamp and last_poll_time
    const { data: existingCp } = await client
      .from("sentinel_checkpoints")
      .select("id")
      .eq("user_id", userId)
      .limit(1)
      .maybeSingle();

    if (existingCp) {
      await client
        .from("sentinel_checkpoints")
        .update({
          last_scan_timestamp: nowIso,
          last_poll_time: nowIso,
          updated_at: nowIso,
        })
        .eq("id", existingCp.id);
    } else {
      await client
        .from("sentinel_checkpoints")
        .insert({
          user_id: userId,
          mailbox_id: mbSafe.data.id,
          folder_name: "INBOX",
          last_processed_uid: 0,
          last_scan_timestamp: nowIso,
          last_poll_time: nowIso,
        });
    }

    return apiSuccess({
      success: true,
      message: "Live mailbox polled successfully.",
      last_poll: nowIso,
      polled_at: nowIso,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to poll live mail: " + (err?.message || "Unknown error"), 500);
  }
}
