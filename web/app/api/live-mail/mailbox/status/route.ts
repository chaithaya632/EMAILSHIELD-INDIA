/**
 * web/app/api/live-mail/mailbox/status/route.ts
 * Authoritative endpoint for checking authenticated user's linked mailbox and worker state.
 */

import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

function maskEmail(email: string): string {
  if (!email || !email.includes("@")) return email;
  const [local, domain] = email.split("@");
  if (local.length <= 2) return `${local[0]}***@${domain}`;
  return `${local.slice(0, 2)}***${local.slice(-1)}@${domain}`;
}

export async function GET(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to query mailbox status.", 401);
    }

    const userId = user.id;

    // Fetch mailbox from safe projection view
    let mailbox: any = null;
    const mbSafe = await client
      .from("sentinel_mailboxes_safe")
      .select("id, email_address, provider, is_active, created_at, updated_at")
      .eq("user_id", userId)
      .limit(1)
      .maybeSingle();

    if (!mbSafe.error && mbSafe.data) {
      mailbox = mbSafe.data;
    } else {
      const mbBase = await client
        .from("sentinel_mailboxes")
        .select("id, email_address, provider, is_active, created_at, updated_at")
        .eq("user_id", userId)
        .limit(1)
        .maybeSingle();
      if (!mbBase.error && mbBase.data) {
        mailbox = mbBase.data;
      }
    }

    // Fetch worker status
    const wkRes = await client
      .from("sentinel_workers")
      .select("id, desired_state, actual_state, last_heartbeat, last_error, error_count")
      .eq("user_id", userId)
      .limit(1)
      .maybeSingle();

    const worker = wkRes.data || null;

    if (!mailbox || !mailbox.is_active) {
      return apiSuccess({
        state: "NO_MAILBOX",
        connected: false,
        mailbox: null,
        worker: worker
          ? {
              id: worker.id,
              desired_state: worker.desired_state,
              actual_state: worker.actual_state,
              last_heartbeat: worker.last_heartbeat,
            }
          : null,
      });
    }

    // Authoritative State Machine resolution
    let state: "CONNECTED" | "ACTIVE" | "WORKER_ERROR" = "CONNECTED";
    if (worker?.actual_state === "FAILED" || (worker?.error_count && worker.error_count > 5)) {
      state = "WORKER_ERROR";
    } else if (worker?.desired_state === "RUNNING") {
      state = "ACTIVE";
    } else {
      state = "CONNECTED";
    }

    return apiSuccess({
      state,
      connected: true,
      mailbox: {
        id: mailbox.id,
        email_address: maskEmail(mailbox.email_address),
        raw_email_for_display: maskEmail(mailbox.email_address),
        provider: mailbox.provider,
        is_active: mailbox.is_active,
        created_at: mailbox.created_at,
      },
      worker: worker
        ? {
            id: worker.id,
            desired_state: worker.desired_state,
            actual_state: worker.actual_state,
            last_heartbeat: worker.last_heartbeat,
          }
        : null,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to retrieve mailbox status: " + (err?.message || "Unknown error"), 500);
  }
}
