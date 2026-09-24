import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function GET(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required.", 401);
    }

    let mailboxData = null;
    const mbSafe = await client
      .from("sentinel_mailboxes_safe")
      .select("id, email_address, provider, is_active")
      .eq("user_id", user.id)
      .limit(1)
      .maybeSingle();

    if (!mbSafe.error && mbSafe.data) {
      mailboxData = mbSafe.data;
    } else {
      const mbBase = await client
        .from("sentinel_mailboxes")
        .select("id, email_address, provider, is_active")
        .eq("user_id", user.id)
        .limit(1)
        .maybeSingle();
      if (!mbBase.error && mbBase.data) {
        mailboxData = mbBase.data;
      }
    }

    const wkRes = await client
      .from("sentinel_workers")
      .select("id, desired_state, last_heartbeat")
      .eq("user_id", user.id)
      .limit(1)
      .maybeSingle();

    return apiSuccess({
      mailbox: mailboxData,
      worker: wkRes.data || null,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to retrieve settings.", 500);
  }
}

export async function POST(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required.", 401);
    }

    const body = await request.json();
    const { action, desired_state } = body;

    if (action === "set_worker_state") {
      if (!["RUNNING", "STOPPED"].includes(desired_state)) {
        return apiError("INVALID_EMAIL", "Invalid desired_state. Must be RUNNING or STOPPED.", 400);
      }

      const { data, error: updError } = await client
        .from("sentinel_workers")
        .upsert({
          user_id: user.id,
          desired_state,
          updated_at: new Date().toISOString(),
        }, { onConflict: "user_id" })
        .select()
        .single();

      if (updError) {
        return apiError("INTERNAL_ERROR", "Failed to update worker state.", 500);
      }

      return apiSuccess({
        message: `Worker desired state updated to ${desired_state}.`,
        worker: data,
      });
    }

    return apiError("INVALID_EMAIL", "Unsupported settings action.", 400);
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to execute settings action.", 500);
  }
}
