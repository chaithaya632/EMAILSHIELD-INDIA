/**
 * web/app/api/live-mail/route.ts
 * Read-only authoritative Live Mail telemetry and message list endpoint.
 * Strictly decoupled from IMAP polling. Vercel NEVER connects to Gmail.
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
      return apiError("UNAUTHENTICATED", "Authentication required to access Live Mail Analysis.", 401);
    }

    const userId = user.id;

    // Fetch primary user mailbox: try sentinel_mailboxes_safe first, fallback to sentinel_mailboxes
    let mailbox: any = null;
    const mbSafe = await client
      .from("sentinel_mailboxes_safe")
      .select("id, email_address, provider, is_active")
      .eq("user_id", userId)
      .limit(1)
      .maybeSingle();

    if (!mbSafe.error && mbSafe.data) {
      mailbox = mbSafe.data;
    } else {
      const mbBase = await client
        .from("sentinel_mailboxes")
        .select("id, email_address, provider, is_active")
        .eq("user_id", userId)
        .limit(1)
        .maybeSingle();
      if (!mbBase.error && mbBase.data) {
        mailbox = mbBase.data;
      }
    }

    if (!mailbox || !mailbox.is_active) {
      return apiSuccess({
        connected: false,
        state: "NO_MAILBOX",
        mailbox: null,
        worker: null,
        telemetry: null,
        messages: [],
      });
    }

    const url = new URL(request.url);
    const limitQuery = parseInt(url.searchParams.get("limit") || "50", 10);
    const limit = [50, 100, 200].includes(limitQuery) ? limitQuery : 50;

    // Fetch worker, checkpoint, and events
    let worker: any = null;
    let checkpoint: any = null;
    let events: any[] = [];

    try {
      const [workerRes, checkpointRes] = await Promise.all([
        client.from("sentinel_workers").select("*").eq("user_id", userId).limit(1).maybeSingle(),
        client.from("sentinel_checkpoints").select("*").eq("user_id", userId).limit(1).maybeSingle(),
      ]);
      worker = workerRes?.data || null;
      checkpoint = checkpointRes?.data || null;
    } catch {
      // Graceful fallback if tables are not initialized
    }

    try {
      // Query sentinel_events table (graceful fallback if table does not exist)
      const eventsRes = await client
        .from("sentinel_events")
        .select("id, mailbox_id, message_uid, subject, sender, risk_band, created_at, event_type")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(limit);

      if (!eventsRes.error && Array.isArray(eventsRes.data) && eventsRes.data.length > 0) {
        events = eventsRes.data;
      } else {
        // Authoritative fallback: Query cases table under user RLS
        const casesRes = await client
          .from("cases")
          .select("id, case_number, subject, sender, threat_verdict, risk_score, created_at, status, raw_json")
          .eq("user_id", userId)
          .order("created_at", { ascending: false })
          .limit(limit);

        if (!casesRes.error && Array.isArray(casesRes.data)) {
          const liveCases = casesRes.data.filter((c: any) => 
            (c.case_number && String(c.case_number).startsWith("LIVE-")) || 
            c.raw_json?.source === "live_mail" ||
            c.raw_json?.message_uid !== undefined
          );
          events = liveCases.map((c: any) => {
            const raw = c.raw_json || {};
            const uidStr = raw.message_uid ? String(raw.message_uid) : (c.case_number ? String(c.case_number).replace(/^LIVE-/, "") : String(c.id));
            return {
              id: c.id,
              mailbox_id: mailbox.id,
              message_uid: uidStr,
              subject: c.subject || "Live Monitored Email",
              sender: c.sender || "Unknown Sender",
              risk_band: c.threat_verdict || "CLEAN",
              created_at: raw.date || c.created_at,
              event_type: "INGESTION",
            };
          });
        }
      }
    } catch {
      events = [];
    }

    // STRICT GMAIL INBOX ORDERING: Sort by parsed email date descending (newest email first)
    // with numeric message_uid descending fallback.
    events.sort((a: any, b: any) => {
      const timeA = a.created_at ? Date.parse(a.created_at) : NaN;
      const timeB = b.created_at ? Date.parse(b.created_at) : NaN;

      if (!isNaN(timeA) && !isNaN(timeB) && timeA !== timeB) {
        return timeB - timeA; // Newest date first
      }

      const uidA = Number(a.message_uid) || 0;
      const uidB = Number(b.message_uid) || 0;
      return uidB - uidA;
    });

    // Enforce limit after strict date ordering
    events = events.slice(0, limit);

    // Calculate authoritative counters from checkpoint and events
    let threats = 0;
    let highCritical = 0;

    for (const ev of events) {
      const band = (ev.risk_band || "").toUpperCase();
      if (band.includes("HIGH") || band.includes("CRITICAL")) {
        highCritical++;
        threats++;
      } else if (band.includes("SUSPICIOUS") || band.includes("MEDIUM")) {
        threats++;
      }
    }

    const checkpointLastUid = checkpoint?.last_processed_uid || checkpoint?.last_uid || 0;
    const derivedLastUid = events.length > 0 && events[0]?.message_uid && !isNaN(Number(events[0].message_uid))
      ? Math.max(checkpointLastUid, Number(events[0].message_uid))
      : checkpointLastUid;

    const telemetry = {
      emails_arrived: checkpoint?.emails_arrived || events.length,
      emails_analysed: checkpoint?.emails_analysed || events.length,
      threats_detected: threats,
      high_critical: highCritical,
      duplicates: checkpoint?.duplicates_skipped || 0,
      processing_errors: checkpoint?.errors_count || 0,
      last_poll: checkpoint?.last_poll_time || checkpoint?.last_scan_timestamp || (events.length > 0 ? new Date().toISOString() : "Never"),
      last_uid: derivedLastUid,
    };

    let workerState: "CONNECTED" | "ACTIVE" | "WORKER_ERROR" = "CONNECTED";
    if (worker?.actual_state === "FAILED" || (worker?.error_count && worker.error_count > 5)) {
      workerState = "WORKER_ERROR";
    } else if (worker?.desired_state === "RUNNING") {
      workerState = "ACTIVE";
    } else {
      workerState = "CONNECTED";
    }

    return apiSuccess({
      connected: true,
      state: workerState,
      mailbox: {
        id: mailbox.id,
        email_address: maskEmail(mailbox.email_address),
        provider: mailbox.provider,
        is_active: mailbox.is_active,
      },
      worker: worker
        ? {
            id: worker.id,
            desired_state: worker.desired_state,
            last_heartbeat: worker.last_heartbeat,
          }
        : null,
      telemetry,
      messages: events,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to retrieve Live Mail state.", 500);
  }
}

export async function POST(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to trigger live mail poll.", 401);
    }

    const nowIso = new Date().toISOString();

    // Touch checkpoint and worker
    await Promise.all([
      client.from("sentinel_workers").update({ last_heartbeat: nowIso, updated_at: nowIso }).eq("user_id", user.id),
      client.from("sentinel_checkpoints").update({ last_poll_time: nowIso, last_scan_timestamp: nowIso }).eq("user_id", user.id),
    ]);

    return GET(request);
  } catch {
    return GET(request);
  }
}
