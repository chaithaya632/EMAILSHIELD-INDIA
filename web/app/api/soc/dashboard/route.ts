/**
 * web/app/api/soc/dashboard/route.ts
 * Consolidated SOC Dashboard endpoint.
 * Executes concurrent queries under PostgreSQL Row-Level Security (RLS)
 * using the caller's request-scoped Supabase client.
 */

import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function GET(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to view SOC Dashboard.", 401);
    }

    const userId = user.id;

    // Concurrent server-side authorized queries under PostgreSQL RLS
    const [
      mailboxRes,
      workerRes,
      checkpointRes,
      casesRes,
      eventsRes,
    ] = await Promise.all([
      client.from("sentinel_mailboxes").select("*").eq("user_id", userId).limit(1).maybeSingle(),
      client.from("sentinel_workers").select("*").eq("user_id", userId).limit(1).maybeSingle(),
      client.from("sentinel_checkpoints").select("*").eq("user_id", userId).limit(1).maybeSingle(),
      client
        .from("cases")
        .select("id, case_number, subject, sender, threat_verdict, risk_score, created_at, status")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(50),
      client
        .from("sentinel_alerts")
        .select("id, user_id, channel, is_enabled")
        .eq("user_id", userId)
        .limit(20),
    ]);

    const mailbox = mailboxRes.data || null;
    const worker = workerRes.data || null;
    const checkpoint = checkpointRes.data || null;
    const cases = (casesRes.data || []).map((c: any) => ({
      ...c,
      case_id: c.case_number || c.id,
      verdict: c.threat_verdict || "CLEAN",
    }));

    // Calculate KPI metrics
    const totalCases = cases.length;
    let highCritical = 0;
    let suspicious = 0;
    let clean = 0;

    for (const c of cases) {
      const v = (c.verdict || c.threat_verdict || "").toUpperCase();
      if (v.includes("HIGH") || v.includes("CRITICAL") || v.includes("MALICIOUS")) {
        highCritical++;
      } else if (v.includes("SUSPICIOUS") || v.includes("MEDIUM")) {
        suspicious++;
      } else {
        clean++;
      }
    }

    const threatRatio = totalCases > 0 ? ((highCritical + suspicious) / totalCases) * 100 : 0;

    // Filter active triage queue (excluding demo prefixes)
    const demoPrefixes = ["CASE-ISO-", "CASE-DEMO-", "CASE-TEST-", "TEST-"];
    const triageQueue = cases
      .filter((c: any) => !demoPrefixes.some((p) => String(c.case_id).startsWith(p)) && c.status !== "CLOSED")
      .slice(0, 10);

    return apiSuccess({
      kpis: {
        total_analyzed: totalCases,
        high_critical: highCritical,
        suspicious: suspicious,
        clean: clean,
        threat_ratio: Number(threatRatio.toFixed(1)),
      },
      mailbox: mailbox
        ? {
            id: mailbox.id,
            email_address: mailbox.email_address,
            provider: mailbox.provider,
            is_active: mailbox.is_active,
          }
        : null,
      worker: worker
        ? {
            id: worker.id,
            desired_state: worker.desired_state,
            last_heartbeat: worker.last_heartbeat,
          }
        : null,
      checkpoint: checkpoint
        ? {
            last_uid: checkpoint.last_uid,
            last_poll_time: checkpoint.last_poll_time,
          }
        : null,
      recent_activity: cases.slice(0, 5),
      triage_queue: triageQueue,
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to load dashboard metrics.", 500);
  }
}
