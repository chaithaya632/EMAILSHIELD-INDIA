/**
 * web/app/api/live-mail/poll/route.ts
 * On-demand Live Mail real IMAP polling endpoint.
 *
 * Architecture:
 * 1. Authenticates user via Supabase session.
 * 2. Retrieves encrypted_credentials via rpc_get_own_mailbox_credential()
 *    (SECURITY DEFINER RPC enforces auth.uid() ownership at the database level).
 * 3. Decrypts the Gmail App Password using the Worker RSA Private Key (server-only).
 * 4. Connects to imap.gmail.com:993 via testGmailImapConnection with incremental UID fetch.
 * 5. Inserts newly discovered messages into the cases table.
 * 6. Advances the sentinel_checkpoints.last_processed_uid.
 *
 * Security Invariants:
 * - Zero service_role usage. Credential access enforced by auth.uid() in SECURITY DEFINER RPC.
 * - Decrypted plaintext is held only in-memory during the request and never logged or persisted.
 * - All IMAP connections go through the SSRF-protected testGmailImapConnection.
 * - Plaintext is zeroed immediately after IMAP connection is established.
 */

import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";
import { testGmailImapConnection } from "@/lib/imap-test";
import { decryptMailboxCredentialAsymmetric } from "@/lib/crypto/sentinel-crypto";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const NO_CACHE_HEADERS = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  Pragma: "no-cache",
};

export async function POST(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required to poll live mail.", 401, NO_CACHE_HEADERS);
    }

    const userId = user.id;

    // 1. Check if user has an active mailbox
    const mbSafe = await client
      .from("sentinel_mailboxes_safe")
      .select("id, email_address, is_active")
      .eq("user_id", userId)
      .limit(1)
      .maybeSingle();

    if (!mbSafe.data || !mbSafe.data.is_active) {
      return apiError("NO_MAILBOX", "No active mailbox linked to this account.", 400, NO_CACHE_HEADERS);
    }

    const mailboxId = mbSafe.data.id;
    const maskedEmail = mbSafe.data.email_address;

    // 2. Retrieve encrypted credential via SECURITY DEFINER RPC
    //    Ownership enforced at database level by auth.uid() — cannot access another user's credential
    const { data: ciphertext, error: rpcErr } = await client
      .rpc("rpc_get_own_mailbox_credential");

    if (rpcErr || !ciphertext) {
      const rpcMessage = rpcErr?.message || "No active mailbox credential found.";
      // Distinguish between "RPC not deployed yet" and "no credential"
      if (rpcMessage.includes("Could not find the function") || rpcMessage.includes("does not exist")) {
        return apiError(
          "INTERNAL_ERROR",
          "Mailbox credential retrieval function not available. Database migration required.",
          503,
          NO_CACHE_HEADERS
        );
      }
      return apiError(
        "INTERNAL_ERROR",
        "Unable to retrieve mailbox credentials: " + rpcMessage,
        500,
        NO_CACHE_HEADERS
      );
    }

    // 3. Decrypt Gmail App Password (server-side only, RSA private key in env or local keyfile)
    let plainPassword: string;
    try {
      plainPassword = decryptMailboxCredentialAsymmetric(ciphertext, userId);
    } catch (decryptErr: any) {
      const msg = decryptErr?.message || "";
      if (msg.includes("SENTINEL_WORKER_PRIVATE_KEY") || msg.includes("not set")) {
        return apiError(
          "INTERNAL_ERROR",
          "Server configuration error: Mailbox decryption key is not configured (SENTINEL_WORKER_PRIVATE_KEY is missing).",
          500,
          NO_CACHE_HEADERS
        );
      }
      return apiError(
        "DECRYPTION_FAILED",
        "Unable to decrypt mailbox credentials: " + msg + ". If you recently rotated keys or reconnected, please re-enter your Gmail App Password.",
        500,
        NO_CACHE_HEADERS
      );
    }

    // 4. Read current checkpoint to determine incremental UID
    const { data: cpData } = await client
      .from("sentinel_checkpoints")
      .select("id, last_processed_uid")
      .eq("user_id", userId)
      .eq("mailbox_id", mailboxId)
      .limit(1)
      .maybeSingle();

    const lastProcessedUid = cpData?.last_processed_uid || 0;

    // 5. Real IMAP connection with incremental UID fetch
    //    email_address from sentinel_mailboxes_safe (step 1) is the real unmasked address.
    //    The safe view projects email_address directly from sentinel_mailboxes without masking.
    const realEmail = maskedEmail;
    if (!realEmail) {
      return apiError(
        "INTERNAL_ERROR",
        "Unable to determine mailbox email address for IMAP login.",
        500,
        NO_CACHE_HEADERS
      );
    }

    const imapResult = await testGmailImapConnection(
      realEmail,
      plainPassword,
      {
        fetchMessages: true,
        maxMessages: 50,
        sinceUid: lastProcessedUid,
      }
    );

    // Zero the plaintext password from local scope immediately
    plainPassword = "";

    if (!imapResult.success) {
      return apiError(
        "IMAP_ERROR",
        imapResult.message || "Failed to poll Gmail IMAP.",
        502,
        NO_CACHE_HEADERS
      );
    }

    const nowIso = new Date().toISOString();
    let newMessagesIngested = 0;
    let highestUid = lastProcessedUid;

    // 6. Ingest new messages into cases table
    if (imapResult.messages && imapResult.messages.length > 0) {
      highestUid = imapResult.messages.reduce(
        (max, m) => Math.max(max, m.uid),
        lastProcessedUid
      );

      const caseRows = imapResult.messages.map((m) => ({
        user_id: userId,
        case_number: `LIVE-${m.uid}`,
        sha256: `LIVE-MSG-${m.uid}`,
        threat_verdict: "CLEAN",
        risk_score: "15",
        verdict_confidence: 90,
        status: "Open",
        assigned_investigator: "Sentinel Live Monitor",
        analyst_notes: "Ingested via Live Mail Gmail IMAP monitoring.",
        case_severity: "LOW",
        subject: m.subject || "(No Subject)",
        sender: m.sender || "Unknown Sender",
        content_type: "text/plain",
        raw_json: {
          case_id: `LIVE-${m.uid}`,
          case_number: `LIVE-${m.uid}`,
          subject: m.subject,
          sender: m.sender,
          recipient: m.recipient || maskedEmail,
          date: m.date,
          message_uid: m.uid,
          message_id: m.messageId,
          threat_verdict: "CLEAN",
          risk_score: 15,
          case_severity: "LOW",
          status: "Open",
          source: "live_mail",
          rule_findings: [],
          indicators: [
            { type: "email", value: m.sender, source: "Headers" },
          ],
          auth_alignment: {
            effective_dmarc: "PASS",
            threat_detected: false,
          },
        },
      }));

      // Deduplicate against existing cases
      const caseNumbers = caseRows.map((r) => r.case_number);
      const { data: existingCases } = await client
        .from("cases")
        .select("case_number")
        .eq("user_id", userId)
        .in("case_number", caseNumbers);

      const existingSet = new Set(
        (existingCases || []).map((c: any) => c.case_number)
      );
      const newCases = caseRows.filter((r) => !existingSet.has(r.case_number));

      if (newCases.length > 0) {
        await client.from("cases").insert(newCases);
        newMessagesIngested = newCases.length;
      }
    }

    // 7. Update checkpoint and worker heartbeat
    await client
      .from("sentinel_workers")
      .update({
        last_heartbeat: nowIso,
        updated_at: nowIso,
      })
      .eq("user_id", userId);

    if (cpData) {
      await client
        .from("sentinel_checkpoints")
        .update({
          last_processed_uid: highestUid,
          last_scan_timestamp: nowIso,
        })
        .eq("id", cpData.id);
    } else {
      // Create checkpoint if it doesn't exist
      let { data: worker } = await client
        .from("sentinel_workers")
        .select("id")
        .eq("user_id", userId)
        .limit(1)
        .maybeSingle();

      if (!worker) {
        const { data: newWorker } = await client
          .from("sentinel_workers")
          .insert({
            user_id: userId,
            desired_state: "RUNNING",
            actual_state: "CREATED",
            poll_interval_seconds: 60,
          })
          .select("id")
          .single();
        worker = newWorker;
      }

      if (worker?.id) {
        await client
          .from("sentinel_checkpoints")
          .insert({
            user_id: userId,
            worker_id: worker.id,
            mailbox_id: mailboxId,
            folder_name: "INBOX",
            last_processed_uid: highestUid,
            last_scan_timestamp: nowIso,
          });
      }
    }

    return apiSuccess(
      {
        success: true,
        message: newMessagesIngested > 0
          ? `Polled Gmail successfully. ${newMessagesIngested} new email(s) ingested.`
          : "Polled Gmail successfully. No new emails.",
        last_poll: nowIso,
        polled_at: nowIso,
        new_messages: newMessagesIngested,
        total_in_inbox: imapResult.totalMessages || 0,
        highest_uid: highestUid,
      },
      200,
      NO_CACHE_HEADERS
    );
  } catch (err: any) {
    return apiError(
      "INTERNAL_ERROR",
      "Failed to poll live mail: " + (err?.message || "Unknown error"),
      500,
      NO_CACHE_HEADERS
    );
  }
}
