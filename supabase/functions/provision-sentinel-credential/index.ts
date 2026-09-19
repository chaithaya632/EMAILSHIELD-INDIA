// =====================================================================
// EMAILSHIELD INDIA — Sentinel Credential Provisioning Boundary
// Supabase Edge Function: provision-sentinel-credential
//
// CRITICAL SECURITY INVARIANTS:
// 1. Authenticated user required (Authorization: Bearer <user_jwt>)
// 2. User identity strictly derived from verified auth context (auth.uid)
// 3. Client-supplied user_id is NEVER trusted or accepted as an override
// 4. Encrypts using Asymmetric Hybrid Envelope:
//    - AES-256-GCM with 96-bit random nonce
//    - Cryptographically bound to tenant AAD (EMAILSHIELD:purpose:user_id:key_ver)
//    - Ephemeral 256-bit DEK wrapped with Worker RSA-OAEP (SHA-256)
// 5. Zero private keys present in Edge Function (Public Key Only)
// 6. Zero service_role usage (Authenticated User PostgREST Context)
// 7. Plaintext credentials are never logged, persisted, or echoed back
// 8. Enforces idempotency and Compare-And-Swap (CAS) versioning
// =====================================================================

import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.0";

// --- Constants & Config ---
const DEFAULT_KEY_VERSION = "k1";
const CONTEXT_MAILBOX = "sentinel_mailbox_credentials";
const MAX_CIPHERTEXT_LENGTH = 8192;
const MAX_CREDENTIAL_LENGTH = 512;

// Standard CORS headers
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// --- Helper: Base64 URL-safe encoding ---
function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --- Helper: Import RSA Public Key from PEM ---
async function importPublicKeyFromPem(pem: string): Promise<CryptoKey> {
  const cleanPem = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");

  const binaryString = atob(cleanPem);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return await crypto.subtle.importKey(
    "spki",
    bytes.buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    false,
    ["encrypt"]
  );
}

// --- Main Request Handler ---
serve(async (req: Request): Promise<Response> => {
  // 1. Handle CORS Preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "Method not allowed. Only POST is supported." }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    // 2. Extract and Validate Authorization Header
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response(
        JSON.stringify({ error: "Unauthorized: Missing or invalid Authorization header." }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const workerPublicKeyPem = Deno.env.get("SENTINEL_WORKER_PUBLIC_KEY");

    if (!supabaseUrl || !supabaseAnonKey) {
      return new Response(
        JSON.stringify({ error: "Server configuration error: missing Supabase environment." }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!workerPublicKeyPem) {
      return new Response(
        JSON.stringify({ error: "Server configuration error: missing Worker Public Key." }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 3. Authenticate User via Supabase Auth (User Client Context - Zero Service Role)
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false },
    });

    const rawJwt = authHeader.replace(/^Bearer\s+/i, "").trim();
    const { data: { user }, error: authError } = rawJwt
      ? await userClient.auth.getUser(rawJwt)
      : await userClient.auth.getUser();
    if (authError || !user || !user.id) {
      return new Response(
        JSON.stringify({ error: "Unauthorized: Invalid or expired authentication token." }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const verifiedUserId = user.id;

    // 4. Parse and Validate Request Payload
    let body: any;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "Invalid JSON payload in request body." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const {
      worker_id,
      mailbox_credential,
      credential_version,
      expected_previous_version,
      idempotency_key,
      key_version,
    } = body;

    // Invariant: Never trust client-supplied user_id
    if (body.user_id && body.user_id !== verifiedUserId) {
      return new Response(
        JSON.stringify({ error: "Access denied: client cannot specify or override user_id." }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Validation: worker_id
    if (!worker_id || typeof worker_id !== "string" || !/^[0-9a-fA-F-]{36}$/.test(worker_id)) {
      return new Response(
        JSON.stringify({ error: "Invalid or missing worker_id (UUID expected)." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Validation: mailbox_credential
    if (!mailbox_credential || typeof mailbox_credential !== "string" || mailbox_credential.trim().length === 0) {
      return new Response(
        JSON.stringify({ error: "Invalid or missing mailbox_credential." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (mailbox_credential.length > MAX_CREDENTIAL_LENGTH) {
      return new Response(
        JSON.stringify({ error: `Credential exceeds maximum length of ${MAX_CREDENTIAL_LENGTH} characters.` }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Validation: credential_version
    const credVer = Number(credential_version);
    if (!Number.isInteger(credVer) || credVer <= 0) {
      return new Response(
        JSON.stringify({ error: "credential_version must be a positive integer." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const expPrevVer = (expected_previous_version !== undefined && expected_previous_version !== null)
      ? Number(expected_previous_version)
      : null;

    if (expPrevVer !== null && (!Number.isInteger(expPrevVer) || expPrevVer < 0)) {
      return new Response(
        JSON.stringify({ error: "expected_previous_version must be a non-negative integer when provided." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const cleanIdempotencyKey = (idempotency_key && typeof idempotency_key === "string" && /^[0-9a-fA-F-]{36}$/.test(idempotency_key))
      ? idempotency_key
      : null;

    const activeKeyVersion = (typeof key_version === "string" && key_version.trim().length > 0)
      ? key_version.trim()
      : DEFAULT_KEY_VERSION;

    // 5. Verify Worker Ownership Under Authenticated User Context
    const { data: workerRecord, error: workerError } = await userClient
      .from("sentinel_workers")
      .select("id, user_id")
      .eq("id", worker_id)
      .eq("user_id", verifiedUserId)
      .maybeSingle();

    if (workerError || !workerRecord) {
      return new Response(
        JSON.stringify({ error: "Ownership violation: worker does not exist or does not belong to caller." }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 6. Asymmetric Hybrid Envelope Encryption (Public Key Only)
    // Step 6a: Generate ephemeral 256-bit DEK
    const dek = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );

    // Step 6b: Export raw DEK bytes for RSA wrapping
    const rawDekBytes = await crypto.subtle.exportKey("raw", dek);

    // Step 6c: Import RSA Public Key and wrap DEK via RSA-OAEP (SHA-256)
    const rsaPublicKey = await importPublicKeyFromPem(workerPublicKeyPem);
    const wrappedDekBuffer = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      rsaPublicKey,
      rawDekBytes
    );

    // Step 6d: Encrypt plaintext credential via AES-256-GCM with tenant AAD binding
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aadString = `EMAILSHIELD:${CONTEXT_MAILBOX}:${verifiedUserId}:${activeKeyVersion}`;
    const aadBytes = new TextEncoder().encode(aadString);
    const plaintextBytes = new TextEncoder().encode(mailbox_credential);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: aadBytes,
      },
      dek,
      plaintextBytes
    );

    // Step 6e: Assemble version 2 envelope
    const b64WrappedDek = bufferToBase64Url(wrappedDekBuffer);
    const b64Nonce = bufferToBase64Url(nonce);
    const b64Ciphertext = bufferToBase64Url(ciphertextBuffer);

    const envelope = `v2:${activeKeyVersion}:${b64WrappedDek}:${b64Nonce}:${b64Ciphertext}`;

    if (envelope.length > MAX_CIPHERTEXT_LENGTH) {
      return new Response(
        JSON.stringify({ error: "Encrypted envelope exceeds maximum permitted length." }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 7. Atomic Database Invocation via Authenticated SECURITY DEFINER RPC
    const { data: rpcSuccess, error: rpcError } = await userClient.rpc(
      "rpc_set_encrypted_mailbox_credential",
      {
        p_worker_id: worker_id,
        p_ciphertext: envelope,
        p_credential_version: credVer,
        p_expected_previous_version: expPrevVer,
        p_idempotency_key: cleanIdempotencyKey,
      }
    );

    if (rpcError) {
      const errMsg = rpcError.message || "RPC execution failed";
      // Detect CAS stale version conflict
      if (errMsg.includes("Concurrent stale update rejected") || errMsg.includes("integrity_constraint_violation")) {
        return new Response(
          JSON.stringify({ error: "Conflict: credential version mismatch or concurrent update.", detail: errMsg }),
          { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      if (errMsg.includes("Ownership violation")) {
        return new Response(
          JSON.stringify({ error: "Forbidden: tenant ownership check failed." }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      return new Response(
        JSON.stringify({ error: `Provisioning failed: ${errMsg}` }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 8. Return Safe Success Confirmation (Never echo passwords or ciphertext)
    return new Response(
      JSON.stringify({
        success: Boolean(rpcSuccess),
        worker_id,
        credential_version: credVer,
        key_version: activeKeyVersion,
        timestamp: new Date().toISOString(),
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err: any) {
    // Fail-closed generic error response without leaking internal state
    return new Response(
      JSON.stringify({ error: "Internal provisioning error." }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
