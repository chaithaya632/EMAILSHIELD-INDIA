/**
 * web/lib/crypto/sentinel-crypto.ts
 * Asymmetric Hybrid Envelope Encryption for Sentinel Mailbox Credentials.
 * Encrypts credentials client-side or server-side using the Worker RSA Public Key.
 *
 * CRITICAL SECURITY INVARIANTS:
 * 1. Only the Worker RSA Public Key is held here (Zero Private Keys).
 * 2. The Next.js application CANNOT decrypt the credentials it encrypts.
 * 3. AES-256-GCM with 96-bit random nonce.
 * 4. AAD bound to tenant identity: EMAILSHIELD:sentinel_mailbox_credentials:<user_id>:k1
 * 5. Ephemeral 256-bit DEK wrapped with RSA-OAEP (SHA-256).
 * 6. Assembled envelope structure: v2:k1:<wrapped_dek_b64url>:<nonce_b64url>:<ciphertext_b64url>
 */

import crypto from "crypto";

const DEFAULT_KEY_VERSION = "k1";
const CONTEXT_MAILBOX = "sentinel_mailbox_credentials";

// Authoritative Worker Public Key (spki PEM format)
const FALLBACK_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsymppKU3TXKKwarTUq7d
0hBWkpC9A81KCGylN4XCOyGYkr3s5+gdIEnghHIfMJm5RZE34+tQ5gDtzviOAkGn
bp7j6cZ3qAXWmDcj81BTbQSqDAdHcdOevf3mu7kcPaqfGaaN+83vbQOW6PkJcvl4
wrjCs4J9PdKK0R+p3yUSI81IghDMCd6qmzDT+Lk6T5QKF4/wGubWvagtlcAlp0I6
75PTbT/h7Je+TrYI5rMPb0aIyafbHHGJAdINhLdpWKzJjy3rIyb3dx2KHZ9JBeNB
YcgFJf5CvJtzvSV/TRBEPv7u6VZmdlPeormYOoR9qL2/JX8JOY3A9ZcgTYNSSakY
twIDAQAB
-----END PUBLIC KEY-----`;

function toBase64Url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function encryptMailboxCredentialAsymmetric(
  plaintext: string,
  userId: string,
  keyVersion = DEFAULT_KEY_VERSION
): string {
  if (!plaintext || typeof plaintext !== "string") {
    throw new Error("Plaintext credential is required.");
  }
  if (!userId || typeof userId !== "string") {
    throw new Error("user_id is required for AAD tenant binding.");
  }

  const publicKeyPem =
    process.env.SENTINEL_WORKER_PUBLIC_KEY?.trim() || FALLBACK_PUBLIC_KEY_PEM;

  // 1. Generate ephemeral 256-bit Data Encryption Key (DEK)
  const dek = crypto.randomBytes(32);

  // 2. Wrap DEK using Worker RSA Public Key with RSA-OAEP (SHA-256)
  const wrappedDek = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    dek
  );

  // 3. Encrypt plaintext via AES-256-GCM with tenant AAD
  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from(
    `EMAILSHIELD:${CONTEXT_MAILBOX}:${userId.trim()}:${keyVersion}`,
    "utf-8"
  );

  const cipher = crypto.createCipheriv("aes-256-gcm", dek, nonce);
  cipher.setAAD(aad);

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext.trim(), "utf-8")),
    cipher.final(),
    cipher.getAuthTag(), // 16-byte authentication tag appended
  ]);

  // 4. Assemble v2 envelope
  const b64WrappedDek = toBase64Url(wrappedDek);
  const b64Nonce = toBase64Url(nonce);
  const b64Ciphertext = toBase64Url(ciphertext);

  return `v2:${keyVersion}:${b64WrappedDek}:${b64Nonce}:${b64Ciphertext}`;
}
