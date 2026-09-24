/**
 * web/lib/api-response.ts
 * Standardized, sanitized API Response and Error utilities for EMAILSHIELD INDIA.
 * Prevents secret leakage, stack traces, and internal database details.
 */

import { NextResponse } from "next/server";

export type ApiErrorCode =
  | "UNAUTHENTICATED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "BAD_REQUEST"
  | "NO_MAILBOX"
  | "PAYLOAD_TOO_LARGE"
  | "INVALID_EMAIL"
  | "INVALID_PASSWORD"
  | "PASSWORD_MISMATCH"
  | "USER_EXISTS"
  | "REGISTRATION_FAILED"
  | "RATE_LIMITED"
  | "DECRYPTION_FAILED"
  | "IMAP_ERROR"
  | "INTERNAL_ERROR";

export function apiSuccess<T>(data: T, status = 200, headers?: HeadersInit) {
  return NextResponse.json(
    {
      success: true,
      data,
    },
    { status, headers }
  );
}

export function apiError(
  code: ApiErrorCode,
  message: string,
  status = 400,
  detailsOrHeaders?: Record<string, unknown> | HeadersInit
) {
  // Determine if the 4th argument is response headers or error details
  let sanitizedDetails: Record<string, unknown> | undefined;
  let headers: HeadersInit | undefined;

  if (detailsOrHeaders) {
    // If it looks like HTTP headers (has Cache-Control or Pragma), treat as headers
    const asRecord = detailsOrHeaders as Record<string, unknown>;
    if (asRecord["Cache-Control"] || asRecord["Pragma"]) {
      headers = detailsOrHeaders as HeadersInit;
    } else {
      sanitizedDetails = { ...asRecord };
      const forbiddenKeys = [
        "password", "token", "jwt", "key", "secret", "cookie",
        "authorization", "service_role", "master_key", "private_key"
      ];
      for (const k of Object.keys(sanitizedDetails)) {
        if (forbiddenKeys.some((f) => k.toLowerCase().includes(f))) {
          delete sanitizedDetails[k];
        }
      }
    }
  }

  return NextResponse.json(
    {
      success: false,
      error: {
        code,
        message,
        details: sanitizedDetails,
      },
    },
    { status, headers }
  );
}
