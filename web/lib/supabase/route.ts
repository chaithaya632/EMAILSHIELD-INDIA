/**
 * web/lib/supabase/route.ts
 * Request-scoped Supabase client helper specifically designed for API Route Handlers.
 * Handles both HTTP-only cookies and Authorization: Bearer <jwt> headers.
 */

import { createServerClient, type CookieOptions } from "@supabase/ssr";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

export async function createRouteClient(request?: NextRequest) {
  const cookieStore = cookies();
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://wajnscjisvtdwohdcnnl.supabase.co";
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "sb_publishable_wF0aXuO4PUuTso83hvWSZg_3Ltyxz5Y";

  // Check for Authorization: Bearer <token> header or sb-access-token cookie
  const authHeader = request?.headers.get("Authorization");
  const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.substring(7).trim() : null;
  const token = bearerToken || cookieStore.get("sb-access-token")?.value;

  const client = createServerClient(supabaseUrl, supabaseAnonKey, {
    global: token ? { headers: { Authorization: `Bearer ${token}` } } : undefined,
    cookies: {
      get(name: string) {
        return cookieStore.get(name)?.value;
      },
      set(name: string, value: string, options: CookieOptions) {
        try {
          cookieStore.set({ name, value, ...options });
        } catch {
          // ignore if response headers already sent
        }
      },
      remove(name: string, options: CookieOptions) {
        try {
          cookieStore.set({ name, value: "", ...options, maxAge: 0 });
        } catch {
          // ignore
        }
      },
    },
  });

  return client;
}

export async function getAuthenticatedUser(request?: NextRequest) {
  const cookieStore = cookies();
  const authHeader = request?.headers.get("Authorization");
  const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.substring(7).trim() : null;
  const token = bearerToken || cookieStore.get("sb-access-token")?.value;

  const client = await createRouteClient(request);
  const { data: { user }, error } = await client.auth.getUser(token || undefined);
  if (error || !user) {
    return { user: null, client, error: error || new Error("Unauthenticated") };
  }
  return { user, client, error: null };
}
