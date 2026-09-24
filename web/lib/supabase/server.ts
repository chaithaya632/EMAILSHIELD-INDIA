/**
 * web/lib/supabase/server.ts
 * Request-scoped Supabase client for Server Components, Server Actions, and Route Handlers.
 * 
 * CRITICAL ARCHITECTURAL INVARIANTS:
 * 1. Zero global clients. Zero module-level user/JWT state.
 * 2. Every client instance is strictly scoped to the incoming request's cookies/headers.
 * 3. PostgreSQL RLS policies evaluate auth.uid() based exclusively on the current caller's session.
 * 4. User A's client can NEVER be reused by User B.
 * 5. service_role is strictly FORBIDDEN.
 */

import { createServerClient, type CookieOptions } from "@supabase/ssr";
import { cookies } from "next/headers";

export function createServerSupabaseClient() {
  const cookieStore = cookies();
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://wajnscjisvtdwohdcnnl.supabase.co";
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "sb_publishable_wF0aXuO4PUuTso83hvWSZg_3Ltyxz5Y";

  return createServerClient(supabaseUrl, supabaseAnonKey, {
    cookies: {
      get(name: string) {
        return cookieStore.get(name)?.value;
      },
      set(name: string, value: string, options: CookieOptions) {
        try {
          cookieStore.set({ name, value, ...options });
        } catch (error) {
          // The `set` method was called from a Server Component.
          // This can be ignored if you have middleware refreshing user sessions.
        }
      },
      remove(name: string, options: CookieOptions) {
        try {
          cookieStore.set({ name, value: "", ...options, maxAge: 0 });
        } catch (error) {
          // The `delete` method was called from a Server Component.
        }
      },
    },
  });
}
