/**
 * web/lib/supabase/client.ts
 * Browser Supabase client using @supabase/ssr.
 * 
 * IMPORTANT:
 * - Does NOT store JWTs or credentials in localStorage.
 * - Relies on secure HTTP-only cookies managed by Next.js server.
 * - Does NOT use service_role.
 */

import { createBrowserClient } from "@supabase/ssr";

export function createClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://wajnscjisvtdwohdcnnl.supabase.co";
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "sb_publishable_wF0aXuO4PUuTso83hvWSZg_3Ltyxz5Y";

  return createBrowserClient(supabaseUrl, supabaseAnonKey);
}
