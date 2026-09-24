-- =====================================================================
-- EMAILSHIELD INDIA — ADDITIVE SECURITY DEFINER RPC
-- rpc_get_own_mailbox_credential
-- =====================================================================
--
-- PURPOSE:
--   Allows the authenticated user to retrieve ONLY their own
--   encrypted mailbox credential via auth.uid() ownership.
--
-- SECURITY MODEL:
--   1. SECURITY DEFINER with search_path = public
--   2. Ownership derived EXCLUSIVELY from auth.uid()
--   3. Zero function parameters — caller CANNOT supply user_id/mailbox_id
--   4. Column-level REVOKE on encrypted_credentials is PRESERVED
--   5. sentinel_mailboxes_safe view is UNCHANGED
--   6. Existing RLS policies are UNCHANGED
--   7. Existing tables/columns/views are UNCHANGED
--
-- GRANT MODEL:
--   - EXECUTE granted to: authenticated
--   - EXECUTE revoked from: PUBLIC, anon
--   - sentinel_worker_role uses rpc_fetch_leased_mailbox_credential instead
--
-- ADDITIVE CHANGE ONLY:
--   Existing Tables Modified:  NO
--   Existing Columns Modified: NO
--   Existing RLS Policies Modified: NO
--   Existing Views Modified: NO
-- =====================================================================

CREATE OR REPLACE FUNCTION public.rpc_get_own_mailbox_credential()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_ciphertext TEXT;
    v_caller_id UUID;
BEGIN
    -- 1. Obtain authenticated caller identity from Supabase JWT
    v_caller_id := auth.uid();

    IF v_caller_id IS NULL THEN
        RAISE EXCEPTION 'Authentication required'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- 2. Retrieve encrypted credential for the caller's own active mailbox ONLY
    SELECT public.sentinel_mailboxes.encrypted_credentials
    INTO v_ciphertext
    FROM public.sentinel_mailboxes
    WHERE public.sentinel_mailboxes.user_id = v_caller_id
      AND public.sentinel_mailboxes.is_active = true
    LIMIT 1;

    -- 3. Fail safely if no active mailbox exists
    IF v_ciphertext IS NULL THEN
        RAISE EXCEPTION 'No active mailbox credential found'
            USING ERRCODE = 'no_data_found';
    END IF;

    RETURN v_ciphertext;
END;
$$;

-- =====================================================================
-- PRIVILEGES: Strictly scoped to authenticated role only
-- =====================================================================

REVOKE EXECUTE ON FUNCTION public.rpc_get_own_mailbox_credential() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.rpc_get_own_mailbox_credential() FROM anon;
GRANT EXECUTE ON FUNCTION public.rpc_get_own_mailbox_credential() TO authenticated;
