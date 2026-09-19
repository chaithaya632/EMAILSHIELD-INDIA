-- =====================================================================
-- PHASE 5C REMEDIATION: SECURE MAILBOX SAFE PROJECTION VIEW
-- =====================================================================
-- Description: Enforce row-level tenant isolation directly inside the safe
-- view definition (WHERE user_id = auth.uid()) and enable security_barrier
-- to prevent query planner / user-predicate pushdown leaks.
-- Preserves blind credential storage (encrypted_credentials excluded).
-- =====================================================================

CREATE OR REPLACE VIEW public.sentinel_mailboxes_safe
WITH (security_barrier = true) AS
SELECT 
    id,
    user_id,
    worker_id,
    created_at,
    updated_at,
    provider,
    email_address,
    imap_host,
    imap_port,
    use_ssl,
    auth_mechanism,
    is_active,
    credential_version,
    credential_status
FROM public.sentinel_mailboxes
WHERE user_id = auth.uid();

-- Privilege lockdown: Ensure anon, public, and worker roles are strictly revoked,
-- and SELECT is granted only to authenticated users.
REVOKE ALL ON public.sentinel_mailboxes_safe FROM anon, public, sentinel_worker_role, sentinel_worker_daemon;
GRANT SELECT ON public.sentinel_mailboxes_safe TO authenticated;
