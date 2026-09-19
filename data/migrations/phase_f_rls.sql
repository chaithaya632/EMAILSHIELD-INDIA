-- =====================================================================
-- PHASE F: ROW LEVEL SECURITY (RLS) & POLICIES
-- =====================================================================

ALTER TABLE public.sentinel_workers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_mailboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_provisioning_idempotency ENABLE ROW LEVEL SECURITY;

-- Force RLS to prevent table owner bypass
ALTER TABLE public.sentinel_workers FORCE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_mailboxes FORCE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_checkpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_alerts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_provisioning_idempotency FORCE ROW LEVEL SECURITY;

-- 1. sentinel_workers policies
DROP POLICY IF EXISTS "sentinel_workers_select_own" ON public.sentinel_workers;
CREATE POLICY "sentinel_workers_select_own" ON public.sentinel_workers
    FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_workers_insert_own" ON public.sentinel_workers;
CREATE POLICY "sentinel_workers_insert_own" ON public.sentinel_workers
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_workers_update_own" ON public.sentinel_workers;
CREATE POLICY "sentinel_workers_update_own" ON public.sentinel_workers
    FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_workers_delete_own" ON public.sentinel_workers;
CREATE POLICY "sentinel_workers_delete_own" ON public.sentinel_workers
    FOR DELETE TO authenticated USING (auth.uid() = user_id);

-- 2. sentinel_mailboxes policies (BLIND CREDENTIAL STORAGE)
DROP POLICY IF EXISTS "sentinel_mailboxes_select_own" ON public.sentinel_mailboxes;
CREATE POLICY "sentinel_mailboxes_select_own" ON public.sentinel_mailboxes
    FOR SELECT TO authenticated USING (false);

DROP POLICY IF EXISTS "sentinel_mailboxes_insert_own" ON public.sentinel_mailboxes;
CREATE POLICY "sentinel_mailboxes_insert_own" ON public.sentinel_mailboxes
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_mailboxes_update_own" ON public.sentinel_mailboxes;
CREATE POLICY "sentinel_mailboxes_update_own" ON public.sentinel_mailboxes
    FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_mailboxes_delete_own" ON public.sentinel_mailboxes;
CREATE POLICY "sentinel_mailboxes_delete_own" ON public.sentinel_mailboxes
    FOR DELETE TO authenticated USING (auth.uid() = user_id);

-- Column-level revokes on raw secrets
REVOKE SELECT (encrypted_credentials) ON public.sentinel_mailboxes FROM authenticated, anon, public;
REVOKE UPDATE (encrypted_credentials) ON public.sentinel_mailboxes FROM authenticated, anon, public;

-- 3. sentinel_checkpoints policies
DROP POLICY IF EXISTS "sentinel_checkpoints_select_own" ON public.sentinel_checkpoints;
CREATE POLICY "sentinel_checkpoints_select_own" ON public.sentinel_checkpoints
    FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_checkpoints_insert_own" ON public.sentinel_checkpoints;
CREATE POLICY "sentinel_checkpoints_insert_own" ON public.sentinel_checkpoints
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_checkpoints_update_own" ON public.sentinel_checkpoints;
CREATE POLICY "sentinel_checkpoints_update_own" ON public.sentinel_checkpoints
    FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_checkpoints_delete_own" ON public.sentinel_checkpoints;
CREATE POLICY "sentinel_checkpoints_delete_own" ON public.sentinel_checkpoints
    FOR DELETE TO authenticated USING (auth.uid() = user_id);

-- 4. sentinel_alerts policies
DROP POLICY IF EXISTS "sentinel_alerts_select_own" ON public.sentinel_alerts;
CREATE POLICY "sentinel_alerts_select_own" ON public.sentinel_alerts
    FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_alerts_insert_own" ON public.sentinel_alerts;
CREATE POLICY "sentinel_alerts_insert_own" ON public.sentinel_alerts
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_alerts_update_own" ON public.sentinel_alerts;
CREATE POLICY "sentinel_alerts_update_own" ON public.sentinel_alerts
    FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "sentinel_alerts_delete_own" ON public.sentinel_alerts;
CREATE POLICY "sentinel_alerts_delete_own" ON public.sentinel_alerts
    FOR DELETE TO authenticated USING (auth.uid() = user_id);

REVOKE SELECT (encrypted_dispatch_config) ON public.sentinel_alerts FROM authenticated, anon, public;
REVOKE UPDATE (encrypted_dispatch_config) ON public.sentinel_alerts FROM authenticated, anon, public;

-- 5. sentinel_provisioning_idempotency policies
DROP POLICY IF EXISTS "provisioning_idempotency_own" ON public.sentinel_provisioning_idempotency;
CREATE POLICY "provisioning_idempotency_own" ON public.sentinel_provisioning_idempotency
    FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
