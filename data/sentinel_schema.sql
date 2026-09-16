-- =====================================================================
-- EMAILSHIELD INDIA — Autonomous Sentinel Database Schema & RLS Policies
-- Phase 1: Schema & Security Foundation (Multi-User Control Plane)
-- Kernel-level tenant isolation via PostgreSQL Row Level Security (RLS)
-- =====================================================================

-- 1. Enable UUID Extension (Idempotent)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================================
-- 2. IMMUTABILITY TRIGGER FUNCTION
-- Prevents modification of user_id across all Sentinel tables.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.trg_enforce_user_id_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.user_id <> OLD.user_id THEN
        RAISE EXCEPTION 'user_id is immutable and cannot be modified';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Timestamp update trigger function
CREATE OR REPLACE FUNCTION public.trg_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- =====================================================================
-- 3. TABLE: public.sentinel_workers
-- Tracks active worker instances, state, and distributed leases.
-- =====================================================================
CREATE TABLE IF NOT EXISTS public.sentinel_workers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    desired_state TEXT NOT NULL DEFAULT 'STOPPED'
        CHECK (desired_state IN ('RUNNING', 'STOPPED')),
    actual_state TEXT NOT NULL DEFAULT 'STOPPED'
        CHECK (
            actual_state IN (
                'CREATED',
                'STARTING',
                'RUNNING',
                'STOPPING',
                'STOPPED',
                'FAILED'
            )
        ),
    poll_interval_seconds INTEGER NOT NULL DEFAULT 60
        CHECK (poll_interval_seconds BETWEEN 30 AND 3600),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_heartbeat TIMESTAMPTZ,
    last_error TEXT,
    error_count INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT uq_sentinel_worker_user UNIQUE (id, user_id),
    CONSTRAINT uq_single_worker_per_user UNIQUE (user_id)
);

-- Immutability & Timestamp triggers for sentinel_workers
DROP TRIGGER IF EXISTS trg_immutability_sentinel_workers ON public.sentinel_workers;
CREATE TRIGGER trg_immutability_sentinel_workers
    BEFORE UPDATE ON public.sentinel_workers
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

DROP TRIGGER IF EXISTS trg_timestamp_sentinel_workers ON public.sentinel_workers;
CREATE TRIGGER trg_timestamp_sentinel_workers
    BEFORE UPDATE ON public.sentinel_workers
    FOR EACH ROW EXECUTE FUNCTION public.trg_update_timestamp();

-- =====================================================================
-- 4. TABLE: public.sentinel_mailboxes
-- Stores mailbox connection parameters and blind encrypted credentials.
-- Plaintext credentials, passwords, or tokens are STRICTLY PROHIBITED.
-- =====================================================================
CREATE TABLE IF NOT EXISTS public.sentinel_mailboxes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    worker_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    provider TEXT NOT NULL
        CHECK (provider IN ('gmail', 'outlook', 'yahoo', 'zoho', 'custom')),
    email_address TEXT NOT NULL,
    imap_host TEXT NOT NULL,
    imap_port INTEGER NOT NULL DEFAULT 993,
    use_ssl BOOLEAN NOT NULL DEFAULT true,
    encrypted_credentials TEXT NOT NULL,
    auth_mechanism TEXT NOT NULL DEFAULT 'APP_PASSWORD'
        CHECK (auth_mechanism IN ('APP_PASSWORD', 'XOAUTH2')),
    is_active BOOLEAN NOT NULL DEFAULT true,
    CONSTRAINT uq_sentinel_mailbox_user UNIQUE (id, user_id),
    CONSTRAINT fk_sentinel_mailbox_worker FOREIGN KEY (worker_id, user_id)
        REFERENCES public.sentinel_workers(id, user_id) ON DELETE CASCADE,
    CONSTRAINT uq_single_mailbox_per_user UNIQUE (user_id)
);

-- Immutability & Timestamp triggers for sentinel_mailboxes
DROP TRIGGER IF EXISTS trg_immutability_sentinel_mailboxes ON public.sentinel_mailboxes;
CREATE TRIGGER trg_immutability_sentinel_mailboxes
    BEFORE UPDATE ON public.sentinel_mailboxes
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

DROP TRIGGER IF EXISTS trg_timestamp_sentinel_mailboxes ON public.sentinel_mailboxes;
CREATE TRIGGER trg_timestamp_sentinel_mailboxes
    BEFORE UPDATE ON public.sentinel_mailboxes
    FOR EACH ROW EXECUTE FUNCTION public.trg_update_timestamp();

-- =====================================================================
-- 5. TABLE: public.sentinel_checkpoints
-- Manages tenant-isolated synchronization and UID state.
-- =====================================================================
CREATE TABLE IF NOT EXISTS public.sentinel_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    worker_id UUID NOT NULL,
    mailbox_id UUID NOT NULL,
    folder_name TEXT NOT NULL DEFAULT 'INBOX',
    uid_validity BIGINT NOT NULL DEFAULT 0,
    last_processed_uid BIGINT NOT NULL DEFAULT 0,
    last_processed_msg_id TEXT,
    last_processed_date TIMESTAMPTZ,
    last_scan_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    checkpoint_hash TEXT,
    CONSTRAINT uq_sentinel_checkpoint_user UNIQUE (id, user_id),
    CONSTRAINT fk_sentinel_checkpoint_worker FOREIGN KEY (worker_id, user_id)
        REFERENCES public.sentinel_workers(id, user_id) ON DELETE CASCADE,
    CONSTRAINT fk_sentinel_checkpoint_mailbox FOREIGN KEY (mailbox_id, user_id)
        REFERENCES public.sentinel_mailboxes(id, user_id) ON DELETE CASCADE,
    CONSTRAINT uq_sentinel_checkpoint_folder UNIQUE (user_id, mailbox_id, folder_name)
);

-- Immutability trigger for sentinel_checkpoints
DROP TRIGGER IF EXISTS trg_immutability_sentinel_checkpoints ON public.sentinel_checkpoints;
CREATE TRIGGER trg_immutability_sentinel_checkpoints
    BEFORE UPDATE ON public.sentinel_checkpoints
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

-- =====================================================================
-- 6. TABLE: public.sentinel_alerts
-- Stores tenant-scoped notification configurations and dispatch metadata.
-- =====================================================================
CREATE TABLE IF NOT EXISTS public.sentinel_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    worker_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    channel TEXT NOT NULL
        CHECK (channel IN ('telegram', 'whatsapp')),
    destination_target TEXT NOT NULL,
    encrypted_dispatch_config TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    high_risk_only BOOLEAN NOT NULL DEFAULT true,
    last_dispatch_at TIMESTAMPTZ,
    dispatch_count INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT uq_sentinel_alert_user UNIQUE (id, user_id),
    CONSTRAINT fk_sentinel_alert_worker FOREIGN KEY (worker_id, user_id)
        REFERENCES public.sentinel_workers(id, user_id) ON DELETE CASCADE
);

-- Immutability trigger for sentinel_alerts
DROP TRIGGER IF EXISTS trg_immutability_sentinel_alerts ON public.sentinel_alerts;
CREATE TRIGGER trg_immutability_sentinel_alerts
    BEFORE UPDATE ON public.sentinel_alerts
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

-- =====================================================================
-- 7. PERFORMANCE & QUERY INDEXES
-- =====================================================================
CREATE INDEX IF NOT EXISTS idx_sentinel_workers_poll 
    ON public.sentinel_workers(desired_state, actual_state, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_sentinel_workers_heartbeat 
    ON public.sentinel_workers(last_heartbeat);

CREATE INDEX IF NOT EXISTS idx_sentinel_mailboxes_user_id 
    ON public.sentinel_mailboxes(user_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_mailboxes_worker_id 
    ON public.sentinel_mailboxes(worker_id);

CREATE INDEX IF NOT EXISTS idx_sentinel_checkpoints_user_id 
    ON public.sentinel_checkpoints(user_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_checkpoints_worker_id 
    ON public.sentinel_checkpoints(worker_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_checkpoints_mailbox_id 
    ON public.sentinel_checkpoints(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_checkpoints_lookup 
    ON public.sentinel_checkpoints(user_id, mailbox_id, folder_name);

CREATE INDEX IF NOT EXISTS idx_sentinel_alerts_user_id 
    ON public.sentinel_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_alerts_worker_id 
    ON public.sentinel_alerts(worker_id);
CREATE INDEX IF NOT EXISTS idx_sentinel_alerts_enabled 
    ON public.sentinel_alerts(user_id, is_enabled);

-- =====================================================================
-- 8. ROW LEVEL SECURITY (RLS) ACTIVATION
-- =====================================================================
ALTER TABLE public.sentinel_workers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_mailboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sentinel_alerts ENABLE ROW LEVEL SECURITY;

-- =====================================================================
-- 9. RLS POLICIES — public.sentinel_workers
-- =====================================================================
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

-- =====================================================================
-- 10. RLS POLICIES — public.sentinel_mailboxes (CREDENTIAL BLIND STORAGE)
-- Authenticated clients cannot read credential-bearing rows directly through PostgREST.
-- SELECT access is denied via USING (false). Safe metadata is exposed via view below.
-- =====================================================================
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

-- Explicitly revoke column-level SELECT and UPDATE on encrypted_credentials
REVOKE SELECT (encrypted_credentials) ON public.sentinel_mailboxes FROM authenticated, anon, public;
REVOKE UPDATE (encrypted_credentials) ON public.sentinel_mailboxes FROM authenticated, anon, public;

-- Safe metadata projection view (omitting encrypted_credentials)
CREATE OR REPLACE VIEW public.sentinel_mailboxes_safe AS
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
    is_active
FROM public.sentinel_mailboxes;

-- =====================================================================
-- 11. RLS POLICIES — public.sentinel_checkpoints
-- =====================================================================
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

-- =====================================================================
-- 12. RLS POLICIES — public.sentinel_alerts
-- =====================================================================
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

-- Revoke column-level SELECT and UPDATE on encrypted_dispatch_config
REVOKE SELECT (encrypted_dispatch_config) ON public.sentinel_alerts FROM authenticated, anon, public;
REVOKE UPDATE (encrypted_dispatch_config) ON public.sentinel_alerts FROM authenticated, anon, public;
