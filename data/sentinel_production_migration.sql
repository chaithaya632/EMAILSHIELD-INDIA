-- =====================================================================
-- EMAILSHIELD INDIA — Autonomous Sentinel Consolidated Production Migration
-- Phases 1 to 4C Refactored: Schema, Hardened SECURITY DEFINER RPCs,
-- Capability Tokens, Session Roles, and Asymmetric Credential Foundation
--
-- CRITICAL OPERATIONAL DIRECTIVES:
-- 1. REVIEW ONLY — DO NOT APPLY TO PRODUCTION WITHOUT EXPLICIT OPERATOR SIGN-OFF.
-- 2. Zero destructive operations: NO DROP TABLE, NO DROP COLUMN, NO TRUNCATE.
-- 3. Kernel-enforced least privilege: sentinel_worker_role has ZERO direct table access.
-- 4. Session-user bound capability tokens with SHA-256 hash storage.
-- 5. All RPCs strictly pinned with search_path = pg_catalog, public.
-- 6. Password placeholder <PRODUCTION_WORKER_DB_PASSWORD> must be injected via DBA secrets.
-- =====================================================================

-- =====================================================================
-- PHASE A: EXTENSIONS & PREREQUISITES
-- =====================================================================

CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA extensions;


-- =====================================================================
-- PHASE B: DEDICATED DATABASE ROLES & MINIMUM SCHEMA PRIVILEGES
-- =====================================================================

DO $$
BEGIN
    -- 1. Base Worker Role (NOLOGIN, NOBYPASSRLS)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker_role') THEN
        CREATE ROLE sentinel_worker_role NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;

    -- 2. Worker Daemon Login Role (LOGIN, NOBYPASSRLS, INHERITS sentinel_worker_role)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker_daemon') THEN
        CREATE ROLE sentinel_worker_daemon WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
        GRANT sentinel_worker_role TO sentinel_worker_daemon;
    END IF;
END;
$$;

-- Grant minimal schema USAGE (required to invoke functions in public and extensions)
GRANT USAGE ON SCHEMA public TO sentinel_worker_role;
GRANT USAGE ON SCHEMA extensions TO sentinel_worker_role;

-- OPERATOR CONFIGURATION NOTE:
-- In production Supabase SQL Editor, set the daemon password securely:
-- ALTER ROLE sentinel_worker_daemon WITH PASSWORD '<PRODUCTION_WORKER_DB_PASSWORD>';


-- =====================================================================
-- PHASE C: SENTINEL TABLES, CONSTRAINTS & COMPOSITE OWNERSHIP KEYS
-- =====================================================================

-- 1. TABLE: public.sentinel_workers
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
    lease_token_hash TEXT,
    last_heartbeat TIMESTAMPTZ,
    last_error TEXT,
    error_count INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT uq_sentinel_worker_user UNIQUE (id, user_id),
    CONSTRAINT uq_single_worker_per_user UNIQUE (user_id)
);

ALTER TABLE public.sentinel_workers 
    ADD COLUMN IF NOT EXISTS lease_token_hash TEXT;

-- 2. TABLE: public.sentinel_mailboxes
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
    credential_version INTEGER NOT NULL DEFAULT 1 
        CHECK (credential_version >= 1),
    credential_status TEXT NOT NULL DEFAULT 'ACTIVE' 
        CHECK (credential_status IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT uq_sentinel_mailbox_user UNIQUE (id, user_id),
    CONSTRAINT fk_sentinel_mailbox_worker FOREIGN KEY (worker_id, user_id)
        REFERENCES public.sentinel_workers(id, user_id) ON DELETE CASCADE,
    CONSTRAINT uq_single_mailbox_per_user UNIQUE (user_id)
);

ALTER TABLE public.sentinel_mailboxes 
    ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 1 
    CHECK (credential_version >= 1);

ALTER TABLE public.sentinel_mailboxes 
    ADD COLUMN IF NOT EXISTS credential_status TEXT NOT NULL DEFAULT 'ACTIVE' 
    CHECK (credential_status IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED'));

-- 3. TABLE: public.sentinel_checkpoints
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

-- 4. TABLE: public.sentinel_alerts
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

-- 5. TABLE: public.sentinel_provisioning_idempotency
CREATE TABLE IF NOT EXISTS public.sentinel_provisioning_idempotency (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    worker_id UUID NOT NULL,
    credential_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '15 minutes'),
    status TEXT NOT NULL DEFAULT 'COMPLETED' 
        CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED')),
    CONSTRAINT uq_provisioning_idempotency UNIQUE (user_id, request_id)
);


-- =====================================================================
-- PHASE D: TRIGGERS & INDEXES
-- =====================================================================

-- Trigger Functions
CREATE OR REPLACE FUNCTION public.trg_enforce_user_id_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.user_id <> OLD.user_id THEN
        RAISE EXCEPTION 'user_id is immutable and cannot be modified'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.trg_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Table Triggers
DROP TRIGGER IF EXISTS trg_immutability_sentinel_workers ON public.sentinel_workers;
CREATE TRIGGER trg_immutability_sentinel_workers
    BEFORE UPDATE ON public.sentinel_workers
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

DROP TRIGGER IF EXISTS trg_timestamp_sentinel_workers ON public.sentinel_workers;
CREATE TRIGGER trg_timestamp_sentinel_workers
    BEFORE UPDATE ON public.sentinel_workers
    FOR EACH ROW EXECUTE FUNCTION public.trg_update_timestamp();

DROP TRIGGER IF EXISTS trg_immutability_sentinel_mailboxes ON public.sentinel_mailboxes;
CREATE TRIGGER trg_immutability_sentinel_mailboxes
    BEFORE UPDATE ON public.sentinel_mailboxes
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

DROP TRIGGER IF EXISTS trg_timestamp_sentinel_mailboxes ON public.sentinel_mailboxes;
CREATE TRIGGER trg_timestamp_sentinel_mailboxes
    BEFORE UPDATE ON public.sentinel_mailboxes
    FOR EACH ROW EXECUTE FUNCTION public.trg_update_timestamp();

DROP TRIGGER IF EXISTS trg_immutability_sentinel_checkpoints ON public.sentinel_checkpoints;
CREATE TRIGGER trg_immutability_sentinel_checkpoints
    BEFORE UPDATE ON public.sentinel_checkpoints
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

DROP TRIGGER IF EXISTS trg_immutability_sentinel_alerts ON public.sentinel_alerts;
CREATE TRIGGER trg_immutability_sentinel_alerts
    BEFORE UPDATE ON public.sentinel_alerts
    FOR EACH ROW EXECUTE FUNCTION public.trg_enforce_user_id_immutability();

-- Performance & Concurrency Indexes
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

CREATE INDEX IF NOT EXISTS idx_sentinel_idempotency_lookup 
    ON public.sentinel_provisioning_idempotency(user_id, request_id, status);


-- =====================================================================
-- PHASE E: SAFE MAILBOX PROJECTION VIEW
-- =====================================================================

-- Exposes mailbox operational metadata while completely excluding encrypted_credentials
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
    is_active,
    credential_version,
    credential_status
FROM public.sentinel_mailboxes;


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


-- =====================================================================
-- PHASE G: HARDENED SECURITY DEFINER RPCS
-- =====================================================================

-- ---------------------------------------------------------------------
-- RPC 1: rpc_set_encrypted_mailbox_credential
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_set_encrypted_mailbox_credential(
    p_worker_id UUID,
    p_ciphertext TEXT,
    p_credential_version INTEGER,
    p_expected_previous_version INTEGER DEFAULT NULL,
    p_idempotency_key UUID DEFAULT NULL
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_caller_uid UUID;
    v_current_version INTEGER;
    v_updated_rows INTEGER;
BEGIN
    -- Step 1: Authentication guard (fail closed)
    v_caller_uid := auth.uid();
    IF v_caller_uid IS NULL THEN
        RAISE EXCEPTION 'Authentication required: caller identity is unauthenticated'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 2: Pre-lock Idempotency check
    IF p_idempotency_key IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM public.sentinel_provisioning_idempotency
            WHERE user_id = v_caller_uid 
              AND request_id = p_idempotency_key
              AND expires_at > now()
              AND status = 'COMPLETED'
        ) THEN
            RETURN TRUE;
        END IF;
    END IF;

    -- Step 3: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_ciphertext IS NULL OR length(trim(p_ciphertext)) = 0 THEN
        RAISE EXCEPTION 'p_ciphertext cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF length(p_ciphertext) > 8192 THEN
        RAISE EXCEPTION 'p_ciphertext exceeds maximum allowed length of 8192 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Envelope format validation:
    -- Supports v1: v1:<nonce_hex_24>:<ct_and_tag_hex>
    -- Supports v2: v2:<key_ver>:<wrapped_dek_b64>:<nonce_b64>:<ct_b64>
    IF NOT (
        p_ciphertext ~ '^v1:[0-9a-fA-F]{24}:[0-9a-fA-F]{34,}$' OR
        p_ciphertext ~ '^v2:[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+={0,2}:[a-zA-Z0-9_\-]+={0,2}:[a-zA-Z0-9_\-]+={0,2}$'
    ) THEN
        RAISE EXCEPTION 'Invalid ciphertext envelope structure'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_credential_version IS NULL OR p_credential_version <= 0 THEN
        RAISE EXCEPTION 'p_credential_version must be a positive integer (got %)', p_credential_version
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 4: Verify tenant ownership of target worker
    IF NOT EXISTS (
        SELECT 1 FROM public.sentinel_workers
        WHERE id = p_worker_id AND user_id = v_caller_uid
    ) THEN
        RAISE EXCEPTION 'Ownership violation: worker % does not belong to caller %', 
            p_worker_id, v_caller_uid
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    -- Step 5: Lock mailbox row and retrieve current version
    SELECT credential_version INTO v_current_version
    FROM public.sentinel_mailboxes
    WHERE worker_id = p_worker_id AND user_id = v_caller_uid
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Step 5b: Re-check idempotency under mailbox row lock to eliminate concurrent race
    IF p_idempotency_key IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM public.sentinel_provisioning_idempotency
            WHERE user_id = v_caller_uid 
              AND request_id = p_idempotency_key
              AND expires_at > now()
              AND status = 'COMPLETED'
        ) THEN
            RETURN TRUE;
        END IF;
    END IF;

    -- Step 6: Compare-And-Swap (CAS) check
    IF p_expected_previous_version IS NOT NULL THEN
        IF v_current_version IS DISTINCT FROM p_expected_previous_version THEN
            RAISE EXCEPTION 'Concurrent stale update rejected (CAS failed): expected %, found %',
                p_expected_previous_version, v_current_version
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;

    -- Step 7: Enforce monotonically increasing credential versions
    IF v_current_version IS NOT NULL AND p_credential_version <= v_current_version THEN
        RAISE EXCEPTION 'Credential version rollback rejected: current version is %, proposed version is %',
            v_current_version, p_credential_version
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- Step 8: Atomic update of credentials
    UPDATE public.sentinel_mailboxes
    SET 
        encrypted_credentials = p_ciphertext,
        credential_version = p_credential_version,
        credential_status = 'ACTIVE',
        updated_at = now()
    WHERE worker_id = p_worker_id AND user_id = v_caller_uid;

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;

    -- Step 9: Record idempotency record if requested
    IF p_idempotency_key IS NOT NULL AND v_updated_rows = 1 THEN
        INSERT INTO public.sentinel_provisioning_idempotency (
            request_id,
            user_id,
            worker_id,
            credential_version,
            status
        ) VALUES (
            p_idempotency_key,
            v_caller_uid,
            p_worker_id,
            p_credential_version,
            'COMPLETED'
        )
        ON CONFLICT (user_id, request_id) DO UPDATE
            SET credential_version = EXCLUDED.credential_version,
                status = 'COMPLETED';
    END IF;

    RETURN (v_updated_rows = 1);
END;
$$;


-- ---------------------------------------------------------------------
-- RPC 2: rpc_claim_worker_lease
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_claim_worker_lease(
    p_worker_id UUID,
    p_lease_duration_seconds INTEGER DEFAULT 120
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_worker RECORD;
    v_clamped_duration INTEGER;
    v_raw_lease_token BYTEA;
    v_raw_token_hex TEXT;
    v_token_hash TEXT;
    v_caller_role TEXT;
BEGIN
    -- Step 1: Worker role authorization guard (fail closed)
    v_caller_role := session_user;
    IF NOT pg_has_role(v_caller_role, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: caller % is not a member of sentinel_worker_role', v_caller_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Bound lease duration between 30 and 600 seconds
    v_clamped_duration := GREATEST(30, LEAST(COALESCE(p_lease_duration_seconds, 120), 600));

    -- Step 3: Atomic selection with non-blocking concurrency control
    SELECT id, user_id, desired_state, actual_state, lease_owner, lease_expires_at
    INTO v_worker
    FROM public.sentinel_workers
    WHERE id = p_worker_id
      AND desired_state = 'RUNNING'
      AND (
          lease_owner IS NULL 
          OR lease_expires_at IS NULL 
          OR lease_expires_at < now()
          OR lease_owner = v_caller_role
      )
    FOR UPDATE SKIP LOCKED;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'reason', 'worker_unavailable_or_locked',
            'worker_id', p_worker_id
        );
    END IF;

    -- Step 4: Generate 256-bit CSPRNG capability token using extensions.gen_random_bytes
    v_raw_lease_token := extensions.gen_random_bytes(32);
    v_raw_token_hex := encode(v_raw_lease_token, 'hex');
    v_token_hash := encode(sha256(v_raw_lease_token), 'hex');

    -- Step 5: Acquire lease and bind to session_user
    UPDATE public.sentinel_workers
    SET 
        lease_owner = v_caller_role,
        lease_expires_at = now() + (v_clamped_duration * interval '1 second'),
        lease_token_hash = v_token_hash,
        actual_state = 'RUNNING',
        last_heartbeat = now(),
        updated_at = now()
    WHERE id = v_worker.id;

    -- Step 6: Return lease metadata with raw capability token
    RETURN jsonb_build_object(
        'success', true,
        'worker_id', v_worker.id,
        'user_id', v_worker.user_id,
        'lease_owner', v_caller_role,
        'lease_token', v_raw_token_hex,
        'lease_expires_at', (now() + (v_clamped_duration * interval '1 second')),
        'lease_duration_seconds', v_clamped_duration
    );
END;
$$;


-- ---------------------------------------------------------------------
-- RPC 3: rpc_fetch_leased_mailbox_credential
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_fetch_leased_mailbox_credential(
    p_worker_id UUID,
    p_lease_token TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_worker RECORD;
    v_mailbox RECORD;
    v_caller_role TEXT;
    v_provided_hash TEXT;
BEGIN
    -- Step 1: Worker role authorization guard
    v_caller_role := session_user;
    IF NOT pg_has_role(v_caller_role, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: caller % is not a member of sentinel_worker_role', v_caller_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_token IS NULL OR length(trim(p_lease_token)) = 0 THEN
        RAISE EXCEPTION 'p_lease_token cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Validate token format and compute hash
    BEGIN
        v_provided_hash := encode(sha256(decode(p_lease_token, 'hex')), 'hex');
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Invalid capability token encoding'
            USING ERRCODE = 'invalid_parameter_value';
    END;

    -- Step 3: Validate active lease ownership and capability token match
    SELECT id, user_id, lease_owner, lease_expires_at, lease_token_hash, desired_state
    INTO v_worker
    FROM public.sentinel_workers
    WHERE id = p_worker_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Worker % not found', p_worker_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF v_worker.lease_owner IS DISTINCT FROM v_caller_role THEN
        RAISE EXCEPTION 'Lease violation: worker % is not leased by caller %', p_worker_id, v_caller_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF v_worker.lease_expires_at IS NULL OR v_worker.lease_expires_at <= now() THEN
        RAISE EXCEPTION 'Lease expired for worker %', p_worker_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF v_worker.desired_state <> 'RUNNING' THEN
        RAISE EXCEPTION 'Worker % desired_state is not RUNNING', p_worker_id
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;

    IF v_worker.lease_token_hash IS NULL OR v_worker.lease_token_hash <> v_provided_hash THEN
        RAISE EXCEPTION 'Capability token verification failed for worker %', p_worker_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 4: Retrieve encrypted credentials
    SELECT 
        id,
        user_id,
        worker_id,
        provider,
        email_address,
        imap_host,
        imap_port,
        use_ssl,
        auth_mechanism,
        encrypted_credentials,
        credential_version,
        credential_status,
        is_active
    INTO v_mailbox
    FROM public.sentinel_mailboxes
    WHERE worker_id = p_worker_id AND user_id = v_worker.user_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'reason', 'mailbox_not_configured',
            'worker_id', p_worker_id
        );
    END IF;

    IF NOT v_mailbox.is_active THEN
        RETURN jsonb_build_object(
            'success', false,
            'reason', 'mailbox_inactive',
            'worker_id', p_worker_id
        );
    END IF;

    -- Return ciphertext envelope and connection parameters
    RETURN jsonb_build_object(
        'success', true,
        'mailbox_id', v_mailbox.id,
        'worker_id', v_mailbox.worker_id,
        'user_id', v_mailbox.user_id,
        'provider', v_mailbox.provider,
        'email_address', v_mailbox.email_address,
        'imap_host', v_mailbox.imap_host,
        'imap_port', v_mailbox.imap_port,
        'use_ssl', v_mailbox.use_ssl,
        'auth_mechanism', v_mailbox.auth_mechanism,
        'encrypted_credentials', v_mailbox.encrypted_credentials,
        'credential_version', v_mailbox.credential_version,
        'credential_status', v_mailbox.credential_status
    );
END;
$$;


-- ---------------------------------------------------------------------
-- RPC 4: rpc_renew_worker_lease
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_renew_worker_lease(
    p_worker_id UUID,
    p_lease_token TEXT,
    p_extension_seconds INTEGER DEFAULT 120
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_caller_role TEXT;
    v_clamped_seconds INTEGER;
    v_provided_hash TEXT;
    v_updated_rows INTEGER;
BEGIN
    v_caller_role := session_user;
    IF NOT pg_has_role(v_caller_role, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: caller % is not a member of sentinel_worker_role', v_caller_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_worker_id IS NULL OR p_lease_token IS NULL THEN
        RETURN FALSE;
    END IF;

    BEGIN
        v_provided_hash := encode(sha256(decode(p_lease_token, 'hex')), 'hex');
    EXCEPTION WHEN OTHERS THEN
        RETURN FALSE;
    END;

    v_clamped_seconds := GREATEST(30, LEAST(COALESCE(p_extension_seconds, 120), 300));

    UPDATE public.sentinel_workers
    SET 
        lease_expires_at = now() + (v_clamped_seconds * interval '1 second'),
        last_heartbeat = now(),
        updated_at = now()
    WHERE id = p_worker_id
      AND lease_owner = v_caller_role
      AND lease_token_hash = v_provided_hash
      AND lease_expires_at > now()
      AND desired_state = 'RUNNING';

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;
    RETURN (v_updated_rows = 1);
END;
$$;


-- ---------------------------------------------------------------------
-- RPC 5: rpc_release_worker_lease
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_release_worker_lease(
    p_worker_id UUID,
    p_lease_token TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_caller_role TEXT;
    v_provided_hash TEXT;
    v_updated_rows INTEGER;
BEGIN
    v_caller_role := session_user;
    IF NOT pg_has_role(v_caller_role, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: caller % is not a member of sentinel_worker_role', v_caller_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_worker_id IS NULL OR p_lease_token IS NULL THEN
        RETURN FALSE;
    END IF;

    BEGIN
        v_provided_hash := encode(sha256(decode(p_lease_token, 'hex')), 'hex');
    EXCEPTION WHEN OTHERS THEN
        RETURN FALSE;
    END;

    -- Invalidate lease and destroy capability token hash
    UPDATE public.sentinel_workers
    SET 
        lease_owner = NULL,
        lease_expires_at = NULL,
        lease_token_hash = NULL,
        actual_state = CASE WHEN desired_state = 'RUNNING' THEN 'STOPPED' ELSE actual_state END,
        updated_at = now()
    WHERE id = p_worker_id
      AND lease_owner = v_caller_role
      AND lease_token_hash = v_provided_hash;

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;
    RETURN (v_updated_rows = 1);
END;
$$;


-- =====================================================================
-- PHASE H: PRIVILEGE SEPARATION & ACCESS CONTROL BOUNDARY
-- =====================================================================

-- 1. Table Access: Revoke ALL direct table operations from worker roles and public
REVOKE ALL ON TABLE public.sentinel_workers FROM sentinel_worker_role, sentinel_worker_daemon, anon, public;
REVOKE ALL ON TABLE public.sentinel_mailboxes FROM sentinel_worker_role, sentinel_worker_daemon, anon, public;
REVOKE ALL ON TABLE public.sentinel_checkpoints FROM sentinel_worker_role, sentinel_worker_daemon, anon, public;
REVOKE ALL ON TABLE public.sentinel_alerts FROM sentinel_worker_role, sentinel_worker_daemon, anon, public;
REVOKE ALL ON TABLE public.sentinel_provisioning_idempotency FROM sentinel_worker_role, sentinel_worker_daemon, anon, public;

-- 2. View Access: Safe metadata view is accessible only to authenticated users
GRANT SELECT ON public.sentinel_mailboxes_safe TO authenticated;
REVOKE ALL ON public.sentinel_mailboxes_safe FROM anon, public, sentinel_worker_role, sentinel_worker_daemon;

-- 3. Revoke all execution on all Sentinel RPCs from PUBLIC and anon
REVOKE EXECUTE ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM PUBLIC, anon;

-- 4. Worker Role Privileges: Grant 4 worker RPCs; explicitly revoke credential provisioning
GRANT EXECUTE ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) TO sentinel_worker_role;
GRANT EXECUTE ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) TO sentinel_worker_role;
GRANT EXECUTE ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) TO sentinel_worker_role;
GRANT EXECUTE ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) TO sentinel_worker_role;

REVOKE EXECUTE ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) FROM sentinel_worker_role, sentinel_worker_daemon;

-- 5. Authenticated User Privileges: Grant provisioning RPC; explicitly revoke worker RPCs
GRANT EXECUTE ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) TO authenticated;

REVOKE EXECUTE ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM authenticated;


