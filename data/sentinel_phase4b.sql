-- =====================================================================
-- EMAILSHIELD INDIA — Autonomous Sentinel Phase 4B Migration
-- Database Capability Tokens, Idempotent Provisioning & Asymmetric Foundations
--
-- CRITICAL SECURITY INVARIANTS:
-- 1. All functions are SECURITY DEFINER with search_path = pg_catalog, public
-- 2. Kernel-generated 256-bit CSPRNG lease capability tokens (raw token never stored)
-- 3. Stored token hash: SHA-256(raw_lease_token)
-- 4. Monotonically increasing credential versions with Compare-And-Swap (CAS)
-- 5. Strict privilege boundary: authenticated vs sentinel_worker_role
-- 6. PUBLIC and anon execution revoked on all privileged RPCs
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. SCHEMA EVOLUTION: public.sentinel_workers & public.sentinel_mailboxes
-- ---------------------------------------------------------------------

-- Add lease_token_hash to sentinel_workers
ALTER TABLE public.sentinel_workers 
    ADD COLUMN IF NOT EXISTS lease_token_hash TEXT;

-- Add credential versioning and state machine columns to sentinel_mailboxes
ALTER TABLE public.sentinel_mailboxes 
    ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 1 
    CHECK (credential_version >= 1);

ALTER TABLE public.sentinel_mailboxes 
    ADD COLUMN IF NOT EXISTS credential_status TEXT NOT NULL DEFAULT 'ACTIVE' 
    CHECK (credential_status IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED'));

-- Update safe metadata projection view
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


-- ---------------------------------------------------------------------
-- 2. TABLE: public.sentinel_provisioning_idempotency
-- Prevents replay and duplicate concurrent provisioning requests.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.sentinel_provisioning_idempotency (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    worker_id UUID NOT NULL,
    credential_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '15 minutes'),
    status TEXT NOT NULL DEFAULT 'COMPLETED' CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED')),
    CONSTRAINT uq_provisioning_idempotency UNIQUE (user_id, request_id)
);

ALTER TABLE public.sentinel_provisioning_idempotency ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "provisioning_idempotency_own" ON public.sentinel_provisioning_idempotency;
CREATE POLICY "provisioning_idempotency_own" ON public.sentinel_provisioning_idempotency
    FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);


-- ---------------------------------------------------------------------
-- 3. DEDICATED WORKER ROLES (Least-Privilege Foundation)
-- ---------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker_role') THEN
        CREATE ROLE sentinel_worker_role NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END;
$$;

-- Production Worker Daemon Login Role Template:
-- (DO NOT COMMIT REAL PASSWORDS. In production, run by DBA):
-- CREATE ROLE sentinel_worker_daemon WITH LOGIN PASSWORD '...STRONG_SCRAM_PASSWORD...' NOBYPASSRLS;
-- GRANT sentinel_worker_role TO sentinel_worker_daemon;


-- =====================================================================
-- 4. RPC 1: rpc_set_encrypted_mailbox_credential
-- Secure credential provisioning gate with CAS and Idempotency tracking.
-- =====================================================================
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

    -- Step 2: Idempotency check
    IF p_idempotency_key IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM public.sentinel_provisioning_idempotency
            WHERE user_id = v_caller_uid 
              AND request_id = p_idempotency_key
              AND expires_at > now()
              AND status = 'COMPLETED'
        ) THEN
            -- Idempotent duplicate: request already processed successfully
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

    -- Bound ciphertext size (allows v1 symmetric and v2 asymmetric envelopes up to 8192 chars)
    IF length(p_ciphertext) > 8192 THEN
        RAISE EXCEPTION 'p_ciphertext exceeds maximum allowed length of 8192 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Validate envelope format:
    -- Supports v1: v1:<nonce_hex>:<ct_hex>
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
        -- Do not auto-create mailbox; metadata must be initialized through control plane first
        RETURN FALSE;
    END IF;

    -- Step 5b: Re-check idempotency under mailbox row lock to eliminate concurrent in-flight race
    IF p_idempotency_key IS NOT NULL THEN
        IF EXISTS (
            SELECT 1 FROM public.sentinel_provisioning_idempotency
            WHERE user_id = v_caller_uid 
              AND request_id = p_idempotency_key
              AND expires_at > now()
              AND status = 'COMPLETED'
        ) THEN
            -- In-flight race: previous concurrent request with same idempotency key already completed
            RETURN TRUE;
        END IF;
    END IF;

    -- Step 6: Compare-And-Swap (CAS) validation if expected version is supplied
    IF p_expected_previous_version IS NOT NULL AND v_current_version IS NOT NULL THEN
        IF v_current_version <> p_expected_previous_version THEN
            RAISE EXCEPTION 'Concurrent stale update rejected: expected version % does not match current version %',
                p_expected_previous_version, v_current_version
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;

    -- Step 7: Enforce monotonically increasing credential versions (no rollbacks)
    IF v_current_version IS NOT NULL AND p_credential_version <= v_current_version THEN
        RAISE EXCEPTION 'Credential version rollback rejected: current version is %, proposed version is %',
            v_current_version, p_credential_version
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- Step 8: Atomic update
    UPDATE public.sentinel_mailboxes
    SET 
        encrypted_credentials = p_ciphertext,
        credential_version = p_credential_version,
        credential_status = 'ACTIVE',
        updated_at = now()
    WHERE worker_id = p_worker_id AND user_id = v_caller_uid;

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;

    -- Step 9: Record idempotency record if key was provided
    IF v_updated_rows = 1 AND p_idempotency_key IS NOT NULL THEN
        INSERT INTO public.sentinel_provisioning_idempotency (
            request_id, user_id, worker_id, credential_version, status
        ) VALUES (
            p_idempotency_key, v_caller_uid, p_worker_id, p_credential_version, 'COMPLETED'
        ) ON CONFLICT (user_id, request_id) DO NOTHING;
    END IF;

    RETURN (v_updated_rows = 1);
END;
$$;

-- Privilege configuration: RPC 1
REVOKE ALL ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) FROM anon;
GRANT EXECUTE ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) TO authenticated;


-- =====================================================================
-- 5. RPC 2: rpc_claim_worker_lease
-- Atomic lease acquisition returning kernel-generated 256-bit CSPRNG lease token.
-- Raw lease token is returned ONCE to the winner; only SHA-256 hash is stored.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_claim_worker_lease(
    p_worker_id UUID DEFAULT NULL,
    p_lease_duration_seconds INTEGER DEFAULT 300
) RETURNS TABLE (
    worker_id UUID,
    user_id UUID,
    poll_interval_seconds INTEGER,
    lease_expires_at TIMESTAMPTZ,
    lease_token TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_claimed_worker_id UUID;
    v_raw_token TEXT;
    v_token_hash TEXT;
BEGIN
    -- Step 1: Parameter validation
    IF p_lease_duration_seconds IS NULL OR p_lease_duration_seconds < 30 OR p_lease_duration_seconds > 900 THEN
        RAISE EXCEPTION 'p_lease_duration_seconds must be between 30 and 900 seconds'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Atomic lock acquisition using SKIP LOCKED
    IF p_worker_id IS NOT NULL THEN
        -- Targeted claim on specific worker
        SELECT w.id INTO v_claimed_worker_id
        FROM public.sentinel_workers w
        WHERE w.id = p_worker_id
          AND w.desired_state = 'RUNNING'
          AND (w.lease_expires_at IS NULL OR w.lease_expires_at < now())
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
    ELSE
        -- Queue-based claim on next available eligible worker
        SELECT w.id INTO v_claimed_worker_id
        FROM public.sentinel_workers w
        WHERE w.desired_state = 'RUNNING'
          AND (w.lease_expires_at IS NULL OR w.lease_expires_at < now())
        ORDER BY COALESCE(w.last_heartbeat, '1970-01-01'::timestamptz) ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
    END IF;

    -- If no eligible worker available or currently locked by concurrent transaction, return empty
    IF v_claimed_worker_id IS NULL THEN
        RETURN;
    END IF;

    -- Step 3: Kernel generation of 256-bit CSPRNG lease token
    -- 32 random bytes encoded as 64-character hex string
    v_raw_token := encode(gen_random_bytes(32), 'hex');
    -- Compute cryptographic SHA-256 hash
    v_token_hash := encode(sha256(v_raw_token::bytea), 'hex');

    -- Step 4: Atomic lease update with token hash
    RETURN QUERY
    UPDATE public.sentinel_workers w
    SET 
        lease_owner = 'ACTIVE_LEASE',
        lease_token_hash = v_token_hash,
        lease_expires_at = now() + (p_lease_duration_seconds || ' seconds')::interval,
        actual_state = 'RUNNING',
        last_heartbeat = now(),
        updated_at = now()
    WHERE w.id = v_claimed_worker_id
    RETURNING 
        w.id AS worker_id,
        w.user_id,
        w.poll_interval_seconds,
        w.lease_expires_at,
        v_raw_token AS lease_token;
END;
$$;

-- Privilege configuration: RPC 2
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) TO sentinel_worker_role;


-- =====================================================================
-- 6. RPC 3: rpc_fetch_leased_mailbox_credential
-- Strictly bounded credential fetch verified by active lease capability token.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_fetch_leased_mailbox_credential(
    p_worker_id UUID,
    p_lease_token TEXT
) RETURNS TABLE (
    mailbox_id UUID,
    user_id UUID,
    provider TEXT,
    email_address TEXT,
    imap_host TEXT,
    imap_port INTEGER,
    use_ssl BOOLEAN,
    auth_mechanism TEXT,
    encrypted_credentials TEXT,
    credential_version INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_clean_token TEXT;
    v_token_hash TEXT;
BEGIN
    -- Step 1: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_token IS NULL OR length(trim(p_lease_token)) = 0 THEN
        RAISE EXCEPTION 'p_lease_token cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_clean_token := trim(p_lease_token);
    IF length(v_clean_token) <> 64 OR NOT v_clean_token ~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'Invalid lease capability token format'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Compute SHA-256 hash of presented token
    v_token_hash := encode(sha256(v_clean_token::bytea), 'hex');

    -- Step 3: Verify matching active unexpired lease
    IF NOT EXISTS (
        SELECT 1 FROM public.sentinel_workers w
        WHERE w.id = p_worker_id
          AND w.lease_token_hash = v_token_hash
          AND w.lease_expires_at > now()
          AND w.desired_state = 'RUNNING'
    ) THEN
        RAISE EXCEPTION 'Access denied: invalid lease capability token or expired lease for worker %', p_worker_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 4: Return single active mailbox record for this claimed worker
    RETURN QUERY
    SELECT 
        m.id AS mailbox_id,
        m.user_id,
        m.provider,
        m.email_address,
        m.imap_host,
        m.imap_port,
        m.use_ssl,
        m.auth_mechanism,
        m.encrypted_credentials,
        m.credential_version
    FROM public.sentinel_mailboxes m
    WHERE m.worker_id = p_worker_id
      AND m.is_active = TRUE
      AND m.credential_status = 'ACTIVE';
END;
$$;

-- Privilege configuration: RPC 3
REVOKE ALL ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) TO sentinel_worker_role;


-- =====================================================================
-- 7. RPC 4: rpc_renew_worker_lease
-- Extends lease expiry verified strictly by lease capability token.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_renew_worker_lease(
    p_worker_id UUID,
    p_lease_token TEXT,
    p_lease_duration_seconds INTEGER DEFAULT 300
) RETURNS TIMESTAMPTZ
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_clean_token TEXT;
    v_token_hash TEXT;
    v_new_expiry TIMESTAMPTZ;
BEGIN
    -- Step 1: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_token IS NULL OR length(trim(p_lease_token)) = 0 THEN
        RAISE EXCEPTION 'p_lease_token cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_clean_token := trim(p_lease_token);
    IF length(v_clean_token) <> 64 OR NOT v_clean_token ~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'Invalid lease capability token format'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_duration_seconds IS NULL OR p_lease_duration_seconds < 30 OR p_lease_duration_seconds > 900 THEN
        RAISE EXCEPTION 'p_lease_duration_seconds must be between 30 and 900 seconds'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Compute SHA-256 hash of presented token
    v_token_hash := encode(sha256(v_clean_token::bytea), 'hex');

    -- Step 3: Atomic renewal update
    UPDATE public.sentinel_workers w
    SET 
        lease_expires_at = now() + (p_lease_duration_seconds || ' seconds')::interval,
        last_heartbeat = now(),
        updated_at = now()
    WHERE w.id = p_worker_id
      AND w.lease_token_hash = v_token_hash
      AND w.lease_expires_at > now()
      AND w.desired_state = 'RUNNING'
    RETURNING w.lease_expires_at INTO v_new_expiry;

    IF v_new_expiry IS NULL THEN
        RAISE EXCEPTION 'Renewal denied: active lease not found or invalid capability token for worker %', p_worker_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN v_new_expiry;
END;
$$;

-- Privilege configuration: RPC 4
REVOKE ALL ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) TO sentinel_worker_role;


-- =====================================================================
-- 8. RPC 5: rpc_release_worker_lease
-- Safely releases the worker lease and clears lease capability token.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_release_worker_lease(
    p_worker_id UUID,
    p_lease_token TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_clean_token TEXT;
    v_token_hash TEXT;
    v_updated_rows INTEGER;
BEGIN
    -- Step 1: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_token IS NULL OR length(trim(p_lease_token)) = 0 THEN
        RAISE EXCEPTION 'p_lease_token cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_clean_token := trim(p_lease_token);
    IF length(v_clean_token) <> 64 OR NOT v_clean_token ~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'Invalid lease capability token format'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Compute SHA-256 hash of presented token
    v_token_hash := encode(sha256(v_clean_token::bytea), 'hex');

    -- Step 3: Atomic release and clear token hash
    UPDATE public.sentinel_workers w
    SET 
        lease_owner = NULL,
        lease_token_hash = NULL,
        lease_expires_at = NULL,
        actual_state = 'STOPPED',
        updated_at = now()
    WHERE w.id = p_worker_id
      AND w.lease_token_hash = v_token_hash;

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;

    RETURN (v_updated_rows = 1);
END;
$$;

-- Privilege configuration: RPC 5
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) TO sentinel_worker_role;
