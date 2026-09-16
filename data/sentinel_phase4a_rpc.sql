-- =====================================================================
-- EMAILSHIELD INDIA — Autonomous Sentinel Phase 4A Migration
-- PostgreSQL Database Security Boundary & Hardened SECURITY DEFINER RPCs
--
-- CRITICAL CONSTRAINTS:
-- 1. All functions are SECURITY DEFINER with search_path = pg_catalog, public
-- 2. Never trust caller-supplied user_id; derive from auth.uid()
-- 3. Monotonically increasing credential versions (no rollbacks)
-- 4. Atomic lease acquisition via SELECT ... FOR UPDATE SKIP LOCKED
-- 5. Strict privilege separation: authenticated vs sentinel_worker_role
-- 6. PUBLIC and anon execution revoked on all privileged RPCs
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. ADDITIVE SCHEMA EVOLUTION: public.sentinel_mailboxes
-- ---------------------------------------------------------------------
ALTER TABLE public.sentinel_mailboxes 
    ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 1 
    CHECK (credential_version >= 1);

ALTER TABLE public.sentinel_mailboxes 
    ADD COLUMN IF NOT EXISTS credential_status TEXT NOT NULL DEFAULT 'ACTIVE' 
    CHECK (credential_status IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED'));

-- Update safe metadata projection view to include safe non-secret columns
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
-- 2. DEDICATED WORKER ROLE DECLARATION (Least-Privilege Foundation)
-- ---------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker_role') THEN
        CREATE ROLE sentinel_worker_role NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END;
$$;


-- =====================================================================
-- 3. RPC 1: rpc_set_encrypted_mailbox_credential
-- Secure credential provisioning gate for authenticated users.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_set_encrypted_mailbox_credential(
    p_worker_id UUID,
    p_ciphertext TEXT,
    p_credential_version INTEGER
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

    -- Step 2: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_ciphertext IS NULL OR length(trim(p_ciphertext)) = 0 THEN
        RAISE EXCEPTION 'p_ciphertext cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Bound ciphertext size (reject oversized payloads > 4096 characters)
    IF length(p_ciphertext) > 4096 THEN
        RAISE EXCEPTION 'p_ciphertext exceeds maximum allowed length of 4096 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Enforce envelope format structure: v<version>:<nonce_hex_24>:<ct_and_tag_hex>
    IF NOT p_ciphertext ~ '^v[1-9]:[0-9a-fA-F]{24}:[0-9a-fA-F]{34,}$' THEN
        RAISE EXCEPTION 'Invalid ciphertext envelope structure'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_credential_version IS NULL OR p_credential_version <= 0 THEN
        RAISE EXCEPTION 'p_credential_version must be a positive integer (got %)', p_credential_version
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 3: Verify tenant ownership of target worker
    IF NOT EXISTS (
        SELECT 1 FROM public.sentinel_workers
        WHERE id = p_worker_id AND user_id = v_caller_uid
    ) THEN
        RAISE EXCEPTION 'Ownership violation: worker % does not belong to caller %', 
            p_worker_id, v_caller_uid
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    -- Step 4: Verify mailbox existence and retrieve current version
    SELECT credential_version INTO v_current_version
    FROM public.sentinel_mailboxes
    WHERE worker_id = p_worker_id AND user_id = v_caller_uid
    FOR UPDATE;

    IF NOT FOUND THEN
        -- Do not auto-create mailbox; metadata must be initialized through control plane first
        RETURN FALSE;
    END IF;

    -- Step 5: Enforce monotonically increasing credential versions (no rollbacks)
    IF v_current_version IS NOT NULL AND p_credential_version <= v_current_version THEN
        RAISE EXCEPTION 'Credential version rollback rejected: current version is %, proposed version is %',
            v_current_version, p_credential_version
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- Step 6: Atomic update of intended columns only (user_id and worker_id remain immutable)
    UPDATE public.sentinel_mailboxes
    SET 
        encrypted_credentials = p_ciphertext,
        credential_version = p_credential_version,
        credential_status = 'ACTIVE',
        updated_at = now()
    WHERE worker_id = p_worker_id AND user_id = v_caller_uid;

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;
    RETURN (v_updated_rows = 1);
END;
$$;

-- Privilege configuration: RPC 1
REVOKE ALL ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER) FROM anon;
GRANT EXECUTE ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER) TO authenticated;


-- =====================================================================
-- 4. RPC 2: rpc_claim_worker_lease
-- Atomic worker lease acquisition via SELECT ... FOR UPDATE SKIP LOCKED.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_claim_worker_lease(
    p_worker_id UUID,
    p_lease_owner_id TEXT,
    p_lease_duration_seconds INTEGER DEFAULT 300
) RETURNS TABLE (
    worker_id UUID,
    user_id UUID,
    poll_interval_seconds INTEGER,
    lease_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_claimed_worker_id UUID;
    v_clean_owner TEXT;
BEGIN
    -- Step 1: Parameter validation
    IF p_lease_owner_id IS NULL OR length(trim(p_lease_owner_id)) = 0 THEN
        RAISE EXCEPTION 'p_lease_owner_id cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_clean_owner := trim(p_lease_owner_id);
    IF length(v_clean_owner) < 8 OR length(v_clean_owner) > 255 THEN
        RAISE EXCEPTION 'p_lease_owner_id must be between 8 and 255 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF NOT v_clean_owner ~ '^[a-zA-Z0-9_\-\.:]+$' THEN
        RAISE EXCEPTION 'p_lease_owner_id contains invalid characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_duration_seconds IS NULL OR p_lease_duration_seconds < 30 OR p_lease_duration_seconds > 900 THEN
        RAISE EXCEPTION 'p_lease_duration_seconds must be between 30 and 900 seconds'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Atomic lock acquisition
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

    -- If no eligible worker available or locked by concurrent transaction, return empty
    IF v_claimed_worker_id IS NULL THEN
        RETURN;
    END IF;

    -- Step 3: Atomic lease update
    RETURN QUERY
    UPDATE public.sentinel_workers w
    SET 
        lease_owner = v_clean_owner,
        lease_expires_at = now() + (p_lease_duration_seconds || ' seconds')::interval,
        actual_state = 'RUNNING',
        last_heartbeat = now(),
        updated_at = now()
    WHERE w.id = v_claimed_worker_id
    RETURNING 
        w.id AS worker_id,
        w.user_id,
        w.poll_interval_seconds,
        w.lease_expires_at;
END;
$$;

-- Privilege configuration: RPC 2
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, TEXT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, TEXT, INTEGER) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, TEXT, INTEGER) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_claim_worker_lease(UUID, TEXT, INTEGER) TO sentinel_worker_role;


-- =====================================================================
-- 5. RPC 3: rpc_fetch_leased_mailbox_credential
-- Strictly bounded credential fetch for workers with active leases.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_fetch_leased_mailbox_credential(
    p_worker_id UUID,
    p_lease_owner_id TEXT
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
    v_clean_owner TEXT;
BEGIN
    -- Step 1: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_owner_id IS NULL OR length(trim(p_lease_owner_id)) = 0 THEN
        RAISE EXCEPTION 'p_lease_owner_id cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_clean_owner := trim(p_lease_owner_id);

    -- Step 2: Strict active lease ownership verification
    IF NOT EXISTS (
        SELECT 1 FROM public.sentinel_workers w
        WHERE w.id = p_worker_id
          AND w.lease_owner = v_clean_owner
          AND w.lease_expires_at > now()
          AND w.desired_state = 'RUNNING'
    ) THEN
        RAISE EXCEPTION 'Access denied: caller does not hold an active unexpired lease for worker %', p_worker_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 3: Return the single mailbox record associated with this claimed worker
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
-- 6. RPC 4: rpc_renew_worker_lease
-- Extends lease expiry for the current valid lease holder only.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_renew_worker_lease(
    p_worker_id UUID,
    p_lease_owner_id TEXT,
    p_lease_duration_seconds INTEGER DEFAULT 300
) RETURNS TIMESTAMPTZ
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_clean_owner TEXT;
    v_new_expiry TIMESTAMPTZ;
BEGIN
    -- Step 1: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_owner_id IS NULL OR length(trim(p_lease_owner_id)) = 0 THEN
        RAISE EXCEPTION 'p_lease_owner_id cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_clean_owner := trim(p_lease_owner_id);

    IF p_lease_duration_seconds IS NULL OR p_lease_duration_seconds < 30 OR p_lease_duration_seconds > 900 THEN
        RAISE EXCEPTION 'p_lease_duration_seconds must be between 30 and 900 seconds'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 2: Atomic renewal verification & update
    UPDATE public.sentinel_workers w
    SET 
        lease_expires_at = now() + (p_lease_duration_seconds || ' seconds')::interval,
        last_heartbeat = now(),
        updated_at = now()
    WHERE w.id = p_worker_id
      AND w.lease_owner = v_clean_owner
      AND w.lease_expires_at > now()
      AND w.desired_state = 'RUNNING'
    RETURNING w.lease_expires_at INTO v_new_expiry;

    IF v_new_expiry IS NULL THEN
        RAISE EXCEPTION 'Renewal denied: active lease not found for worker % and owner %', p_worker_id, v_clean_owner
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
-- 7. RPC 5: rpc_release_worker_lease
-- Safely releases the worker lease upon task completion or graceful shutdown.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.rpc_release_worker_lease(
    p_worker_id UUID,
    p_lease_owner_id TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_clean_owner TEXT;
    v_updated_rows INTEGER;
BEGIN
    -- Step 1: Parameter validation
    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'p_worker_id cannot be null'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_lease_owner_id IS NULL OR length(trim(p_lease_owner_id)) = 0 THEN
        RAISE EXCEPTION 'p_lease_owner_id cannot be null or empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_clean_owner := trim(p_lease_owner_id);

    -- Step 2: Atomic release
    -- Only current lease owner can release; clears lease fields and sets actual_state = 'STOPPED'
    UPDATE public.sentinel_workers w
    SET 
        lease_owner = NULL,
        lease_expires_at = NULL,
        actual_state = 'STOPPED',
        updated_at = now()
    WHERE w.id = p_worker_id
      AND w.lease_owner = v_clean_owner;

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;

    RETURN (v_updated_rows = 1);
END;
$$;

-- Privilege configuration: RPC 5
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) TO sentinel_worker_role;
