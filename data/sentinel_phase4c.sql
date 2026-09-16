-- =====================================================================
-- EMAILSHIELD INDIA — Autonomous Sentinel Phase 4C Migration
-- Worker Authentication, Session Role Verification & Credential Boundary
--
-- CRITICAL SECURITY INVARIANTS:
-- 1. All functions are SECURITY DEFINER with search_path = pg_catalog, public
-- 2. Worker authentication is derived strictly from PostgreSQL session_user
--    and verified via pg_has_role(session_user, 'sentinel_worker_role', 'MEMBER')
-- 3. Lease ownership records session_user (login identity, e.g., 'sentinel_worker_daemon')
-- 4. Operations on active leases require BOTH matching session_user AND valid capability token
-- 5. Raw 256-bit CSPRNG lease token returned once to caller; only SHA-256 hash persisted
-- 6. In-flight idempotency re-checked under mailbox row lock to eliminate concurrent races
-- 7. Strict privilege isolation: authenticated vs sentinel_worker_role vs anon/PUBLIC
-- 8. Zero service_role usage; zero user JWT machine credentials
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. DEDICATED WORKER ROLES (Least-Privilege Foundation)
-- ---------------------------------------------------------------------
DO $$
BEGIN
    -- Base worker role (NOLOGIN, NOBYPASSRLS)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker_role') THEN
        CREATE ROLE sentinel_worker_role NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;

    -- Candidate worker daemon login role (LOGIN, NOBYPASSRLS)
    -- In staging / production environments, password managed via SCRAM-SHA-256 secrets
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker_daemon') THEN
        CREATE ROLE sentinel_worker_daemon WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
        GRANT sentinel_worker_role TO sentinel_worker_daemon;
    END IF;
END;
$$;


-- =====================================================================
-- 2. RPC 1: rpc_set_encrypted_mailbox_credential
-- Provisioning-side gate with CAS, post-lock idempotency, and tenant binding.
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

    -- Step 2: Idempotency check (pre-lock optimization)
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
REVOKE ALL ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) FROM sentinel_worker_role;
GRANT EXECUTE ON FUNCTION public.rpc_set_encrypted_mailbox_credential(UUID, TEXT, INTEGER, INTEGER, UUID) TO authenticated;


-- =====================================================================
-- 3. RPC 2: rpc_claim_worker_lease
-- Verifies caller session role, claims lease, records session_user as lease_owner,
-- generates 256-bit CSPRNG capability token, persists SHA-256 hash.
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
    -- Step 1: Worker role verification
    IF NOT pg_has_role(session_user, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: database session % is not an authorized Sentinel worker role', session_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 2: Parameter validation
    IF p_lease_duration_seconds IS NULL OR p_lease_duration_seconds < 30 OR p_lease_duration_seconds > 900 THEN
        RAISE EXCEPTION 'p_lease_duration_seconds must be between 30 and 900 seconds'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Step 3: Atomic lock acquisition using SKIP LOCKED
    IF p_worker_id IS NOT NULL THEN
        SELECT w.id INTO v_claimed_worker_id
        FROM public.sentinel_workers w
        WHERE w.id = p_worker_id
          AND w.desired_state = 'RUNNING'
          AND (w.lease_expires_at IS NULL OR w.lease_expires_at < now())
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
    ELSE
        SELECT w.id INTO v_claimed_worker_id
        FROM public.sentinel_workers w
        WHERE w.desired_state = 'RUNNING'
          AND (w.lease_expires_at IS NULL OR w.lease_expires_at < now())
        ORDER BY COALESCE(w.last_heartbeat, '1970-01-01'::timestamptz) ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
    END IF;

    IF v_claimed_worker_id IS NULL THEN
        RETURN;
    END IF;

    -- Step 4: Kernel generation of 256-bit CSPRNG lease capability token
    v_raw_token := encode(gen_random_bytes(32), 'hex');
    v_token_hash := encode(sha256(v_raw_token::bytea), 'hex');

    -- Step 5: Atomic lease update with session_user as lease_owner
    RETURN QUERY
    UPDATE public.sentinel_workers w
    SET 
        lease_owner = session_user,
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

REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_claim_worker_lease(UUID, INTEGER) TO sentinel_worker_role;


-- =====================================================================
-- 4. RPC 3: rpc_fetch_leased_mailbox_credential
-- Verifies session_user, lease_owner, lease_token_hash, and unexpired lease.
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
    -- Step 1: Worker role verification
    IF NOT pg_has_role(session_user, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: database session % is not an authorized Sentinel worker role', session_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 2: Parameter validation
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

    v_token_hash := encode(sha256(v_clean_token::bytea), 'hex');

    -- Step 3: Verify matching active unexpired lease, token hash, and session_user ownership
    IF NOT EXISTS (
        SELECT 1 FROM public.sentinel_workers w
        WHERE w.id = p_worker_id
          AND w.lease_token_hash = v_token_hash
          AND w.lease_owner = session_user
          AND w.lease_expires_at > now()
          AND w.desired_state = 'RUNNING'
    ) THEN
        RAISE EXCEPTION 'Access denied: invalid lease capability token, wrong worker identity, or expired lease for worker %', p_worker_id
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 4: Return single active mailbox record
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

REVOKE ALL ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_fetch_leased_mailbox_credential(UUID, TEXT) TO sentinel_worker_role;


-- =====================================================================
-- 5. RPC 4: rpc_renew_worker_lease
-- Extends lease expiry verified strictly by session_user, lease_owner, and token hash.
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
    -- Step 1: Worker role verification
    IF NOT pg_has_role(session_user, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: database session % is not an authorized Sentinel worker role', session_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 2: Parameter validation
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

    v_token_hash := encode(sha256(v_clean_token::bytea), 'hex');

    -- Step 3: Atomic renewal update enforcing session_user ownership
    UPDATE public.sentinel_workers w
    SET 
        lease_expires_at = now() + (p_lease_duration_seconds || ' seconds')::interval,
        last_heartbeat = now(),
        updated_at = now()
    WHERE w.id = p_worker_id
      AND w.lease_token_hash = v_token_hash
      AND w.lease_owner = session_user
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

REVOKE ALL ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_renew_worker_lease(UUID, TEXT, INTEGER) TO sentinel_worker_role;


-- =====================================================================
-- 6. RPC 5: rpc_release_worker_lease
-- Releases worker lease and clears capability token hash enforcing session_user ownership.
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
    -- Step 1: Worker role verification
    IF NOT pg_has_role(session_user, 'sentinel_worker_role', 'MEMBER') THEN
        RAISE EXCEPTION 'Access denied: database session % is not an authorized Sentinel worker role', session_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Step 2: Parameter validation
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

    v_token_hash := encode(sha256(v_clean_token::bytea), 'hex');

    -- Step 3: Atomic release enforcing session_user ownership
    UPDATE public.sentinel_workers w
    SET 
        lease_owner = NULL,
        lease_token_hash = NULL,
        lease_expires_at = NULL,
        actual_state = 'STOPPED',
        updated_at = now()
    WHERE w.id = p_worker_id
      AND w.lease_token_hash = v_token_hash
      AND w.lease_owner = session_user;

    GET DIAGNOSTICS v_updated_rows = ROW_COUNT;

    RETURN (v_updated_rows = 1);
END;
$$;

REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_release_worker_lease(UUID, TEXT) TO sentinel_worker_role;
