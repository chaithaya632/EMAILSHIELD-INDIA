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
