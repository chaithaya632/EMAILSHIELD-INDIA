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
