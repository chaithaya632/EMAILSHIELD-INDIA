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
