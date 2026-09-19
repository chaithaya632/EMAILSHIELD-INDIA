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
