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
