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
