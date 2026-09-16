-- =====================================================================
-- EMAILSHIELD INDIA — Supabase Multi-User Database Schema & RLS Policies
-- Kernel-level tenant isolation via PostgreSQL Row Level Security (RLS)
-- =====================================================================

-- 1. Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Profiles Table
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    display_name TEXT
);

-- 3. Cases Table
CREATE TABLE IF NOT EXISTS public.cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    case_number TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sha256 TEXT NOT NULL,
    threat_verdict TEXT NOT NULL,
    risk_score TEXT NOT NULL,
    verdict_confidence INTEGER NOT NULL DEFAULT 0 CHECK (verdict_confidence BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'In Progress', 'Resolved', 'Closed')),
    assigned_investigator TEXT NOT NULL DEFAULT 'Unassigned',
    analyst_notes TEXT NOT NULL DEFAULT '',
    case_severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (case_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    subject TEXT NOT NULL DEFAULT 'No Subject',
    sender TEXT NOT NULL DEFAULT 'Unknown',
    content_type TEXT NOT NULL DEFAULT 'Unknown',
    raw_json JSONB NOT NULL,
    CONSTRAINT uq_cases_id_user UNIQUE (id, user_id),
    CONSTRAINT uq_cases_user_case_number UNIQUE (user_id, case_number)
);

-- 4. Indicators Table (With Composite Foreign Key Integrity)
CREATE TABLE IF NOT EXISTS public.indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    type TEXT NOT NULL CHECK (type IN ('IP', 'URL', 'Email', 'Domain', 'Hash', 'UPI', 'Bank_Account')),
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'Body/Headers',
    CONSTRAINT fk_indicators_case_user 
        FOREIGN KEY (case_id, user_id) 
        REFERENCES public.cases(id, user_id) 
        ON DELETE CASCADE
);

-- 5. Indexes for Query Performance & Scoped Lookups
CREATE INDEX IF NOT EXISTS idx_cases_user_id ON public.cases(user_id);
CREATE INDEX IF NOT EXISTS idx_cases_user_created ON public.cases(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_sha256 ON public.cases(user_id, sha256);

CREATE INDEX IF NOT EXISTS idx_indicators_user_id ON public.indicators(user_id);
CREATE INDEX IF NOT EXISTS idx_indicators_case_id ON public.indicators(case_id);
CREATE INDEX IF NOT EXISTS idx_indicators_user_value ON public.indicators(user_id, type, value);

-- 6. Enable Row Level Security (RLS)
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.indicators ENABLE ROW LEVEL SECURITY;

-- 7. RLS Policies for Profiles
DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own" ON public.profiles
    FOR SELECT TO authenticated USING (id = auth.uid());

DROP POLICY IF EXISTS "profiles_insert_own" ON public.profiles;
CREATE POLICY "profiles_insert_own" ON public.profiles
    FOR INSERT TO authenticated WITH CHECK (id = auth.uid());

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own" ON public.profiles
    FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());

-- 8. RLS Policies for Cases
DROP POLICY IF EXISTS "cases_select_own" ON public.cases;
CREATE POLICY "cases_select_own" ON public.cases
    FOR SELECT TO authenticated USING (user_id = auth.uid());

DROP POLICY IF EXISTS "cases_insert_own" ON public.cases;
CREATE POLICY "cases_insert_own" ON public.cases
    FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "cases_update_own" ON public.cases;
CREATE POLICY "cases_update_own" ON public.cases
    FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "cases_delete_own" ON public.cases;
CREATE POLICY "cases_delete_own" ON public.cases
    FOR DELETE TO authenticated USING (user_id = auth.uid());

-- 9. RLS Policies for Indicators
DROP POLICY IF EXISTS "indicators_select_own" ON public.indicators;
CREATE POLICY "indicators_select_own" ON public.indicators
    FOR SELECT TO authenticated USING (user_id = auth.uid());

DROP POLICY IF EXISTS "indicators_insert_own" ON public.indicators;
CREATE POLICY "indicators_insert_own" ON public.indicators
    FOR INSERT TO authenticated WITH CHECK (
        user_id = auth.uid()
        AND EXISTS (
            SELECT 1 FROM public.cases
            WHERE cases.id = indicators.case_id
              AND cases.user_id = auth.uid()
        )
    );

DROP POLICY IF EXISTS "indicators_delete_own" ON public.indicators;
CREATE POLICY "indicators_delete_own" ON public.indicators
    FOR DELETE TO authenticated USING (user_id = auth.uid());

-- NOTE ON INDICATOR UPDATES:
-- Indicators represent immutable forensic telemetry records.
-- No UPDATE policy exists intentionally; RLS therefore denies indicator UPDATE operations by default.
-- If future correction of indicators is required, it must happen through a controlled new-record/audit-event model.
