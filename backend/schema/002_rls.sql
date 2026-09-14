-- ============================================================================
-- NFC Medicine Authenticity System v2 — Row Level Security
-- ARCHITECTURE.md §8.2
-- Run after 001_core.sql. Idempotent.
-- ============================================================================

-- Every table gets RLS with ZERO policies for anon/authenticated. The backend
-- connects as Supabase's `postgres` role (BYPASSRLS) and is unaffected. What this
-- closes is the auto-generated PostgREST API, which every Supabase project exposes
-- and which is reachable with the project's anon key. Missing this leaks the whole
-- database (F7a). v1 got this right for two tables — extend it to all of them.
ALTER TABLE device_registry     ENABLE ROW LEVEL SECURITY;
ALTER TABLE batches             ENABLE ROW LEVEL SECURITY;
ALTER TABLE products            ENABLE ROW LEVEL SECURITY;
ALTER TABLE tag_counter_state   ENABLE ROW LEVEL SECURITY;
ALTER TABLE divergence_incident ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_key     ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log           ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumer_report     ENABLE ROW LEVEL SECURITY;
ALTER TABLE transparency_root   ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limit_bucket   ENABLE ROW LEVEL SECURITY;

-- FORCE also applies RLS to the table owner. Applied to the three tables where a
-- policy-less owner-bypass would be the difference between "leaked" and "not".
ALTER TABLE device_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE products        FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log       FORCE ROW LEVEL SECURITY;

-- No policies are created on purpose. Do not add one "just for testing" — a
-- permissive policy here re-opens the PostgREST API to the whole internet.

-- Belt and braces: revoke the PostgREST roles explicitly as well.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated';
    END IF;
END $$;

-- Retention (F30, DPDP Act 2023): audit rows older than 90 days are deleted.
-- Run from the nightly GitHub Action (.github/workflows/backup.yml), not a
-- Postgres extension — pg_cron is not available on the Supabase free tier.
