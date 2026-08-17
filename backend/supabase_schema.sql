-- ============================================================
-- NFC Medicine Authenticity System — Supabase schema
--
-- Run once in the Supabase dashboard: Project -> SQL Editor -> New query
-- -> paste this whole file -> Run.
--
-- This is the final-state schema (equivalent to running init_db.py then
-- migrate.py against a fresh database) -- safe to run on an empty Supabase
-- project. All statements are idempotent, so re-running this file is safe.
-- ============================================================

CREATE TABLE IF NOT EXISTS products (
    id             SERIAL PRIMARY KEY,
    product_id     TEXT NOT NULL,
    product_id_iv  TEXT NOT NULL,
    batch_id       TEXT NOT NULL,
    batch_id_iv    TEXT NOT NULL,
    mfg_date       TEXT NOT NULL,
    mfg_date_iv    TEXT NOT NULL,
    tag_uid        TEXT NOT NULL,
    tag_uid_iv     TEXT NOT NULL,
    shelf_life     INTEGER NOT NULL,
    expiry_date    DATE NOT NULL,
    payload_hash   TEXT NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    nonce          TEXT NOT NULL UNIQUE,   -- enforces replay protection at the DB level
    key_chars      TEXT,                   -- only populated for crypto_version = 'paper_v1'
    tag_uid_hash   TEXT NOT NULL,
    crypto_version TEXT NOT NULL DEFAULT 'paper_v1'
);

CREATE INDEX IF NOT EXISTS idx_tag_uid_hash ON products(tag_uid_hash);
CREATE INDEX IF NOT EXISTS idx_tag_uid      ON products(tag_uid);

CREATE TABLE IF NOT EXISTS audit_log (
    id           SERIAL PRIMARY KEY,
    event_type   TEXT NOT NULL,   -- 'product_write' | 'verify_attempt' | 'admin_products_list' | 'admin_key_fetch' | 'auth_failure'
    tag_uid_hash TEXT,
    result       TEXT,            -- 'success' | 'authentic' | 'expired' | 'tampered' | 'unknown' | 'duplicate_nonce' | 'bad_signature' | ...
    source_ip    TEXT,
    user_agent   TEXT,
    detail       JSONB,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tag_uid_hash ON audit_log(tag_uid_hash);
CREATE INDEX IF NOT EXISTS idx_audit_event_type    ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at     ON audit_log(created_at);

-- ------------------------------------------------------------
-- Row Level Security
--
-- The Flask backend connects using Supabase's "postgres" role, which has
-- BYPASSRLS and is completely unaffected by the policies below. What this
-- protects against is Supabase's auto-generated REST API (PostgREST): every
-- Supabase project exposes one automatically, and it's reachable with the
-- project's anon/public key. With RLS enabled and no policies granted to the
-- anon/authenticated roles, that API can neither read nor write these
-- tables -- the only path to this data is through the Flask backend itself.
-- ------------------------------------------------------------
ALTER TABLE products  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
