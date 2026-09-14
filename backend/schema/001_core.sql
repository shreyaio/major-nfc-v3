-- ============================================================================
-- NFC Medicine Authenticity System v2 — core schema
-- ARCHITECTURE.md §8.1
-- Idempotent. Safe to re-run.
--
-- This is a FRESH register. v2 is not migration-compatible with v1 rows: the
-- lookup index is keyed, the paper cipher is gone, payload_hash is replaced by
-- an Ed25519 row signature. Export v1 data first if you need it.
-- ============================================================================

-- ---------------------------------------------------------------- devices ---
CREATE TABLE IF NOT EXISTS device_registry (
    device_id       UUID PRIMARY KEY,
    label           TEXT        NOT NULL,
    public_key      TEXT        NOT NULL,              -- Ed25519, 64 hex chars
    sig_alg         TEXT        NOT NULL DEFAULT 'ed25519',
    status          TEXT        NOT NULL DEFAULT 'active',   -- active | revoked
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    CONSTRAINT device_status_valid CHECK (status IN ('active','revoked')),
    CONSTRAINT device_sig_alg_valid CHECK (sig_alg IN ('ed25519'))
);

-- ---------------------------------------------------------------- batches ---
-- Two-person authorisation + enrolment quota. This is the cheapest mitigation
-- for a stolen Pi signing key (F1): a compromise is bounded by the open quota.
CREATE TABLE IF NOT EXISTS batches (
    batch_ref        TEXT        PRIMARY KEY,           -- operator-visible, e.g. 'AMX-2026-09-001'
    product_name     TEXT        NOT NULL,
    mfg_date         DATE        NOT NULL,
    shelf_life_days  INTEGER     NOT NULL,
    quota            INTEGER     NOT NULL,
    enrolled_count   INTEGER     NOT NULL DEFAULT 0,
    status           TEXT        NOT NULL DEFAULT 'open',  -- open|closed|recalled|withdrawn
    opened_by        TEXT        NOT NULL,
    countersigned_by TEXT        NOT NULL,               -- the second person (F12, G5)
    opened_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at        TIMESTAMPTZ,
    recall_notice    TEXT,
    recalled_at      TIMESTAMPTZ,
    CONSTRAINT batch_status_valid CHECK (status IN ('open','closed','recalled','withdrawn')),
    CONSTRAINT batch_quota_positive CHECK (quota > 0),
    CONSTRAINT batch_quota_not_exceeded CHECK (enrolled_count <= quota),
    CONSTRAINT batch_two_person CHECK (countersigned_by <> opened_by),
    CONSTRAINT batch_shelf_life_sane CHECK (shelf_life_days BETWEEN 1 AND 3650)
);

-- `batch_quota_not_exceeded` is a DB-level invariant on purpose. Enforce invariants
-- where they cannot be bypassed — an application-level count is a race, a CHECK is not.

-- --------------------------------------------------------------- products ---
CREATE TABLE IF NOT EXISTS products (
    id                 BIGSERIAL   PRIMARY KEY,
    tag_index          TEXT        NOT NULL UNIQUE,     -- HMAC(TAG_INDEX_KEY, uid). UNIQUE closes D10/F7.
    binding_token_hash TEXT        NOT NULL,            -- SHA-256 of the 128-bit token on the tag

    product_id_ct      TEXT        NOT NULL,            -- {"n":...,"c":...} JSON text, AES-256-GCM
    batch_id_ct        TEXT        NOT NULL,
    mfg_date_ct        TEXT        NOT NULL,
    tag_uid_ct         TEXT        NOT NULL,
    enc_dek            TEXT        NOT NULL,            -- epk||nonce||wrapped DEK, hex

    shelf_life         INTEGER     NOT NULL,
    expiry_date        DATE        NOT NULL,
    crypto_version     TEXT        NOT NULL DEFAULT 'aes_gcm_v2',
    enrol_counter      INTEGER     NOT NULL,            -- counter value captured at enrolment
    batch_ref          TEXT        NOT NULL REFERENCES batches(batch_ref),
    device_id          UUID        NOT NULL REFERENCES device_registry(device_id),
    originality_status TEXT        NOT NULL DEFAULT 'unverified',
    status             TEXT        NOT NULL DEFAULT 'active',
    binding_class      TEXT        NOT NULL DEFAULT 'counter',  -- counter | none (QR fallback, F4)
    enrolled_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    superseded_by      BIGINT      REFERENCES products(id),

    row_sig            TEXT        NOT NULL,
    row_sig_alg        TEXT        NOT NULL DEFAULT 'ed25519',
    row_key_version    INTEGER     NOT NULL DEFAULT 1,

    CONSTRAINT products_crypto_version_valid CHECK (crypto_version = 'aes_gcm_v2'),
    CONSTRAINT products_status_valid
        CHECK (status IN ('active','recalled','withdrawn','destroyed','superseded')),
    CONSTRAINT products_originality_valid
        CHECK (originality_status IN ('verified','unverified','failed')),
    CONSTRAINT products_binding_class_valid CHECK (binding_class IN ('counter','none')),
    CONSTRAINT products_enrol_counter_sane CHECK (enrol_counter BETWEEN 0 AND 16777215)
);
CREATE INDEX IF NOT EXISTS idx_products_tag_index ON products(tag_index);
CREATE INDEX IF NOT EXISTS idx_products_batch_ref ON products(batch_ref);

-- ----------------------------------------------------- MTA counter state ---
CREATE TABLE IF NOT EXISTS tag_counter_state (
    tag_index         TEXT        PRIMARY KEY REFERENCES products(tag_index) ON DELETE CASCADE,
    max_counter       INTEGER     NOT NULL,
    observation_count INTEGER     NOT NULL DEFAULT 0,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_region       TEXT,                             -- coarse geo, for impossible-travel
    status            TEXT        NOT NULL DEFAULT 'ok', -- ok | suspect_duplicate | frozen
    CONSTRAINT counter_state_status_valid CHECK (status IN ('ok','suspect_duplicate','frozen')),
    CONSTRAINT counter_state_max_sane CHECK (max_counter BETWEEN 0 AND 16777215)
);

-- G1: SUSPECT_DUPLICATE is STICKY. There is deliberately no path from
-- 'suspect_duplicate' back to 'ok' except an explicit, audited admin action.
-- A counterfeiter must not be able to probe which stolen identifiers are still good.

CREATE TABLE IF NOT EXISTS divergence_incident (
    id               BIGSERIAL   PRIMARY KEY,
    tag_index        TEXT        NOT NULL,
    observed_counter INTEGER     NOT NULL,
    expected_min     INTEGER     NOT NULL,
    velocity_bound   INTEGER,
    kind             TEXT        NOT NULL,   -- rollback | repeat | velocity | geo | mirror_disabled
    source_ip_hash   TEXT,
    user_agent_class TEXT,
    resolution       TEXT        NOT NULL DEFAULT 'open', -- open|confirmed|false_positive|closed
    resolved_by      TEXT,
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT incident_kind_valid
        CHECK (kind IN ('rollback','repeat','velocity','geo','mirror_disabled')),
    CONSTRAINT incident_resolution_valid
        CHECK (resolution IN ('open','confirmed','false_positive','closed'))
);
CREATE INDEX IF NOT EXISTS idx_incident_tag_index  ON divergence_incident(tag_index);
CREATE INDEX IF NOT EXISTS idx_incident_created_at ON divergence_incident(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_open       ON divergence_incident(resolution)
    WHERE resolution = 'open';

-- --------------------------------------------------------- idempotency ----
CREATE TABLE IF NOT EXISTS idempotency_key (
    key             UUID        PRIMARY KEY,
    device_id       UUID        NOT NULL,
    request_hash    TEXT        NOT NULL,      -- sha256 of the raw body
    response_status INTEGER     NOT NULL,
    response_body   JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_idem_created_at ON idempotency_key(created_at);

-- --------------------------------------------------------- audit (chained) -
CREATE TABLE IF NOT EXISTS audit_log (
    seq          BIGSERIAL   PRIMARY KEY,
    event_type   TEXT        NOT NULL,
    tag_index    TEXT,
    actor        TEXT,                          -- device_id, admin subject, or 'public'
    result       TEXT,
    source_ip_hash TEXT,                        -- HMAC(IP_HASH_KEY_today, ip). Never a raw IP.
    user_agent_class TEXT,                      -- 'android-chrome' etc. Never the raw UA string.
    detail       JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_hash    TEXT        NOT NULL,
    entry_hash   TEXT        NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tag_index  ON audit_log(tag_index);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at DESC);

-- -------------------------------------------------------- consumer reports -
CREATE TABLE IF NOT EXISTS consumer_report (
    id            BIGSERIAL   PRIMARY KEY,
    tag_index     TEXT,
    verdict_shown TEXT,
    pharmacy_name TEXT,
    city          TEXT,
    note          TEXT,
    contact       TEXT,                          -- optional, consumer-supplied
    triage        TEXT        NOT NULL DEFAULT 'new',  -- new|reviewing|actioned|spam
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT report_triage_valid CHECK (triage IN ('new','reviewing','actioned','spam'))
);
CREATE INDEX IF NOT EXISTS idx_report_triage ON consumer_report(triage) WHERE triage = 'new';

-- ---------------------------------------------------------- transparency ---
CREATE TABLE IF NOT EXISTS transparency_root (
    id            BIGSERIAL   PRIMARY KEY,
    as_of_date    DATE        NOT NULL UNIQUE,
    merkle_root   TEXT        NOT NULL,
    record_count  INTEGER     NOT NULL,
    audit_head    TEXT        NOT NULL,          -- latest audit_log.entry_hash
    signature     TEXT        NOT NULL,
    published_url TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------- rate limiting ----
-- Second layer behind the Cloudflare Worker, for the case where the edge is
-- bypassed (someone hits the Render origin directly). Fixed-window counters.
CREATE TABLE IF NOT EXISTS rate_limit_bucket (
    bucket_key   TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    hits         INTEGER     NOT NULL DEFAULT 1,
    PRIMARY KEY (bucket_key, window_start)
);
CREATE INDEX IF NOT EXISTS idx_rl_window ON rate_limit_bucket(window_start);
