"""
Additive, idempotent schema migration.
Safe to run repeatedly against a fresh or already-populated database.
Run after init_db.py (or directly against an existing DB): python migrate.py
"""

from db import get_connection
import sys

STATEMENTS = [
    # crypto_version tags each row as 'paper_v1' (existing rows) or 'aes_gcm_v1' (new rows).
    "ALTER TABLE products ADD COLUMN IF NOT EXISTS crypto_version TEXT NOT NULL DEFAULT 'paper_v1';",

    # aes_gcm_v1 rows never populate key_chars (no key-derivation material is stored anymore).
    "ALTER TABLE products ALTER COLUMN key_chars DROP NOT NULL;",

    # Real replay protection: a nonce can only ever be inserted once.
    """
    DO $$ BEGIN
        ALTER TABLE products ADD CONSTRAINT uq_products_nonce UNIQUE (nonce);
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    """,

    # Audit trail for every product write and every consumer verify attempt.
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id           SERIAL PRIMARY KEY,
        event_type   TEXT NOT NULL,
        tag_uid_hash TEXT,
        result       TEXT,
        source_ip    TEXT,
        user_agent   TEXT,
        detail       JSONB,
        created_at   TIMESTAMPTZ DEFAULT NOW()
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_tag_uid_hash ON audit_log(tag_uid_hash);",
    "CREATE INDEX IF NOT EXISTS idx_audit_event_type    ON audit_log(event_type);",
    "CREATE INDEX IF NOT EXISTS idx_audit_created_at    ON audit_log(created_at);",

    # Row Level Security: the backend connects with Supabase's "postgres" role,
    # which bypasses RLS, so this doesn't affect the app. What it does do is stop
    # Supabase's auto-generated REST API (PostgREST) from reading or writing these
    # tables if it's ever queried with the project's anon/public key -- with RLS
    # enabled and no policies granted to anon/authenticated, that path is a dead
    # end. The only route to this data is through the Flask backend.
    "ALTER TABLE products ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;",
]


def run_migration():
    print("\n" + "=" * 60)
    print("SCHEMA MIGRATION (additive, idempotent)")
    print("=" * 60)

    conn = get_connection()
    if not conn:
        print("\n[ERROR] Could not connect to the database.")
        return False

    try:
        cur = conn.cursor()
        for stmt in STATEMENTS:
            cur.execute(stmt)
        conn.commit()
        cur.close()
        conn.close()
        print("\n[OK] Migration applied successfully.")
        return True
    except Exception as e:
        conn.rollback()
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        return False


if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
