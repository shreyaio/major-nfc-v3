"""
Database Bootstrap Script
Creates the products table if it doesn't already exist. Safe to rerun against a
populated database — it will NOT drop or touch existing data. For schema changes
on top of an existing table, use migrate.py instead.
"""

from db import get_connection
import sys

def init_database():
    """Create the products table with full security schema (idempotent)"""
    print("\n" + "="*60)
    print("DATABASE BOOTSTRAP (idempotent — creates table if missing)")
    print("="*60)

    try:
        conn = get_connection()
        if not conn:
            print("\n[ERROR] Could not connect to the database.")
            return False
        cur = conn.cursor()

        # Create products table with 17 columns (no-op if it already exists)
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            product_id TEXT NOT NULL,
            product_id_iv TEXT NOT NULL,
            batch_id TEXT NOT NULL,
            batch_id_iv TEXT NOT NULL,
            mfg_date TEXT NOT NULL,
            mfg_date_iv TEXT NOT NULL,
            tag_uid TEXT NOT NULL,
            tag_uid_iv TEXT NOT NULL,
            shelf_life INTEGER NOT NULL,
            expiry_date DATE NOT NULL,
            payload_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            nonce TEXT NOT NULL,
            key_chars TEXT NOT NULL,
            tag_uid_hash TEXT NOT NULL
        );
        """

        print("\nCreating products table with full schema...")
        cur.execute(create_table_sql)

        # Create indexes (no-op if they already exist)
        print("Creating indexes...")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tag_uid_hash ON products(tag_uid_hash);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tag_uid ON products(tag_uid);")

        conn.commit()
        print("[OK] Products table created successfully!")

        cur.close()
        conn.close()

        print("\n" + "="*60)
        print("[OK] Database bootstrap complete!")
        print("="*60)
        return True

    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}")
        print(f"Message: {str(e)}")
        return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
