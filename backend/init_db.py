"""
Database Initialization Script
Run this to create or update the products table to the 17-column schema.
"""

from db import get_connection
import sys

def init_database():
    """Create the products table with full security schema"""
    print("\n" + "="*60)
    print("DATABASE INITIALIZATION (Plan 2 Schema)")
    print("="*60)

    try:
        conn = get_connection()
        cur = conn.cursor()

        # We will DROP and RECREATE for a clean state in development, 
        # but you can use ALTER TABLE if you have data you want to keep.
        # Since we are debugging, a clean table is safer.
        print("\nDropping old table (if exists)...")
        cur.execute("DROP TABLE IF EXISTS products;")

        # Create products table with 17 columns
        create_table_sql = """
        CREATE TABLE products (
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

        # Create indexes
        print("Creating indexes...")
        cur.execute("CREATE INDEX idx_tag_uid_hash ON products(tag_uid_hash);")
        cur.execute("CREATE INDEX idx_tag_uid ON products(tag_uid);")

        conn.commit()
        print("✅ Products table created successfully with 17 columns!")

        cur.close()
        conn.close()

        print("\n" + "="*60)
        print("✅ Database initialization complete!")
        print("="*60)
        return True

    except Exception as e:
        print(f"\n❌ ERROR: {type(e).__name__}")
        print(f"Message: {str(e)}")
        return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
