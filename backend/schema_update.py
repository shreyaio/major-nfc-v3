import psycopg2
from config import DATABASE_URL

def update_schema():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        # IV columns for CBC decryption
        print("Adding IV columns...")
        cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS product_id_iv TEXT NOT NULL DEFAULT '';")
        cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS batch_id_iv   TEXT NOT NULL DEFAULT '';")
        cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS mfg_date_iv   TEXT NOT NULL DEFAULT '';")
        cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS tag_uid_iv    TEXT NOT NULL DEFAULT '';")
        
        # Stored key seed for /api/keys fallback route
        print("Adding key_chars column...")
        cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS key_chars     TEXT NOT NULL DEFAULT '';")
        
        # Lookup index (SHA-256 of raw tag UID)
        print("Adding tag_uid_hash column...")
        cur.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS tag_uid_hash  TEXT NOT NULL DEFAULT '';")
        
        conn.commit()
        print("✅ Schema updated successfully!")
        cur.close()
        conn.close()
    except Exception as e:
        print("❌ Error updating schema:", e)

if __name__ == "__main__":
    update_schema()
