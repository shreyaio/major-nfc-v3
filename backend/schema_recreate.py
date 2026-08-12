import psycopg2
from config import DATABASE_URL

def recreate_table():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        print("Dropping products table...")
        cur.execute("DROP TABLE IF EXISTS products;")
        
        print("Creating products table with interleaved schema...")
        cur.execute("""
            CREATE TABLE products (
                id              SERIAL PRIMARY KEY,
                product_id      TEXT NOT NULL,
                product_id_iv   TEXT NOT NULL,
                batch_id        TEXT NOT NULL,
                batch_id_iv     TEXT NOT NULL,
                mfg_date        TEXT NOT NULL,
                mfg_date_iv     TEXT NOT NULL,
                tag_uid         TEXT NOT NULL,
                tag_uid_iv      TEXT NOT NULL,
                shelf_life      INTEGER NOT NULL,
                expiry_date     DATE NOT NULL,
                payload_hash    TEXT NOT NULL,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                nonce           TEXT NOT NULL,
                key_chars       TEXT NOT NULL,
                tag_uid_hash    TEXT NOT NULL
            );
        """)
        
        conn.commit()
        print("Schema recreated successfully!")
        cur.close()
        conn.close()
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    recreate_table()
