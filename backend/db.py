import psycopg2
from config import DATABASE_URL

def get_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print("❌ DB Connection Error:", e)
        return None


def test_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        print("✅ Connected to PostgreSQL!")

        cur = conn.cursor()
        cur.execute("SELECT version();")
        version = cur.fetchone()

        print("PostgreSQL Version:", version)

        cur.close()
        conn.close()

    except Exception as e:
        print("❌ Connection Failed:", e)


# Run test
if __name__ == "__main__":
    test_connection()