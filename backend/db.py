import psycopg2
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from config import DATABASE_URL


def _with_sslmode(url: str) -> str:
    """Supabase's Postgres requires an SSL connection. If the connection string
    doesn't already specify sslmode, add sslmode=require so psycopg2 negotiates
    TLS instead of failing (or silently connecting unencrypted)."""
    if not url or "sslmode=" in url:
        return url
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["sslmode"] = ["require"]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def get_connection():
    try:
        conn = psycopg2.connect(_with_sslmode(DATABASE_URL))
        return conn
    except Exception as e:
        # Plain ASCII only: emoji here crashes with UnicodeEncodeError on Windows'
        # default cp1252 console, which then masks the real connection error.
        print("[DB] Connection Error:", e)
        return None


def test_connection():
    try:
        conn = psycopg2.connect(_with_sslmode(DATABASE_URL))
        print("[DB] Connected to PostgreSQL!")

        cur = conn.cursor()
        cur.execute("SELECT version();")
        version = cur.fetchone()

        print("PostgreSQL Version:", version)

        cur.close()
        conn.close()

    except Exception as e:
        print("[DB] Connection Failed:", e)


# Run test
if __name__ == "__main__":
    test_connection()