import psycopg2
from config import DATABASE_URL

def check_schema():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'products'
            ORDER BY ordinal_position;
        """)
        columns = cur.fetchall()
        print("Columns in 'products' table:")
        for col in columns:
            print(f"- {col[0]} ({col[1]})")
        cur.close()
        conn.close()
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    check_schema()
