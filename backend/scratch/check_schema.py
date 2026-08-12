from db import get_connection

def check_schema():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'products'
        ORDER BY ordinal_position;
    """)
    columns = cur.fetchall()
    for col in columns:
        print(f"{col[0]}: {col[1]}")
    cur.close()
    conn.close()

if __name__ == "__main__":
    check_schema()
