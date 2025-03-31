import mysql.connector
import os

# Connection Settings
DB_HOST = "infosec-db.tail79918a.ts.net"
DB_PORT = 3306
DB_USER = "appuser"
DB_PASS = "apppass"
DB_NAME = "infosec"
SQL_FILE = "insert_assets.sql"

# Connect to DB
print("Connecting to MariaDB...")
conn = mysql.connector.connect(
    host=DB_HOST,
    port=DB_PORT,
    user=DB_USER,
    password=DB_PASS,
    database=DB_NAME
)

cursor = conn.cursor()

# Load SQL file
if os.path.exists(SQL_FILE):
    with open(SQL_FILE, "r") as f:
        sql = f.read()
        print(f"Running {SQL_FILE}...")
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if stmt:
                try:
                    cursor.execute(stmt)
                except mysql.connector.Error as e:
                    print(f"[!] Error executing statement:\n{stmt}\n→ {e}")
    conn.commit()
else:
    print(f"[!] SQL file '{SQL_FILE}' not found.")

# Query the assets table
print("\nAssets table contents:")
cursor.execute("SELECT * FROM assets")
rows = cursor.fetchall()
columns = [desc[0] for desc in cursor.description]

# Print assets
print("\t".join(columns))
for row in rows:
    print("\t".join(str(col) for col in row))

cursor.close()
conn.close()
print("\nDone.")
