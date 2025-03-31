import mysql.connector

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

cursor.execute("SELECT * FROM assets;")

rows = cursor.fetchall()

# Print header
column_names = [desc[0] for desc in cursor.description]
print("\t".join(column_names))

# Print rows
for row in rows:
    print("\t".join(str(cell) for cell in row))

cursor.close()
conn.close()