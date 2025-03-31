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

# Assign risk to keywords in asset names
# (eg, workstations will all have same risk rating)
# currently unsure what risk ratings to assign to people/processes
risk_map = {
    'server': 8,
    'switch': 6,
    'router': 7,
    'phones': 5,
    'workstation': 6,
    'cms': 6,
    'crm': 7,
    'juice_shop': 9,
    'mariadb': 8,
    'customer_data': 10,
    'employee_data': 9,
    'sales_data': 9,
    'branding_assets': 6,
}

# Update risk_level based on asset name
for name_substring, risk in risk_map.items():
    query = "UPDATE assets SET risk_level = %s WHERE name LIKE %s"
    cursor.execute(query, (risk, f"%{name_substring}%"))

cursor.execute("SELECT id, category FROM assets WHERE category IN ('people', 'processes')")
assets = cursor.fetchall()

for asset_id, category in assets:
    if category == 'people':
        risk = 5
        cursor.execute("UPDATE assets SET risk_level = %s WHERE id = %s", (risk, asset_id))
    elif category == 'processes':
        risk = 7
        cursor.execute("UPDATE assets SET risk_level = %s WHERE id = %s", (risk, asset_id))

conn.commit()
cursor.close()
conn.close()
print("Done.")
