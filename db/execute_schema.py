import mysql.connector

conn = mysql.connector.connect(
    host="100.106.166.35",
    port=3306,
    user="appuser",
    password="apppass",
    database="infosec"
)

cursor = conn.cursor()

with open("./db/schema.sql", "r") as f:
    schema = f.read()

cursor.execute(schema)