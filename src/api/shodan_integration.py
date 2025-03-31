import requests
import os
import mysql.connector
from dotenv import load_dotenv
from datetime import datetime

# Load API key from .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '../api_keys/.env')
load_dotenv(dotenv_path)

API_KEY = os.getenv('SHODAN_API_KEY')
if not API_KEY:
    raise ValueError("No SHODAN_API_KEY found in environment variables")

# Fetch data from Shodan
IP = "8.8.8.8"
URL = f"https://api.shodan.io/shodan/host/{IP}?key={API_KEY}"

response = requests.get(URL)
data = response.json()

# Check if Shodan API returned data
if "error" in data:
    print(f"Shodan API Error: {data['error']}")
    exit()

# Extract useful information
ip_address = data.get("ip_str", "N/A")
domains = ", ".join(data.get("hostnames", [])) if data.get("hostnames") else "N/A"
threat_type = "Malware"  # Assume a default category (You can update this dynamically)
threat_level = "High"  # Assume a default risk level
source = "Shodan"
details = str(data)  # Store full API response as a JSON string
detected_at = datetime.now()

# Connect to MySQL database
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="shopsmart"
)
cursor = conn.cursor()

# Insert data into `threat_data` table
query = """
INSERT INTO threat_data (ip_address, domain, threat_type, threat_level, source, details, detected_at)
VALUES (%s, %s, %s, %s, %s, %s, %s)
"""

values = (ip_address, domains, threat_type, threat_level, source, details, detected_at)

cursor.execute(query, values)
conn.commit()

print("Shodan threat data inserted successfully!")

# Close database connection
cursor.close()
conn.close()
