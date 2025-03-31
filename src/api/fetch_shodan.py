import requests
import os
from dotenv import load_dotenv
import psycopg2
from psycopg2 import sql

# Construct the path to the .env file relative to the script's location
dotenv_path = os.path.join(os.path.dirname(__file__), '../api_keys/.env')
load_dotenv(dotenv_path)
# Get the Shodan API key from environment variables
API_KEY = os.getenv('SHODAN_API_KEY')
# Get the database connection string from environment variables
DB_CONNECTION_STRING = os.getenv('DATABASE_URL')

def authenticate():    
    if not API_KEY:
        raise ValueError("Shodan API key is not set in environment variables.")
    return API_KEY

def fetch_threat_data():
    API_KEY = authenticate()
    # Fetch the data
    url = f"https://api.shodan.io/shodan/alerts?key={API_KEY}"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Error fetching data from Shodan: {response.status_code} - {response.text}")
    
    return response.json()

def store_threat_data(threat_data):
    if not DB_CONNECTION_STRING:
        raise ValueError("No DATABASE_URL found in environment variables")

    conn = psycopg2.connect(DB_CONNECTION_STRING)
    cursor = conn.cursor()

    for threat in threat_data.get('matches', []):
        threat_name = threat.get('name', 'Unknown Threat')
        vulnerability_description = threat.get('description', 'No description available')
        likelihood = threat.get('likelihood', 1)  # Default value if missing
        impact = threat.get('impact', 1)  # Default value if missing

        # Ensure asset_id exists; if missing, create a default asset
        asset_id = threat.get('asset_id')
        if asset_id is None:
            cursor.execute(
                sql.SQL("INSERT INTO assets (name, category, description, risk_level) VALUES (%s, %s, %s, %s) RETURNING id"),
                ('Unknown Asset', 'Uncategorized', 'Auto-created asset', 5)
            )
            asset_id = cursor.fetchone()[0]  # Fetch the newly created asset ID

        # Insert threat data (if it doesn't already exist)
        cursor.execute(
            sql.SQL("""
                INSERT INTO threats (asset_id, threat_name, vulnerability_description, likelihood, impact) 
                VALUES (%s, %s, %s, %s, %s) 
                ON CONFLICT (threat_name) DO UPDATE SET 
                vulnerability_description = EXCLUDED.vulnerability_description,
                likelihood = EXCLUDED.likelihood,
                impact = EXCLUDED.impact
            """),
            (asset_id, threat_name, vulnerability_description, likelihood, impact)
        )

    conn.commit()
    cursor.close()
    conn.close()

def main():
    threat_data = fetch_threat_data()
    store_threat_data(threat_data)

if __name__ == "__main__":
    main()