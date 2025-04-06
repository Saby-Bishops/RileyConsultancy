import requests
from dotenv import load_dotenv
import os
import psycopg2
from psycopg2 import sql

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(__file__), 'api_keys/.env')
load_dotenv(dotenv_path)
# Get the database connection string from environment variables
DB_CONNECTION_STRING = os.getenv('DATABASE_URL')
# Ensure the API key is set in the environment variables
if not os.getenv("OPENROUTER_API_KEY"):
    raise ValueError("OpenRouter API key is not set in environment variables.")
# Get the OpenRouter API key from environment variables
API_KEY = os.getenv("OPENROUTER_API_KEY")
# Define the OpenRouter API URL
API_URL = "https://openrouter.ai/api/v1/chat/completions"

def analyze_risk(threat, likelihood, impact): 
    prompt = f"Analyze the risk score for {threat} with likelihood {likelihood} and impact {impact}."

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "mistralai/mixtral-8x7b-instruct",
        "max_tokens": 300,
        "temperature": 0.3,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    response = requests.post(API_URL, headers=headers, json=data)

    # DEBUG: print full response
    try:
        response_json = response.json()
        print("Raw response:", response_json)
        return response_json["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Failed to get a valid response. Error: {e}"


def get_latest_risk_data(threat_name):
    conn = psycopg2.connect(DB_CONNECTION_STRING)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT likelihood, impact
        FROM threats
        WHERE threat_name = %s
    """, (threat_name,))
    
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        return result[0], result[1]  # likelihood, impact
    else:
        return None, None

# Example usage
threat_name = "SQL Injection"
likelihood, impact = get_latest_risk_data(threat_name)
if likelihood and impact:
    risk_score = analyze_risk(threat_name, likelihood, impact)
    print(f"AI-Assessed Risk Score: {risk_score}")
else:
    print(f"No data found for threat: {threat_name}")
