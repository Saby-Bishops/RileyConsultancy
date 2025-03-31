import requests
from dotenv import load_dotenv
import os

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(__file__), 'api_keys/.env')
load_dotenv(dotenv_path)

API_KEY = os.getenv("OPENROUTER_API_KEY")
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


# Example usage 
risk_score = analyze_risk("SQL Injection", 4, 5) 
print(f"AI-Assessed Risk Score: {risk_score}")
