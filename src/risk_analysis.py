import openai
from dotenv import load_dotenv
import os

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

def analyze_risk(threat, likelihood, impact): 
    prompt = f"Analyze the risk score for {threat} with likelihood {likelihood} and impact {impact}." 
    response = openai.ChatCompletion.create( 
        model="gpt-3.5-turbo", 
        messages=[{"role": "system", "content": prompt}] 
    ) 
    return response["choices"][0]["message"]["content"] 

# Example usage 
risk_score = analyze_risk("SQL Injection", 4, 5) 
print(f"AI-Assessed Risk Score: {risk_score}")
