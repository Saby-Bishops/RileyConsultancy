import requests
import os
from dotenv import load_dotenv

# Construct the path to the .env file relative to the script's location
dotenv_path = os.path.join(os.path.dirname(__file__), '../api_keys/.env')
load_dotenv(dotenv_path)

# Get the VirusTotal API key from environment variables
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
if not API_KEY:
    raise ValueError("No VIRUSTOTAL_API_KEY found in environment variables")

# Prompt the user for the URL to scan
URL_TO_SCAN = input("Enter the URL to scan: ")
URL = "https://www.virustotal.com/api/v3/urls"

headers = {
    "x-apikey": API_KEY
}

params = {
    "url": URL_TO_SCAN
}

response = requests.post(URL, headers=headers, data=params)
print(response.json())