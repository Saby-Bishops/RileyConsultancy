import requests
import os
from dotenv import load_dotenv

# Construct the path to the .env file relative to the script's location
dotenv_path = os.path.join(os.path.dirname(__file__), '../api_keys/.env')
load_dotenv(dotenv_path)

# Get the IPinfo API key from environment variables
API_KEY = os.getenv('IPINFO_API_KEY')
if not API_KEY:
    raise ValueError("No IPINFO_API_KEY found in environment variables")

IP = "8.8.8.8"
URL = f"https://ipinfo.io/{IP}/json?token={API_KEY}"

response = requests.get(URL)
print(response.json())