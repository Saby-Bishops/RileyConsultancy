# API Research and Integration
## Shodan API Integration
-Authentication
To authenticate with the Shodan API, you need an API key. Follow these steps to obtain and use the API key:

Sign up for a Shodan account at Shodan.
Navigate to your account settings and obtain your API key.
Store the API key in a .env file in the src/api_keys directory:
SHODAN_API_KEY=your_api_key_here

-Usage
You can use the requests library in Python to make API calls. Below is an example script to fetch data from Shodan:

import requests
import os
from dotenv import load_dotenv

--Construct the path to the .env file relative to the script's location
dotenv_path = os.path.join(os.path.dirname(__file__), '../api_keys/.env')
load_dotenv(dotenv_path)

--Get the Shodan API key from environment variables
API_KEY = os.getenv('SHODAN_API_KEY')
if not API_KEY:
    raise ValueError("No SHODAN_API_KEY found in environment variables")

IP = "8.8.8.8"
URL = f"https://api.shodan.io/shodan/host/{IP}?key={API_KEY}"

response = requests.get(URL)
print(response.json())

## IPinfo API Integration
-Authentication
To authenticate with the IPinfo API, you need an API key. Follow these steps to obtain and use the API key:

Sign up for an IPinfo account at IPinfo.
Navigate to your account settings and obtain your API key.
Store the API key in a .env file in the api_keys directory:
IPINFO_API_KEY=your_api_key_here

-Usage
You can use the requests library in Python to make API calls. Below is an example script to fetch data from IPinfo:

import requests
import os
from dotenv import load_dotenv

--Construct the path to the .env file relative to the script's location
dotenv_path = os.path.join(os.path.dirname(__file__), '../api_keys/.env')
load_dotenv(dotenv_path)

--Get the IPinfo API key from environment variables
API_KEY = os.getenv('IPINFO_API_KEY')
if not API_KEY:
    raise ValueError("No IPINFO_API_KEY found in environment variables")

IP = "8.8.8.8"
URL = f"https://ipinfo.io/{IP}/json?token={API_KEY}"

response = requests.get(URL)
print(response.json())

## VirusTotal API Integration
-Authentication
To authenticate with the VirusTotal API, you need an API key. Follow these steps to obtain and use the API key:

Sign up for a VirusTotal account at VirusTotal.
Navigate to your account settings and obtain your API key.
Store the API key in a .env file in the api_keys directory:

VIRUSTOTAL_API_KEY=your_api_key_here

-Usage
You can use the requests library in Python to make API calls. Below is an example script to fetch data from VirusTotal:

import requests
import os
from dotenv import load_dotenv

--Construct the path to the .env file relative to the script's location
dotenv_path = os.path.join(os.path.dirname(__file__), '../api_keys/.env')
load_dotenv(dotenv_path)

--Get the VirusTotal API key from environment variables
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
if not API_KEY:
    raise ValueError("No VIRUSTOTAL_API_KEY found in environment variables")

URL_TO_SCAN = "http://example.com"
URL = "https://www.virustotal.com/api/v3/urls"

headers = {
    "x-apikey": API_KEY
}

params = {
    "url": URL_TO_SCAN
}

response = requests.post(URL, headers=headers, data=params)
print(response.json())