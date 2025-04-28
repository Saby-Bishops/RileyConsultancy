import requests
from datetime import datetime
from urllib.parse import urlparse
import os

def fetch_phishing_urls():
    # URL to the OpenPhish feed
    data_path = os.path.join(os.path.dirname(__file__), 'data')
    file_path = os.path.join(data_path, 'ALL-phishing-domains.lst')
    
    try:
        with open(file_path, 'r') as file:
            # Read the entire content of the file
            content = file.read()
            phishing_urls = content.splitlines()
            # Remove any empty lines
            phishing_urls = [url for url in phishing_urls if url.strip()]
        # Add timestamp for when this data was collected
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return phishing_urls, timestamp
    
    except requests.RequestException as e:
        print(f"Error fetching phishing URLs: {e}")
        return None, None
    
def extract_domains(urls):
    domains = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        domains.append(domain)
    
    return domains