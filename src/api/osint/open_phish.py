import requests
from datetime import datetime
from urllib.parse import urlparse

def fetch_phishing_urls():
    # URL to the OpenPhish feed
    url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    
    try:
        # Fetch the content
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        # Get all URLs as a list (one URL per line)
        phishing_urls = response.text.strip().split('\n')
        
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