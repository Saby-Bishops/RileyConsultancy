import requests
from datetime import datetime
from urllib.parse import urlparse
import os

def read_file(file_path):
    """
    Reads a file and returns its content as a list of lines.
    """
    with open(file_path, 'r') as file:
        # Read the entire content of the file
        content = file.read()
        lines = content.splitlines()
        # Remove any empty lines
        lines = [line for line in lines if line.strip()]
    
    return lines

def fetch_phishing_urls():
    # URL to the OpenPhish feed
    domain_fn = 'ALL-phishing-domains.lst'
    links_fn = 'ALL-phishing-links.lst'
    domains_url = f'https://phish.co.za/latest/{domain_fn}'
    links_url = f'https://phish.co.za/latest/{links_fn}'
    data_path = os.path.join(os.path.dirname(__file__), 'data')
    domains_path = os.path.join(data_path, domain_fn)
    links_path = os.path.join(data_path, links_fn)

    # Fetch the phishing domains and links
    if not os.path.exists(domains_path):
        response = requests.get(domains_url)
        with open(domains_path, 'wb') as file:
            file.write(response.content)
    if not os.path.exists(links_path):
        response = requests.get(links_url)
        with open(links_path, 'wb') as file:
            file.write(response.content)
    
    try:
        domains = read_file(domains_path)
        links = read_file(links_path)
        # Add timestamp for when this data was collected
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {"timestamp": timestamp, "domains": domains, "links": links}
    
    except requests.RequestException as e:
        print(f"Error fetching phishing URLs: {e}")
        return None
    
def extract_domains(urls):
    domains = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        domains.append(domain)
    
    return domains