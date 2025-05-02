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

def fetch_phishing_urls(url, file_name):
    data_path = os.path.join(os.path.dirname(__file__), 'data')
    file_path = os.path.join(data_path, file_name)

    # Fetch the phishing domains and links
    if not os.path.exists(file_path):
        response = requests.get(url)
        with open(file_path, 'wb') as file:
            file.write(response.content)
    
    try:
        content = read_file(file_path)
        # Add timestamp for when this data was collected
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return {"timestamp": timestamp, "content": content}
    
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