from dotenv import load_dotenv
import os
import requests
import pandas as pd
import time
from tqdm import tqdm

load_dotenv('.env')

class EmailSearch:
    def __init__(self):
        """Initialize with database connection"""
        # Hunter API key
        self.api_key = os.environ.get('HUNTER_API_KEY')
        if not self.api_key:
            raise ValueError("HUNTER_API_KEY not found in environment variables")

    def search(self, employees):
        """Search for emails for all employees in the database"""
        for employee in tqdm(employees, desc="Searching for emails"):
            employee_id = employee['id']
            first_name = employee['first_name']
            last_name = employee['last_name']
            domain = employee['domain']
            results = []
            
            try:
                response = self.fetch_hunter_data(first_name, last_name, domain)
                if response.status_code == 200:
                    data = response.json()
                    email = data.get('data', {}).get('email')
                    score = data.get('data', {}).get('score')
                    results.append({
                        'employee_id': employee_id,
                        'email': email,
                        'score': score
                    })
                else:
                    print(f"Failed to fetch for {first_name} {last_name}: {response.status_code}")
                
                # Sleep to avoid rate limiting
                time.sleep(1)
                
            except Exception as e:
                print(f"Error for {first_name} {last_name}: {e}")
        
        print(f"Email search completed for {len(employees)} employees")
        return results

    def fetch_hunter_data(self, first_name, last_name, domain):
        # endpoint for email finder
        api_endpoint = "https://api.hunter.io/v2/email-finder"
        response = requests.get(f"{api_endpoint}?domain={domain}&first_name={first_name}&last_name={last_name}&api_key={self.api_key}")
        return response