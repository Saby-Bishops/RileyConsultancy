from dotenv import load_dotenv
import os
import requests
import pandas as pd
import time
from tqdm import tqdm
import json
import sqlite3

load_dotenv('.env')

class EmailSearch:
    def __init__(self, db_path='osint.db'):
        """Initialize with database connection"""
        load_dotenv('.env')
        
        # Connect to the database
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        
        # Ensure the database schema exists
        self._init_db()
        
        # Hunter API key
        self.api_key = os.environ.get('HUNTER_API_KEY')
        if not self.api_key:
            raise ValueError("HUNTER_API_KEY not found in environment variables")
        
    def _init_db(self):
        """Initialize database tables if they don't exist"""
        schema_path = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, os.pardir, 'db/schema.sql')
        with open('schema.sql', 'r') as f:
            schema = f.read()
            self.conn.executescript(schema)
            self.conn.commit()

    def search(self):
        """Search for emails for all employees in the database"""
        # Get all employees without email results
        self.cursor.execute("""
            SELECT e.id, e.first_name, e.last_name, e.domain
            FROM employees e
            LEFT JOIN email_results er ON e.id = er.employee_id
            WHERE er.id IS NULL
        """)
        
        employees = self.cursor.fetchall()
        
        for employee in tqdm(employees, desc="Searching for emails"):
            employee_id = employee['id']
            first_name = employee['first_name']
            last_name = employee['last_name']
            domain = employee['domain']
            
            try:
                response = self.fetch_hunter_data(first_name, last_name, domain)
                if response.status_code == 200:
                    data = response.json()
                    email = data.get('data', {}).get('email')
                    score = data.get('data', {}).get('score')
                    
                    # Save to database
                    self.cursor.execute(
                        "INSERT INTO email_results (employee_id, email, score) VALUES (?, ?, ?)",
                        (employee_id, email, score)
                    )
                    self.conn.commit()
                    
                else:
                    print(f"Failed to fetch for {first_name} {last_name}: {response.status_code}")
                
                # Sleep to avoid rate limiting
                time.sleep(1)
                
            except Exception as e:
                print(f"Error for {first_name} {last_name}: {e}")
        
        print(f"Email search completed for {len(employees)} employees")

    def fetch_hunter_data(self, first_name, last_name, domain):
        # endpoint for email finder
        api_endpoint = "https://api.hunter.io/v2/email-finder"
        response = requests.get(f"{api_endpoint}?domain={domain}&first_name={first_name}&last_name={last_name}&api_key={self.api_key}")
        return response
    
    def get_all_results(self):
        """Get all email results from the database with employee information"""
        self.cursor.execute("""
            SELECT 
                e.id as employee_id,
                e.first_name,
                e.last_name,
                e.domain,
                er.email,
                er.score
            FROM 
                employees e
            LEFT JOIN 
                email_results er ON e.id = er.employee_id
            ORDER BY 
                e.last_name, e.first_name
        """)
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def __del__(self):
        """Close database connection when object is destroyed"""
        if hasattr(self, 'conn'):
            self.conn.close()