import os
import requests
import json
import concurrent.futures
from urllib.parse import quote
from tqdm import tqdm

class UsernameSearch:
    def __init__(self, data_file='whatsmyname_data.json'):
        """Initialize with the path to the WhatsMyName data file and database"""
        # Load WhatsMyName data
        if not os.path.exists(data_file):
            self.fetch_wmn_data()

        with open(data_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.sites = data.get('sites', [])
        self.categories = data.get('categories', [])
    
    def search_username(self, username, employee_id=None, first_name=None, last_name=None, domain=None, 
                        max_concurrent=10, timeout=10, categories=None):
        """
        Search for username across multiple sites and save results to database
        
        Args:
            username: The username to search for
            employee_id: Optional ID of the employee (will be looked up if not provided)
            first_name: First name (required if employee_id not provided)
            last_name: Last name (required if employee_id not provided)
            domain: Domain (required if employee_id not provided)
            max_concurrent: Maximum number of concurrent requests
            timeout: Request timeout in seconds
            categories: List of categories to search (None for all)
            
        Returns:
            List of dictionaries containing search results
        """
        results = []
        
        # Get or create employee ID
        if employee_id is None:
            if None in (first_name, last_name, domain):
                raise ValueError("Must provide either employee_id or all of: first_name, last_name, domain")
            employee_id = self.get_employee_id(first_name, last_name, domain)
        
        # Filter sites by category if specified
        sites_to_check = self.sites
        if categories:
            sites_to_check = [site for site in self.sites if site.get('cat') in categories]
        
        # Create a function to check a single site
        def check_site(site):
            try:
                # Prepare URL
                check_url = site['uri_check'].replace('{account}', quote(username))
                pretty_url = site.get('uri_pretty', check_url).replace('{account}', quote(username))
                
                # Prepare headers and request method
                headers = site.get('headers', {})
                method = 'POST' if 'post_body' in site else 'GET'
                
                # Prepare post data if needed
                data = None
                if method == 'POST' and 'post_body' in site:
                    data = site['post_body'].replace('{account}', username)
                    
                    # Handle JSON data
                    if 'Content-Type' in headers and 'application/json' in headers['Content-Type']:
                        try:
                            data = json.loads(data)
                        except:
                            pass
                
                # Make the request
                response = requests.request(
                    method=method,
                    url=check_url,
                    headers=headers,
                    data=data,
                    timeout=timeout,
                    allow_redirects=True
                )
                
                # Check if the account exists
                exists = False
                
                # Check for existence based on expected status code
                if response.status_code == site.get('e_code', 200):
                    # Check for expected string in response
                    if 'e_string' in site and site['e_string'] in response.text:
                        exists = True
                
                # Check for non-existence based on missing status code
                elif response.status_code == site.get('m_code', 404):
                    # Check for missing string in response
                    if 'm_string' in site and site['m_string'] in response.text:
                        exists = False
                    else:
                        exists = True
                
                result = {
                    'site_name': site['name'],
                    'url_user': pretty_url,
                    'exists': exists,
                    'category': site.get('cat', 'unknown'),
                    'http_status': response.status_code
                }
                
                # Save to database if account exists
                if exists:
                    self.save_account_finding(
                        employee_id=employee_id,
                        username=username,
                        site_name=site['name'],
                        url=pretty_url,
                        category=site.get('cat', 'unknown'),
                        http_status=response.status_code
                    )
                
                return result
            
            except Exception as e:
                return {
                    'site_name': site['name'],
                    'url_user': site.get('uri_pretty', site['uri_check']).replace('{account}', quote(username)),
                    'exists': None,  # Unknown
                    'category': site.get('cat', 'unknown'),
                    'error': str(e)
                }
        
        # Process sites with concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_to_site = {executor.submit(check_site, site): site for site in sites_to_check}
            
            # Use tqdm for a progress bar
            for future in tqdm(concurrent.futures.as_completed(future_to_site), total=len(sites_to_check), desc=f"Searching for '{username}'"):
                result = future.result()
                if result:
                    results.append(result)
        
        return results
    
    def get_stats(self, results):
        """Get statistics from search results"""
        total = len(results)
        found = sum(1 for r in results if r.get('exists'))
        errors = sum(1 for r in results if 'error' in r)
        
        # Count by category
        categories = {}
        for result in results:
            if result.get('exists'):
                cat = result.get('category', 'unknown')
                categories[cat] = categories.get(cat, 0) + 1
        
        return {
            'total_checked': total,
            'accounts_found': found,
            'errors': errors,
            'found_by_category': categories
        }
    
    def print_results(self, username, results):
        """Print formatted results to console"""
        stats = self.get_stats(results)
        
        print(f"\n===== Results for username: {username} =====")
        print(f"Checked {stats['total_checked']} sites, found {stats['accounts_found']} accounts")
        
        if stats['accounts_found'] > 0:
            print("\n=== Accounts Found ===")
            for cat in sorted(stats['found_by_category'].keys()):
                print(f"\n-- {cat.upper()} ({stats['found_by_category'][cat]}) --")
                for result in sorted([r for r in results if r.get('exists') and r.get('category') == cat], 
                                   key=lambda x: x['site_name']):
                    print(f"- {result['site_name']}: {result['url_user']}")
        
        if stats['errors'] > 0:
            print(f"\n{stats['errors']} errors occurred during the search")
    
    def fetch_wmn_data(self):
        """Fetch the latest WhatsMyName data"""
        url = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/refs/heads/main/wmn-data.json"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print("WhatsMyName data fetched successfully")
        else:
            print(f"Failed to fetch data. Status code: {response.status_code}")
            data = {"sites": [], "categories": []}

        with open('whatsmyname_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return data