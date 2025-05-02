import datetime
from werkzeug.security import generate_password_hash
from contextlib import contextmanager
from typing import List, Dict, Any, Optional

from db.db_repo import DBRepository
from db.db_connector import DBConnector

class DBManager:
    """
    Database manager that uses DBConnector for pooled cursors,
    and provides repository instances.
    """
    
    def __init__(self, connector: DBConnector):
        """Initialize with database connection settings"""
        self.connector = connector
        self._repositories = {}
        self._ensure_tables_exist()
    
    @contextmanager
    def get_cursor(self):
        """
        Proxy to connector.cursor()
        """
        with self.connector.cursor() as cursor:
            yield cursor
    
    def _ensure_tables_exist(self):
        """Ensure all necessary database tables exist"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS employees (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    first_name VARCHAR(255) NOT NULL,
                    last_name VARCHAR(255) NOT NULL,
                    domain VARCHAR(255)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    employee_id INT,
                    email VARCHAR(255),
                    score DOUBLE,
                    FOREIGN KEY (employee_id) REFERENCES employees (id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS account_findings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    employee_id INT,
                    username VARCHAR(255),
                    site_name VARCHAR(255),
                    url VARCHAR(2083),
                    category VARCHAR(255),
                    http_status INT,
                    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (employee_id) REFERENCES employees (id)
                );
            """)

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS phishing_urls (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    url VARCHAR(2083) NOT NULL,
                    timestamp DATE NOT NULL
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS gvm_scan_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    task_id VARCHAR(255) NOT NULL,
                    timestamp DATETIME NOT NULL,
                    total_vulnerabilities INT NOT NULL,
                    critical_count INT NOT NULL,
                    high_count INT NOT NULL,
                    medium_count INT NOT NULL,
                    low_count INT NOT NULL
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS gvm_vulnerabilities (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_id INT NOT NULL,
                    vuln_id VARCHAR(255) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    host VARCHAR(255) NOT NULL,
                    port VARCHAR(255) NOT NULL,
                    severity VARCHAR(255) NOT NULL,
                    severity_value DOUBLE NOT NULL,
                    description TEXT,
                    cvss_base VARCHAR(255),
                    timestamp DATETIME NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES gvm_scan_sessions(id)
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS nids_alerts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    source_ip VARCHAR(45),
                    destination_ip VARCHAR(45),
                    source_port INT,
                    destination_port INT,
                    protocol INT,
                    threat_type VARCHAR(255),
                    severity VARCHAR(255),
                    description TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    role VARCHAR(50) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL
                );
            ''')

            # Create OSINT data table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS osint_data (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    source VARCHAR(255) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    threat_type VARCHAR(255),
                    confidence FLOAT,
                    url VARCHAR(2083),
                    ioc_type VARCHAR(255),
                    ioc_value TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    tags TEXT,
                    metadata TEXT
                );
            ''')

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    type VARCHAR(50) NOT NULL,
                    filepath VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    days_range INT NOT NULL,
                    threat_types TEXT
                );
            """)
    
    def get_repository(self, table_name):
        """
        Get or create a repository for the specified table
        
        Args:
            table_name: Name of the table
            
        Returns:
            DBRepository instance for the table
        """
        if table_name not in self._repositories:
            self._repositories[table_name] = DBRepository(self.connector, table_name)
        return self._repositories[table_name]
    
    # Convenience methods for common repositories
    def employees(self):
        return self.get_repository('employees')
        
    def email_results(self):
        return self.get_repository('email_results')
        
    def account_findings(self):
        return self.get_repository('account_findings')
        
    def phishing_urls(self):
        return self.get_repository('phishing_urls')
        
    def gvm_scan_sessions(self):
        return self.get_repository('gvm_scan_sessions')
        
    def gvm_vulnerabilities(self):
        return self.get_repository('gvm_vulnerabilities')
        
    def nids_alerts(self):
        return self.get_repository('nids_alerts')
        
    def users(self):
        return self.get_repository('users')
    
    def osint_data(self):
        return self.get_repository('osint_data')
    
    # Compatibility methods with original API
    def save_email_result(self, employee_id, email, score=None):
        """Save or update email result for an employee"""
        data = {
            'employee_id': employee_id,
            'email': email,
            'score': score
        }
        return self.email_results().save(data, unique_fields=['employee_id'])
    
    def save_account_finding(self, employee_id, username, site_name, url, category=None, http_status=None):
        """Save a new account finding for an employee"""
        data = {
            'employee_id': employee_id,
            'username': username,
            'site_name': site_name,
            'url': url,
            'category': category,
            'http_status': http_status
        }
        return self.account_findings().insert(data)
    
    def save_gvm_results(self, task_id, gvm_results):
        """Save GVM results"""
        # First save the session
        session_data = {
            'task_id': task_id,
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_vulnerabilities': gvm_results.get('total', 0),
            'critical_count': gvm_results.get('summary', {}).get('Critical', 0),
            'high_count': gvm_results.get('summary', {}).get('High', 0),
            'medium_count': gvm_results.get('summary', {}).get('Medium', 0),
            'low_count': gvm_results.get('summary', {}).get('Low', 0)
        }
        
        session_id = self.gvm_scan_sessions().insert(session_data)
        
        # Then save each vulnerability
        for vuln in gvm_results.get('results', []):
            vuln_data = {
                'session_id': session_id,
                'vuln_id': vuln.get('id', ''),
                'name': vuln.get('name', 'Unknown'),
                'host': vuln.get('host', 'Unknown'),
                'port': vuln.get('port', 'Unknown'),
                'severity': vuln.get('severity', 'Low'),
                'severity_value': vuln.get('severity_value', 0.0),
                'description': vuln.get('description', 'No description available'),
                'cvss_base': vuln.get('cvss_base', 'N/A'),
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.gvm_vulnerabilities().insert(vuln_data)
        
        return session_id
    
    def save_alert(self, alert_data):
        """Save an alert to the database"""
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        return self.nids_alerts().insert(alert_data)
    
    def save_phishing_data(self, urls, timestamp):
        """Save phishing data to the database"""
        ids = []
        for url in urls:
            data = {
                'url': url,
                'timestamp': timestamp
            }
            ids.append(self.phishing_urls().insert(data))
        return ids
    
    def show_phishing_urls(self):
        """Fetch and display phishing URLs from the database"""
        return self.phishing_urls().find()
    
    def get_gvm_results(self, task_id):
        """Retrieve GVM results for a specific task"""
        # First, get the scan session information
        session_data = self.gvm_scan_sessions().find_one({'id': task_id})
        if not session_data:
            return None
            
        session_id = session_data['id']
        
        # Then get all vulnerabilities for this session
        vuln_rows = self.gvm_vulnerabilities().find({'session_id': session_id})
        
        # Format results to match the structure from get_results
        results = []
        for row in vuln_rows:
            results.append({
                'id': row['vuln_id'],
                'name': row['name'],
                'host': row['host'],
                'port': row['port'],
                'severity': row['severity'],
                'severity_value': row['severity_value'],
                'description': row['description'],
                'cvss_base': row['cvss_base'],
                'timestamp': row['timestamp']
            })
        
        # Create summary dictionary
        summary = {
            'Critical': session_data['critical_count'],
            'High': session_data['high_count'],
            'Medium': session_data['medium_count'],
            'Low': session_data['low_count']
        }
        
        # Return in the same format as get_results
        return {
            'results': results,
            'summary': summary,
            'total': session_data['total_vulnerabilities']
        }
    
    def get_user_by_username(self, username):
        """Get user data by username"""
        return self.users().find_one(username=username)
                
    def get_user_by_id(self, user_id):
        """Get user data by ID"""
        return self.users().find_one(id=user_id)

    def create_user(self, username, password, email=None, role='user'):
        """Create new user with hashed password"""
        password_hash = generate_password_hash(password)
        
        try:
            user_data = {
                'username': username,
                'password_hash': password_hash,
                'email': email,
                'role': role
            }
            user_id = self.users().insert(user_data)
            return {"success": True, "user_id": user_id}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def update_last_login(self, user_id):
        """Update user's last login timestamp"""
        data = {
            'last_login': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return self.users().update(user_id, data)
    
    def get_osint_data(self, start_date: Optional[str] = None, end_date: Optional[str] = None, 
                   threat_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Retrieve OSINT data from the database with optional filtering.
        
        Args:
            start_date: Optional start date filter (YYYY-MM-DD)
            end_date: Optional end date filter (YYYY-MM-DD)
            threat_types: Optional list of threat types to filter
            
        Returns:
            List of OSINT data entries matching the criteria
        """
        query = "SELECT * FROM osint_data WHERE 1=1"
        params = []
        
        # Add date filters if provided
        if start_date:
            query += " AND timestamp >= %s"
            params.append(start_date + " 00:00:00")
            
        if end_date:
            query += " AND timestamp <= %s"
            params.append(end_date + " 23:59:59")
            
        # Add threat types filter if provided
        if threat_types and len(threat_types) > 0:
            placeholders = ', '.join(['%s'] * len(threat_types))
            query += f" AND threat_type IN ({placeholders})"
            params.extend(threat_types)
            
        # Add order by timestamp
        query += " ORDER BY timestamp DESC"
        
        # Execute query and get results
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            results = cursor.fetchall()
            
        # Convert results to list of dictionaries
        osint_data = []
        for row in results:
            osint_data.append({
                'id': row[0],
                'source': row[1],
                'title': row[2],
                'description': row[3],
                'threat_type': row[4],
                'confidence': row[5],
                'url': row[6],
                'ioc_type': row[7],
                'ioc_value': row[8],
                'timestamp': row[9].isoformat() if row[9] else None,
                'tags': row[10].split(',') if row[10] else [],
                'metadata': row[11]
            })
        
        return osint_data

    def get_vulnerabilities(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve vulnerability data from the database with optional filtering.
        
        Args:
            start_date: Optional start date filter (YYYY-MM-DD)
            end_date: Optional end date filter (YYYY-MM-DD)
            
        Returns:
            List of vulnerability entries matching the criteria
        """
        query = """
            SELECT v.*, s.task_id 
            FROM gvm_vulnerabilities v
            JOIN gvm_scan_sessions s ON v.session_id = s.id
            WHERE 1=1
        """
        params = []
        
        # Add date filters if provided
        if start_date:
            query += " AND v.timestamp >= %s"
            params.append(start_date + " 00:00:00")
            
        if end_date:
            query += " AND v.timestamp <= %s"
            params.append(end_date + " 23:59:59")
            
        # Add order by severity value (descending) and timestamp
        query += " ORDER BY v.severity_value DESC, v.timestamp DESC"
        
        # Execute query and get results
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            results = cursor.fetchall()
            
        # Convert results to list of dictionaries
        vulnerabilities = []
        for row in results:
            vulnerabilities.append({
                'id': row[0],
                'session_id': row[1],
                'vuln_id': row[2],
                'name': row[3],
                'host': row[4],
                'port': row[5],
                'severity': row[6],
                'severity_value': row[7],
                'description': row[8],
                'cvss_base': row[9],
                'timestamp': row[10].isoformat() if row[10] else None,
                'task_id': row[11]
            })
        
        return vulnerabilities

    def get_network_traffic(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve network traffic data from the database with optional filtering.
        
        Args:
            start_date: Optional start date filter (YYYY-MM-DD)
            end_date: Optional end date filter (YYYY-MM-DD)
            
        Returns:
            List of network traffic entries matching the criteria
        """
        query = "SELECT * FROM nids_alerts WHERE 1=1"
        params = []
        
        # Add date filters if provided
        if start_date:
            query += " AND timestamp >= %s"
            params.append(start_date + " 00:00:00")
            
        if end_date:
            query += " AND timestamp <= %s"
            params.append(end_date + " 23:59:59")
            
        # Add order by timestamp
        query += " ORDER BY timestamp DESC"
        
        # Execute query and get results
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            results = cursor.fetchall()
            
        # Convert results to list of dictionaries
        network_traffic = []
        for row in results:
            network_traffic.append({
                'id': row[0],
                'source_ip': row[1],
                'destination_ip': row[2],
                'source_port': row[3],
                'destination_port': row[4],
                'protocol': row[5],
                'threat_type': row[6],
                'severity': row[7],
                'description': row[8],
                'timestamp': row[9].isoformat() if row[9] else None,
            })
        
        return network_traffic

    def get_threat_actors(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve threat actor data from the osint_data table with filtering.
        This implementation assumes threat actors are stored in the osint_data table
        with a specific tag or threat_type.
        
        Args:
            start_date: Optional start date filter (YYYY-MM-DD)
            end_date: Optional end date filter (YYYY-MM-DD)
            
        Returns:
            List of threat actor entries matching the criteria
        """
        # For this implementation, we'll extract threat actors from the osint_data table
        # Assuming threat actors have 'threat_actor' in their tags or a specific threat_type
        query = """
            SELECT * FROM osint_data 
            WHERE (tags LIKE %s OR metadata LIKE %s) 
        """
        params = ['%threat_actor%', '%threat_actor%']
        
        # Add date filters if provided
        if start_date:
            query += " AND timestamp >= %s"
            params.append(start_date + " 00:00:00")
            
        if end_date:
            query += " AND timestamp <= %s"
            params.append(end_date + " 23:59:59")
            
        # Add order by timestamp
        query += " ORDER BY timestamp DESC"
        
        # Execute query and get results
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            results = cursor.fetchall()
            
        # Convert results to list of dictionaries
        threat_actors = []
        for row in results:
            threat_actors.append({
                'id': row[0],
                'source': row[1],
                'name': row[2],  # Using title as the actor name
                'description': row[3],
                'threat_type': row[4],
                'confidence': row[5],
                'url': row[6],
                'timestamp': row[9].isoformat() if row[9] else None,
                'tags': row[10].split(',') if row[10] else [],
                'metadata': row[11]
            })
        
        return threat_actors

    def get_indicators_of_compromise(self, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve indicators of compromise (IOCs) from the osint_data table with filtering.
        
        Args:
            start_date: Optional start date filter (YYYY-MM-DD)
            end_date: Optional end date filter (YYYY-MM-DD)
            
        Returns:
            List of IOC entries matching the criteria
        """
        # For this implementation, we'll extract IOCs from the osint_data table
        # We'll look for entries that have an ioc_type and ioc_value
        query = "SELECT * FROM osint_data WHERE ioc_type IS NOT NULL AND ioc_type != ''"
        params = []
        
        # Add date filters if provided
        if start_date:
            query += " AND timestamp >= %s"
            params.append(start_date + " 00:00:00")
            
        if end_date:
            query += " AND timestamp <= %s"
            params.append(end_date + " 23:59:59")
            
        # Add order by timestamp
        query += " ORDER BY timestamp DESC"
        
        # Execute query and get results
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            results = cursor.fetchall()
            
        # Convert results to list of dictionaries
        iocs = []
        for row in results:
            iocs.append({
                'id': row[0],
                'source': row[1],
                'title': row[2],
                'description': row[3],
                'threat_type': row[4],
                'confidence': row[5],
                'url': row[6],
                'ioc_type': row[7],
                'ioc_value': row[8],
                'timestamp': row[9].isoformat() if row[9] else None,
                'tags': row[10].split(',') if row[10] else [],
                'metadata': row[11]
            })
        
        return iocs