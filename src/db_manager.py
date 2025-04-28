import json
import pandas as pd
import datetime
from werkzeug.security import generate_password_hash
import mysql.connector
from contextlib import contextmanager

class DBManager:
    def __init__(self, conn_settings):
        """Initialize with database connection"""
        self.conn_settings = conn_settings
        self._ensure_tables_exist()
    
    @contextmanager
    def get_cursor(self):
        conn = mysql.connector.connect(**self.conn_settings)
        try:
            cursor = conn.cursor(dictionary=True)
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()
    
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
    
    def import_employees_from_csv(self, csv_file_path):
        """Import employees from a CSV file and return stats"""
        with self.get_cursor() as cursor:
            table_name = 'employees'
            columns = '(first_name, last_name, domain)'
            
            try:
                employee_data = pd.read_csv(csv_file_path)
                for index, row in employee_data.iterrows():
                    # Check if required fields exist
                    if not ('first_name' in row and 'last_name' in row):
                        continue
                        
                    # Get domain or use default
                    domain = row.get('domain', '')
                    self.insert_to_database(table_name, columns, (row['first_name'], row['last_name'], domain))
                    count += 1
                
                return {"success": True, "imported_count": count}
            except Exception as e:
                return {"success": False, "error": str(e)}
    
    def get_threat_data(self):
        """Get data for the threats page"""
        with self.get_cursor() as cursor:
            
            cursor.execute("""
                SELECT
                    e.id as employee_id,
                    e.first_name,
                    e.last_name,
                    er.email,
                    (er.email IS NOT NULL) as email_found,
                    COUNT(DISTINCT af.id) as account_count,
                    COUNT(DISTINCT af.site_name) as unique_sites,
                    GROUP_CONCAT(DISTINCT af.site_name) as sites
                FROM
                    employees e
                LEFT JOIN
                    email_results er ON e.id = er.employee_id
                LEFT JOIN
                    account_findings af ON e.id = af.employee_id
                GROUP BY
                    e.id
                ORDER BY
                    account_count DESC, email_found DESC
            """)
            
            results = [dict(row) for row in cursor.fetchall()]
        
        return results
    
    def get_employee_details(self, employee_id):
        """Get detailed information for a specific employee"""
        with self.get_cursor() as cursor:
            # Get employee info
            cursor.execute("""
                SELECT
                    e.id,
                    e.first_name,
                    e.last_name,
                    e.domain,
                    er.email,
                    er.score as email_score
                FROM
                    employees e
                LEFT JOIN
                    email_results er ON e.id = er.employee_id
                WHERE
                    e.id = %s
            """, (employee_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            employee = dict(row)
            
            # Get account findings
            cursor.execute("""
                SELECT
                    username,
                    site_name,
                    url,
                    category,
                    http_status,
                    found_at
                FROM
                    account_findings
                WHERE
                    employee_id = %s
                ORDER BY
                    category, site_name
            """, (employee_id,))
            
            employee['accounts'] = [dict(row) for row in cursor.fetchall()]
        return employee
    
    def export_threats_json(self, export_path=None):
        """Export threat data as JSON"""
        data = self.get_threat_data()
        
        if export_path is None:
            export_path = 'threats_export.json'
            
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            
        return export_path
    
    def add_employee(self, first_name, last_name, domain=None):
        """Add a new employee to the database"""
        with self.get_cursor() as cursor:
            table_name = 'employees'
            columns = '(first_name, last_name, domain)'
            data = (first_name, last_name, domain)
            
            employee_id = self.insert_to_database(table_name, columns, data)
        return employee_id
    
    def save_email_result(self, employee_id, email, score=None):
        """Save or update email result for an employee"""
        with self.get_cursor() as cursor:
            table_name = 'email_results'
            
            # Check if email already exists for this employee
            cursor.execute(f"""
                SELECT id FROM {table_name} 
                WHERE employee_id = %s
            """, (employee_id,))
            
            result = cursor.fetchone()
            
            if result:
                # Update existing record
                cursor.execute(f"""
                    UPDATE {table_name}
                    SET email = %s, score = %s
                    WHERE employee_id = %s
                """, (email, score, employee_id))
            else:
                # Insert new record
                columns = '(employee_id, email, score)'
                data = (employee_id, email, score)
                self.insert_to_database(table_name, columns, data)
            
        return True
    
    def save_account_finding(self, employee_id, username, site_name, url, category=None, http_status=None):
        """Save a new account finding for an employee"""
        with self.get_cursor() as cursor:
            table_name = 'account_findings'
            columns = '(employee_id, username, site_name, url, category, http_status)'
            data = (employee_id, username, site_name, url, category, http_status)
            finding_id = self.insert_to_database(table_name, columns, data)
        
        return finding_id
    
    def save_gvm_results(self, task_id, gvm_results):
        """Save GVM results for an employee"""
        with self.get_cursor() as cursor:
            table_name = 'gvm_scan_sessions'
            columns = '(task_id, timestamp, total_vulnerabilities, critical_count, high_count, medium_count, low_count)'
            data = (task_id, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), gvm_results.get('total', 0),
                                                                        gvm_results.get('summary', {}).get('Critical', 0),
                                                                        gvm_results.get('summary', {}).get('High', 0),
                                                                        gvm_results.get('summary', {}).get('Medium', 0),
                                                                        gvm_results.get('summary', {}).get('Low', 0))
            
            session_id = self.insert_to_database(table_name, columns, data)
            
            # Insert each vulnerability
            for vuln in gvm_results.get('results', []):
                table_name = 'gvm_vulnerabilities'
                columns = '(session_id, vuln_id, name, host, port, severity, severity_value, description, cvss_base, timestamp)'
                data = (session_id,
                        vuln.get('id', ''),
                        vuln.get('name', 'Unknown'),
                        vuln.get('host', 'Unknown'),
                        vuln.get('port', 'Unknown'),
                        vuln.get('severity', 'Low'),
                        vuln.get('severity_value', 0.0),
                        vuln.get('description', 'No description available'),
                        vuln.get('cvss_base', 'N/A'),
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
                self.insert_to_database(table_name, columns, data)
            
        return True
    
    def save_alert(self, alert_data):
        """Save an alert to the database"""
        with self.get_cursor() as cursor:
            table_name = 'nids_alerts'
            columns = '(source_ip, destination_ip, source_port, destination_port, protocol, threat_type, severity, description, timestamp)'
            data = (
                alert_data.get('source_ip'),
                alert_data.get('destination_ip'),
                alert_data.get('source_port'),
                alert_data.get('destination_port'),
                alert_data.get('protocol'),
                alert_data.get('threat_type'),
                alert_data.get('severity'),
                alert_data.get('description'),
                alert_data.get('timestamp', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            
            self.insert_to_database(table_name, columns, data)
        
        return True
    
    def save_phishing_data(self, urls, timestamp):
        """Save phishing data to the database"""
        with self.get_cursor() as cursor:
            table_name = 'phishing_urls'
            columns = '(url, timestamp)'
            
            for url in urls:
                data = (url, timestamp)
                self.insert_to_database(table_name, columns, data)
        
        return True
    
    def insert_to_database(self, table_name, columns, data):
        """Insert data into the specified table"""
        with self.get_cursor() as cursor:
            # Create placeholders string with %s for MySQL
            placeholders = ', '.join(['%s' for _ in data])
            
            cursor.execute(f"""
                INSERT INTO {table_name} {columns}
                VALUES ({placeholders})
            """, data)
            
            last_id = cursor.lastrowid
            return last_id

    def show_phishing_urls(self):
        """Fetch and display phishing URLs from the database"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT * FROM phishing_urls")
            rows = cursor.fetchall()
            
            # Convert to list of dictionaries
            phishing_urls = [dict(row) for row in rows]
        
        return phishing_urls
    
    def get_gvm_results(self, task_id):
        """Retrieve GVM results for a specific task"""
        with self.get_cursor() as cursor:
            
            # First, get the scan session information
            cursor.execute('''
            SELECT id, timestamp, total_vulnerabilities, 
                critical_count, high_count, medium_count, low_count
            FROM gvm_scan_sessions
            WHERE id = %s
            ''', (task_id,))
            
            session_data = cursor.fetchone()
            if not session_data:
                return None
                
            session_id = session_data['id']
            timestamp = session_data['timestamp']
            total = session_data['total_vulnerabilities']
            critical = session_data['critical_count']
            high = session_data['high_count']
            medium = session_data['medium_count']
            low = session_data['low_count']
            
            # Then get all vulnerabilities for this session
            cursor.execute('''
            SELECT vuln_id, name, host, port, severity, 
                severity_value, description, cvss_base, timestamp
            FROM gvm_vulnerabilities
            WHERE session_id = %s
            ''', (session_id,))
            
            vuln_rows = cursor.fetchall()
            
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
                'Critical': critical,
                'High': high,
                'Medium': medium,
                'Low': low
            }
            
            # Return in the same format as get_results
            return {
                'results': results,
                'summary': summary,
                'total': total
            }
        
    def get_user_by_username(self, username):
        """Get user data by username"""
        with self.get_cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            return user
            
    def get_user_by_id(self, user_id):
        """Get user data by ID"""
        with self.get_cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            return user

    def create_user(self, username, password, email=None, role='user'):
        """Create new user with hashed password"""
        password_hash = generate_password_hash(password)
        
        with self.get_cursor() as cursor:
            try:
                cursor.execute(
                    'INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s)',
                    (username, password_hash, email, role)
                )
                return {"success": True, "user_id": cursor.lastrowid}
            except Exception as e:
                return {"success": False, "error": str(e)}

    def update_last_login(self, user_id):
        """Update user's last login timestamp"""
        with self.get_cursor() as cursor:
            cursor.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s',
                (user_id,)
            )