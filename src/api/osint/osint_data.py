import sqlite3
import json
import pandas as pd

class OsintData:
    def __init__(self, db_path='osint.db'):
        """Initialize with database connection"""
        self.db_path = db_path
        self._ensure_tables_exist()
        
    def _get_connection(self):
        """Get a database connection with row factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _ensure_tables_exist(self):
        """Ensure all necessary database tables exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create employees table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                domain TEXT
            )
        """)
        
        # Create email_results table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER,
                email TEXT,
                score REAL,
                FOREIGN KEY (employee_id) REFERENCES employees (id)
            )
        """)
        
        # Create account_findings table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS account_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER,
                username TEXT,
                site_name TEXT,
                url TEXT,
                category TEXT,
                http_status INTEGER,
                found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees (id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def import_employees_from_csv(self, csv_file_path):
        """Import employees from a CSV file and return stats"""
        conn = self._get_connection()
        cursor = conn.cursor()
        count = 0
        
        try:
            employee_data = pd.read_csv(csv_file_path)
            for index, row in employee_data.iterrows():
                # Check if required fields exist
                if not ('first_name' in row and 'last_name' in row):
                    continue
                    
                # Get domain or use default
                domain = row.get('domain', '')
                
                # Insert employee into database
                cursor.execute("""
                    INSERT INTO employees (first_name, last_name, domain)
                    VALUES (?, ?, ?)
                """, (row['first_name'], row['last_name'], domain))
                count += 1
            
            conn.commit()
            return {"success": True, "imported_count": count}
        except Exception as e:
            conn.rollback()
            return {"success": False, "error": str(e)}
        finally:
            conn.close()
    
    def get_threat_data(self):
        """Get data for the threats page"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
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
        conn.close()
        return results
    
    def get_employee_details(self, employee_id):
        """Get detailed information for a specific employee"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
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
                e.id = ?
        """, (employee_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
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
                employee_id = ?
            ORDER BY
                category, site_name
        """, (employee_id,))
        
        employee['accounts'] = [dict(row) for row in cursor.fetchall()]
        conn.close()
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
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO employees (first_name, last_name, domain)
            VALUES (?, ?, ?)
        """, (first_name, last_name, domain))
        
        employee_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return employee_id
    
    def save_email_result(self, employee_id, email, score=None):
        """Save or update email result for an employee"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Check if email already exists for this employee
        cursor.execute("""
            SELECT id FROM email_results 
            WHERE employee_id = ?
        """, (employee_id,))
        
        result = cursor.fetchone()
        
        if result:
            # Update existing record
            cursor.execute("""
                UPDATE email_results
                SET email = ?, score = ?
                WHERE employee_id = ?
            """, (email, score, employee_id))
        else:
            # Insert new record
            cursor.execute("""
                INSERT INTO email_results (employee_id, email, score)
                VALUES (?, ?, ?)
            """, (employee_id, email, score))
        
        conn.commit()
        conn.close()
        
        return True
    
    def save_account_finding(self, employee_id, username, site_name, url, category=None, http_status=None):
        """Save a new account finding for an employee"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO account_findings 
            (employee_id, username, site_name, url, category, http_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (employee_id, username, site_name, url, category, http_status))
        
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return finding_id