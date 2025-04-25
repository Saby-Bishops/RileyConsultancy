import mysql.connector
import json
import pandas as pd
import datetime


class DBManager:
    def __init__(self):
        """Initialize with database connection"""
        self.conn_settings = {
            "host": "infosec-db.tail79918a.ts.net",
            "port": 3306,
            "user": "appuser",
            "password": "apppass",
            "database": "infosec",
        }
        self._ensure_tables_exist()

    def _get_connection(self):
        """Get a database connection with row factory"""
        conn = mysql.connector.connect(**self.conn_settings)
        return conn

    def _ensure_tables_exist(self):
        """Ensure all necessary database tables exist"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    domain TEXT
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS email_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER,
                    email TEXT,
                    score REAL,
                    FOREIGN KEY (employee_id) REFERENCES employees (id)
                )
            """
            )

            cursor.execute(
                """
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
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS phishing_urls (
                    id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL,
                    collection_date TEXT NOT NULL
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS gvm_scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_vulnerabilities INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS gvm_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    vuln_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    severity_value REAL NOT NULL,
                    description TEXT,
                    cvss_base TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES gvm_scan_sessions(id)
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS nids_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol INTEGER,
                    threat_type TEXT,
                    severity TEXT,
                    description TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def import_employees_from_csv(self, csv_file_path):
        """Import employees from a CSV file and return stats"""
        with self._get_connection() as conn:
            count = 0
            table_name = "employees"
            columns = "(first_name, last_name, domain)"

            try:
                employee_data = pd.read_csv(csv_file_path)
                for index, row in employee_data.iterrows():
                    # Check if required fields exist
                    if not ("first_name" in row and "last_name" in row):
                        continue

                    # Get domain or use default
                    domain = row.get("domain", "")
                    self.insert_to_database(
                        table_name,
                        columns,
                        (row["first_name"], row["last_name"], domain),
                    )
                    count += 1

                return {"success": True, "imported_count": count}
            except Exception as e:
                conn.rollback()
                return {"success": False, "error": str(e)}

    def get_threat_data(self):
        """Get data for the threats page"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
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
            """
            )

            results = [dict(row) for row in cursor.fetchall()]

        return results

    def get_employee_details(self, employee_id):
        """Get detailed information for a specific employee"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            # Get employee info
            cursor.execute(
                """
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
            """,
                (employee_id,),
            )

            row = cursor.fetchone()
            if not row:
                conn.close()
                return None

            employee = dict(row)

            # Get account findings
            cursor.execute(
                """
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
            """,
                (employee_id,),
            )

            employee["accounts"] = [dict(row) for row in cursor.fetchall()]
        return employee

    def export_threats_json(self, export_path=None):
        """Export threat data as JSON"""
        data = self.get_threat_data()

        if export_path is None:
            export_path = "threats_export.json"

        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return export_path

    def add_employee(self, first_name, last_name, domain=None):
        """Add a new employee to the database"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            table_name = "employees"
            columns = "(first_name, last_name, domain)"
            data = (first_name, last_name, domain)

            self.insert_to_database(table_name, columns, data)
            employee_id = cursor.lastrowid

        return employee_id

    def save_email_result(self, employee_id, email, score=None):
        """Save or update email result for an employee"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            table_name = "email_results"
            data = (employee_id, email, score)
            columns = "(employee_id, email, score)"

            # Check if email already exists for this employee
            cursor.execute(
                f"""
                SELECT id FROM {table_name} 
                WHERE employee_id = ?
            """,
                (employee_id,),
            )

            result = cursor.fetchone()

            if result:
                # Update existing record
                cursor.execute(
                    f"""
                    UPDATE {table_name}
                    SET email = ?, score = ?
                    WHERE employee_id = ?
                """,
                    data,
                )
            else:
                self.insert_to_database(table_name, columns, data)

        return True

    def save_account_finding(
        self, employee_id, username, site_name, url, category=None, http_status=None
    ):
        """Save a new account finding for an employee"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            table_name = "account_findings"
            columns = "(employee_id, username, site_name, url, category, http_status)"
            data = (employee_id, username, site_name, url, category, http_status)
            self.insert_to_database(table_name, columns, data)
            finding_id = cursor.lastrowid

        return finding_id

    def save_gvm_results(self, task_id, gvm_results):
        """Save GVM results for an employee"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            table_name = "gvm_scan_sessions"
            columns = "(task_id, timestamp, total_vulnerabilities, critical_count, high_count, medium_count, low_count)"
            data = (
                task_id,
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                gvm_results.get("total", 0),
                gvm_results.get("summary", {}).get("Critical", 0),
                gvm_results.get("summary", {}).get("High", 0),
                gvm_results.get("summary", {}).get("Medium", 0),
                gvm_results.get("summary", {}).get("Low", 0),
            )

            session_id = self.insert_to_database(table_name, columns, data)

            # Insert each vulnerability
            for vuln in gvm_results.get("results", []):
                table_name = "gvm_vulnerabilities"
                columns = "(session_id, vuln_id, name, host, port, severity, severity_value, description, cvss_base, timestamp)"
                data = (
                    session_id,
                    vuln.get("id", ""),
                    vuln.get("name", "Unknown"),
                    vuln.get("host", "Unknown"),
                    vuln.get("port", "Unknown"),
                    vuln.get("severity", "Low"),
                    vuln.get("severity_value", 0.0),
                    vuln.get("description", "No description available"),
                    vuln.get("cvss_base", "N/A"),
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )

                self.insert_to_database(table_name, columns, data)

        return True

    def save_alert(self, alert_data):
        """Save an alert to the database"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            table_name = "nids_alerts"
            columns = "(source_ip, destination_ip, source_port, destination_port, protocol, threat_type, severity, description, timestamp)"
            data = (
                alert_data.get("source_ip"),
                alert_data.get("destination_ip"),
                alert_data.get("source_port"),
                alert_data.get("destination_port"),
                alert_data.get("protocol"),
                alert_data.get("threat_type"),
                alert_data.get("severity"),
                alert_data.get("description"),
                alert_data.get(
                    "timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ),
            )

            self.insert_to_database(table_name, columns, data)

        return True

    def insert_to_database(self, table_name, columns, data):
        """Insert data into the specified table"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                f"""
                INSERT INTO {table_name} {columns}
                VALUES ({', '.join(['?' for _ in data])})
            """,
                data,
            )

            return cursor.lastrowid

    def show_phishing_urls(self):
        """Fetch and display phishing URLs from the database"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM phishing_urls")
            rows = cursor.fetchall()

            # Convert to list of dictionaries
            phishing_urls = [dict(row) for row in rows]

        return phishing_urls

    def get_gvm_results(self, task_id):
        """Retrieve GVM results for a specific task"""
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            # First, get the scan session information
            cursor.execute(
                """
            SELECT id, timestamp, total_vulnerabilities, 
                critical_count, high_count, medium_count, low_count
            FROM gvm_scan_sessions
            WHERE id = ?
            """,
                (task_id,),
            )

            session_data = cursor.fetchone()
            if not session_data:
                return None

            session_id, timestamp, total, critical, high, medium, low = session_data

            # Then get all vulnerabilities for this session
            cursor.execute(
                """
            SELECT vuln_id, name, host, port, severity, 
                severity_value, description, cvss_base, timestamp
            FROM gvm_vulnerabilities
            WHERE session_id = ?
            """,
                (session_id,),
            )

            vuln_rows = cursor.fetchall()

            # Format results to match the structure from get_results
            results = []
            for row in vuln_rows:
                (
                    vuln_id,
                    name,
                    host,
                    port,
                    severity,
                    severity_value,
                    description,
                    cvss_base,
                    timestamp,
                ) = row
                results.append(
                    {
                        "id": vuln_id,
                        "name": name,
                        "host": host,
                        "port": port,
                        "severity": severity,
                        "severity_value": severity_value,
                        "description": description,
                        "cvss_base": cvss_base,
                        "timestamp": timestamp,
                    }
                )

            # Create summary dictionary
            summary = {"Critical": critical, "High": high, "Medium": medium, "Low": low}

            # Return in the same format as get_results
            return {"results": results, "summary": summary, "total": total}
