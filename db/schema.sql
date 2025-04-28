-- -- Drop existing tables if needed
-- DROP TABLE IF EXISTS risk_ratings;
-- DROP TABLE IF EXISTS vulnerabilities;
-- DROP TABLE IF EXISTS threats;
-- DROP TABLE IF EXISTS assets;

-- Create ASSETS table
CREATE TABLE assets (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    description TEXT,
    risk_level INT CHECK (risk_level BETWEEN 1 AND 10)
);

-- Create THREATS table
CREATE TABLE threats (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    threat_name VARCHAR(255) UNIQUE,
    vulnerability_description TEXT,
    likelihood INT,
    impact INT,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

-- Create VULNERABILITIES table
CREATE TABLE vulnerabilities (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    asset_id INT,
    name VARCHAR(255),
    description TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

-- Create RISK_RATINGS table
CREATE TABLE risk_ratings (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    asset_id INT,
    threat_id INT,
    vulnerability_id INT,
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (threat_id) REFERENCES threats(id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    domain TEXT
);

CREATE TABLE email_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER,
    email TEXT,
    score REAL,
    FOREIGN KEY (employee_id) REFERENCES employees (id)
);

CREATE TABLE account_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER,
    username TEXT,
    site_name TEXT,
    url TEXT,
    category TEXT,
    http_status INTEGER,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id) REFERENCES employees (id)
);

CREATE TABLE phishing_urls (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    collection_date TEXT NOT NULL
);

CREATE TABLE gvm_scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    total_vulnerabilities INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL,
    medium_count INTEGER NOT NULL,
    low_count INTEGER NOT NULL
);

CREATE TABLE gvm_vulnerabilities (
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
);

CREATE TABLE nids_alerts (
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
);