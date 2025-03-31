CREATE TABLE assets (
    id INT AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    description TEXT,
    risk_level INT,
    PRIMARY KEY (id)
    -- Optional CHECK: risk_level BETWEEN 1 AND 10 (not enforced by MariaDB unless specified)
);

CREATE TABLE threats (
    id INT AUTO_INCREMENT,
    asset_id INT NOT NULL,
    name VARCHAR(255),
    risk_level INT,
    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
    -- Optional CHECK: risk_level BETWEEN 1 AND 10
);

CREATE TABLE vulnerabilities (
    id INT AUTO_INCREMENT,
    asset_id INT,
    name VARCHAR(255),
    description TEXT,
    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE risk_ratings (
    id INT AUTO_INCREMENT,
    asset_id INT,
    threat_id INT,
    vulnerability_id INT,
    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (threat_id) REFERENCES threats(id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);

-- Table for storing employee information
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    domain TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for storing email search results
CREATE TABLE email_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    email TEXT,
    score REAL,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id) REFERENCES employees(id)
);

-- Table for storing social media and other account findings
CREATE TABLE account_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    site_name TEXT NOT NULL,
    url TEXT NOT NULL,
    category TEXT NOT NULL,
    http_status INTEGER,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id) REFERENCES employees(id)
);

-- Create indexes for faster lookups
CREATE INDEX idx_employees_names ON employees(first_name, last_name);
CREATE INDEX idx_email_employee ON email_results(employee_id);
CREATE INDEX idx_account_employee ON account_findings(employee_id);
CREATE INDEX idx_account_username ON account_findings(username);
