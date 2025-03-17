-- Table for storing asset details
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    description TEXT,
    risk_level INTEGER CHECK (risk_level BETWEEN 1 AND 10)
);

-- Table for storing threats related to assets
CREATE TABLE threats (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL,
    name VARCHAR(255),
    risk_level INTEGER CHECK (risk_level BETWEEN 1 AND 10),
    FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
);

-- Table for storing vulnerabilities associated with assets
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER,
    name VARCHAR(255),
    description TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
);

-- Table for storing risk ratings, linking assets, threats, and vulnerabilities
CREATE TABLE risk_ratings (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER,
    threat_id INTEGER,
    vulnerability_id INTEGER,
    FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
    FOREIGN KEY (threat_id) REFERENCES threats (id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id) ON DELETE CASCADE
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
    FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
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
    FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

-- Create indexes for faster lookups
CREATE INDEX idx_employees_names ON employees(first_name, last_name);
CREATE INDEX idx_email_employee ON email_results(employee_id);
CREATE INDEX idx_account_employee ON account_findings(employee_id);
CREATE INDEX idx_account_username ON account_findings(username);
