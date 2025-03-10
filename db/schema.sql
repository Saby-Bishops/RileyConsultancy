CREATE TABLE assets
(
    id serial,
    name varchar(255) NOT NULL,
    category varchar(50),
    description text,
    risk_level integer,

    PRIMARY KEY (id),
    CHECK (risk_level BETWEEN 1 AND 10)
);

CREATE TABLE threats
(
    id serial,
    asset_id integer NOT NULL,
    name varchar(255),
    risk_level integer,

    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets (id)
    CHECK (risk_level BETWEEN 1 AND 10)
);

CREATE TABLE vulnerabilities
(
    id serial,
    asset_id integer,
    name varchar(255),
    description text,

    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES asset (id),
);

CREATE TABLE risk_ratings
(
    id serial,
    asset_id integer,
    threat_id integer,
    vulnerability_id integer,


    PRIMARY KEY id,
    FOREIGN KEY asset_id REFERENCES assets (id),
    FOREIGN KEY threat_id REFERENCES threats (id),
    FOREIGN KEY vulnerability_id REFERENCES vulnerability (id)
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
