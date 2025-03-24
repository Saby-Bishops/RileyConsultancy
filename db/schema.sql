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
