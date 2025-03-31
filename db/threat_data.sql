CREATE DATABASE IF NOT EXISTS osint_db;
USE osint_db;

CREATE TABLE IF NOT EXISTS threat_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    domain VARCHAR(255),
    threat_type ENUM('Malware', 'Phishing', 'DDoS', 'Ransomware', 'Other') NOT NULL,
    threat_level ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    source VARCHAR(255) NOT NULL,
    details TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
