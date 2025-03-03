from flask import Flask, render_template, jsonify
import datetime
import random
import os

app = Flask(__name__)

# Sample threat intelligence data - would be replaced with real data sources
def generate_sample_threats():
    threat_types = ["Malware", "Phishing", "DDoS", "Zero-day", "Ransomware", "APT"]
    severity_levels = ["Critical", "High", "Medium", "Low"]
    countries = ["United States", "China", "Russia", "North Korea", "Iran", "Unknown"]
    
    threats = []
    for i in range(10):
        timestamp = datetime.datetime.now() - datetime.timedelta(minutes=random.randint(5, 120))
        threats.append({
            "id": f"THREAT-{random.randint(1000, 9999)}",
            "type": random.choice(threat_types),
            "severity": random.choice(severity_levels),
            "source": random.choice(countries),
            "target": random.choice(countries),
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "details": f"Detected suspicious activity matching known {random.choice(threat_types).lower()} patterns"
        })
    
    return sorted(threats, key=lambda x: x["timestamp"], reverse=True)

# Routes
@app.route('/')
def index():
    return render_template('index.html')


# Continue the app.py file from where it was cut off
@app.route('/api/threats')
def get_threats():
    return jsonify(generate_sample_threats())

@app.route('/api/stats')
def get_stats():
    return jsonify({
        "total_threats": random.randint(150, 300),
        "critical": random.randint(5, 20),
        "high": random.randint(20, 50),
        "medium": random.randint(50, 100),
        "low": random.randint(80, 150),
        "blocked": random.randint(120, 250),
        "investigating": random.randint(10, 30)
    })

@app.route('/api/trends')
def get_trends():
    # Generate some random trend data for the past 7 days
    days = [(datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    
    return jsonify({
        "days": days,
        "malware": [random.randint(10, 50) for _ in range(7)],
        "phishing": [random.randint(20, 70) for _ in range(7)],
        "ddos": [random.randint(5, 30) for _ in range(7)],
        "ransomware": [random.randint(2, 15) for _ in range(7)]
    })

if __name__ == '__main__':
    # Create required directories if they don't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    if not os.path.exists('static'):
        os.makedirs('static')
    if not os.path.exists('static/css'):
        os.makedirs('static/css')
    if not os.path.exists('static/js'):
        os.makedirs('static/js')
    
    app.run(debug=True)