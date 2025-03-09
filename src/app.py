# app.py
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
import datetime
import random
import os
from api.gvm_integration import GVMScanner
import threading
import json
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For flash messages

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Get a logger for this module

# Store scan results
scan_results = {
    'last_scan': None,
    'results': [],
    'summary': {
        'Critical': 0,
        'High': 0, 
        'Medium': 0,
        'Low': 0
    },
    'total': 0,
    'status': 'None',
    'target': 'None'
}

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

# Run scan in background thread
def run_scan_thread(username, password, target_name, target_hosts):
    global scan_results
    
    # Update status
    scan_results['status'] = 'Running'
    scan_results['target'] = target_hosts
    
    # Initialize scanner
    scanner = GVMScanner()
    
    # Run scan
    try:
        results = scanner.run_scan(username, password, target_name, target_hosts)
        
        if 'error' in results:
            scan_results['status'] = f"Error: {results['error']}"
            return
            
        # Update global results
        scan_results['results'] = results['results']
        scan_results['summary'] = results['summary']
        scan_results['total'] = results['total']
        scan_results['last_scan'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_results['status'] = 'Completed'
    except Exception as e:
        scan_results['status'] = f"Error: {str(e)}"

# Routes
@app.route('/')
def index():
    user_actions = [{'url': '/refresh', 'icon': 'fa-search', 'text': 'Refresh', 'class': 'refresh-btn'}]
    return render_template('dashboard.html', user_actions=user_actions)

@app.route('/vulnerabilities')
def vulnerabilities():
    user_actions = [
        {'url': '/scan', 'icon': 'fa-search', 'text': 'New Scan', 'class': 'scan-btn'},
        {'url': '/rescan', 'icon': 'fa-sync-alt', 'text': 'Rescan', 'class': 'rescan-btn', 'method': 'post'}
    ]
    return render_template('vulnerabilities.html', user_actions=user_actions)

@app.route('/api/threats')
def get_threats():
    return jsonify(generate_sample_threats())

@app.route('/api/stats')
def get_stats():
    # Combine regular threat stats with vulnerability stats
    stats = {
        "total_threats": random.randint(150, 300),
        "critical": random.randint(5, 20),
        "high": random.randint(20, 50),
        "medium": random.randint(50, 100),
        "low": random.randint(80, 150),
        "blocked": random.randint(120, 250),
        "investigating": random.randint(10, 30),
        "vulnerabilities": {
            "total": scan_results['total'],
            "critical": scan_results['summary'].get('Critical', 0),
            "high": scan_results['summary'].get('High', 0),
            "medium": scan_results['summary'].get('Medium', 0),
            "low": scan_results['summary'].get('Low', 0),
            "last_scan": scan_results['last_scan'],
            "status": scan_results['status']
        }
    }
    return jsonify(stats)

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

# New routes for vulnerability scanning
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    global scan_results
    return jsonify(scan_results)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        # Handle form submission to start scan
        username = request.form.get('username')
        password = request.form.get('password')
        target_name = request.form.get('target_name')
        target_hosts = request.form.get('target_hosts')
        scan_config_id = request.form.get('scan_config_id')
        scanner_id = request.form.get('scanner_id')
        existing_target_id = request.form.get('existing_target_id')
        
        # Create scanner instance
        scanner = GVMScanner()
        
        # Start the scan
        result = scanner.run_scan(
            username, 
            password, 
            target_name, 
            target_hosts, 
            scan_config_id, 
            scanner_id,
            existing_target_id
        )
        
        if 'error' in result:
            flash(result['error'], 'error')
            return redirect(url_for('scan'))
        
        # Store task_id in session to check status later
        session['task_id'] = result['task_id']
        
        flash('Scan started successfully!', 'success')
        return redirect(url_for('scan_status'))
    
    else:
        # GET request - show form
        # If credentials are in session, fetch available options
        if 'gvm_username' in session and 'gvm_password' in session:
            scanner = GVMScanner()
            options = scanner.get_scan_options(session['gvm_username'], session['gvm_password'])
            
            if 'error' in options:
                flash('Could not load scan options. Please check your credentials.', 'error')
                scan_options = None
            else:
                scan_options = options
        else:
            scan_options = None
            
        return render_template('scan_form.html', scan_options=scan_options)
    
@app.route('/rescan', methods=['GET', 'POST'])
def rescan():
    if 'task_id' not in session:
        flash('No scan in progress', 'error')
        return redirect(url_for('scan'))
    
    scanner = GVMScanner()
    task_id = session['task_id']
    target_name = scan_results['target']
    target_hosts = scan_results['target']

    scanner.start_scan(task_id, target_name, target_hosts)
    flash('Rescan started successfully!', 'success')
    return redirect(url_for('get_scan_status'))


@app.route('/get_scan_options', methods=['POST'])
def get_scan_options():
    """AJAX endpoint to get scan options after user enters credentials"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'})
    
    # Store credentials in session for convenience
    session['gvm_username'] = username
    session['gvm_password'] = password
    
    scanner = GVMScanner()
    options = scanner.get_scan_options(username, password)
    
    return jsonify(options)

@app.route('/scan_status')
def get_scan_status():
    if 'task_id' not in session:
        flash('No scan in progress', 'error')
        return redirect(url_for('scan'))
        
    scanner = GVMScanner()
    status = scanner.get_scan_status(task_id=session['task_id'], username=session['gvm_username'], password=session['gvm_password'])
    
    if status['status'] == 'Done':
        flash('Scan completed successfully!', 'success')
        return redirect(url_for('get_scan_results'))
    
    return render_template('scan_status.html', status=status)

@app.route('/scan_results')
def get_scan_results():
    if 'task_id' not in session:
        flash('No scan results available', 'error')
        return redirect(url_for('scan'))
    
    scanner = GVMScanner()
    results = scanner.get_results(username=session['gvm_username'], password=session['gvm_password'])

    return render_template('scan_results.html', results=results)


@app.route('/test')
def test():
    return render_template('test.html')

if __name__ == '__main__':
    app.run(debug=True)