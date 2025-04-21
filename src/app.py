# app.py
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, send_file, Response
import json
import datetime
import random
import os
import logging
from werkzeug.utils import secure_filename
import threading

from api.osint.email_search import EmailSearch
from api.osint.username_search import UsernameSearch
from api.osint.open_phish import fetch_phishing_urls, extract_domains

from api.recon.gvm_scanner import GVMScanner

from api.realtime.nids import IntrusionDetectionSystem

from db_manager import DBManager

print("Content-type: text/html\n")
print("Hello, Python is working with XAMPP!")

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
app.secret_key = os.urandom(24)  # For flash messages
db_path = os.path.join(os.path.dirname(__file__), os.pardir, 'db', 'shopsmart.db')
data_access = DBManager(db_path)
data_access._ensure_tables_exist()

scanner = GVMScanner()
nids = IntrusionDetectionSystem()
nids.db_manager = data_access  # Set the DBManager instance for NIDS

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Get a logger for this module

# Run scan in background thread
def run_scan_thread(username, password, target_name, target_hosts):
    scan_results = {
        'status': 'Pending',
        'target': target_hosts,
        'results': None,
        'summary': None,
        'total': 0,
        'last_scan': None
    }
    
    # Update status
    scan_results['status'] = 'Running'
    scan_results['target'] = target_hosts
    
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
        scanner.results.append(scan_results)
    except Exception as e:
        scan_results['status'] = f"Error: {str(e)}"

# Start NIDS in a background thread
def start_nids_thread():
    logger.info("Starting Network Intrusion Detection System in background thread...")
    try:
        alert = nids.start()
        if alert:
            data_access.save_alert(alert)
    except Exception as e:
        logger.error(f"Error starting NIDS: {str(e)}")

@app.route('/')
def index():
    user_actions = [{'url': '/refresh', 'icon': 'fa-search', 'text': 'Refresh', 'class': 'refresh-btn'}]
    return render_template('dashboard.html', user_actions=user_actions)

@app.route('/api/threats')
def get_threats():
    """Fetch cleaned threat data from db"""
    try:
        with data_access._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT ip_address, domain, threat_type, threat_level, source, detected_at FROM threat_data ORDER BY detected_at DESC")
            threats = cursor.fetchall()

        return jsonify(threats)  # Return only useful fields
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/employee/<int:employee_id>')
def get_employee(employee_id):
    """API endpoint to get employee details"""
    employee = data_access.get_employee_details(employee_id)
    return jsonify(employee)

@app.route('/api/export/threats')
def export_threats():
    """Export threats data as JSON"""
    filename = data_access.export_threats_json()
    return send_file(filename, as_attachment=True)

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Fetch vulnerabilities data"""
    if len(scanner.results) == 0:
        # No scan results available
        return jsonify({"error": "No scan results available"})
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
            "total":scanner.results[-1]['total'],
            "critical": scanner.results[-1]['summary'].get('Critical', 0),
            "high": scanner.results[-1]['summary'].get('High', 0),
            "medium": scanner.results[-1]['summary'].get('Medium', 0),
            "low": scanner.results[-1]['summary'].get('Low', 0),
            "last_scan": scanner.results[-1]['last_scan'],
            "status": scanner.results[-1]['status']
        }
    }
    return jsonify(stats)

@app.route('/vulnerabilities')
def vulnerabilities():
    # Check if GVM credentials are already in session
    if 'gvm_username' not in session or 'gvm_password' not in session:
        # No credentials, redirect to GVM login page with a return URL
        return redirect(url_for('gvm_login', next=url_for('vulnerabilities')))
    
    user_actions = [
        {'url': '/scan', 'icon': 'fa-search', 'text': 'New Scan', 'class': 'scan-btn'},
        {'url': '/rescan', 'icon': 'fa-sync-alt', 'text': 'Rescan', 'class': 'rescan-btn', 'method': 'post'}
    ]
    return render_template('vulnerabilities.html', user_actions=user_actions)

@app.route('/gvm_login', methods=['GET', 'POST'])
def gvm_login():
    next_url = request.args.get('next', url_for('vulnerabilities'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('gvm_login.html', next=next_url)
        
        # Verify credentials with GVM
        result = scanner.test_connection(username, password)
        
        if 'error' in result:
            flash(result['error'], 'error')
            return render_template('gvm_login.html', next=next_url)
        
        # Store credentials in session
        session['gvm_username'] = username
        session['gvm_password'] = password
        
        # Redirect to the originally requested page
        return redirect(next_url)
    
    # GET request - show login form
    return render_template('gvm_login.html', next=next_url)

@app.route('/threats')
def threats():
    user_actions = [
        {'url': '/api/export/threats', 'icon': 'fa-download', 'text': 'Export', 'class': 'export-btn'},
        {'url': '/import', 'icon': 'fa-upload', 'text': 'Import', 'class': 'import-btn'}
    ]
    return render_template('threats.html', user_actions=user_actions)

def allowed_file(filename):
    """Check if the uploaded file is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/import', methods=['GET', 'POST'])
def import_employees():
    """Import employees from CSV file"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        # Check if file is allowed
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Import employees from CSV
            result = data_access.import_employees_from_csv(file_path)
            
            if result["success"]:
                flash(f'Successfully imported {result["imported_count"]} employees!')
            else:
                flash(f'Error importing employees: {result["error"]}')
                
            return redirect(url_for('threats'))
        
    return render_template('import_csv.html')

@app.route('/api/stats')
def get_stats():
    
    if len(scanner.results) == 0:
        # No scan results available
        return jsonify({"error": "No scan results available"})
    
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
            "total":scanner.results[-1]['total'],
            "critical": scanner.results[-1]['summary'].get('Critical', 0),
            "high": scanner.results[-1]['summary'].get('High', 0),
            "medium": scanner.results[-1]['summary'].get('Medium', 0),
            "low": scanner.results[-1]['summary'].get('Low', 0),
            "last_scan": scanner.results[-1]['last_scan'],
            "status": scanner.results[-1]['status']
        }
    }
    return jsonify(stats)

@app.route('/api/trends')
def get_trends():
    """Fetch trends data for the past 7 days"""
    with data_access._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM phishing_urls WHERE collection_date >= DATE('now', '-7 days')")
        result = cursor.fetchone()
        logger.debug(f"Phishing URLs count in the last 7 days: {result['count'] if result else 0}")

        # If no phishing URLs in the last 7 days, try to fetch from OpenPhish
        if result['count'] == 0:
            urls, timestamps = fetch_phishing_urls()
            logger.debug(f"Fetched {len(urls)} URLs from OpenPhish")
            if urls:
                # Insert URLs into the database
                for url in urls:
                    data_access.insert_to_database('phishing_urls', '(url, collection_date)', (url, timestamps))
            else:
                return jsonify({"error": "Failed to fetch phishing URLs"})
            
        ph = result['count'] if result else 0

    # Generate some random trend data for the past 7 days
    days = [(datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    
    return jsonify({
        "days": days,
        "malware": [random.randint(10, 50) for _ in range(7)],
        "phishing": [ph],
        "ddos": [random.randint(5, 30) for _ in range(7)],
        "ransomware": [random.randint(2, 15) for _ in range(7)]
    })

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    # Make sure user is authenticated with GVM
    if 'gvm_username' not in session or 'gvm_password' not in session:
        return redirect(url_for('gvm_login', next=url_for('scan')))
    
    if request.method == 'POST':
        # Use stored credentials
        username = session['gvm_username']
        password = session['gvm_password']
        target_name = request.form.get('target_name')
        target_hosts = request.form.get('target_hosts')
        scan_config_id = request.form.get('scan_config_id')
        scanner_id = request.form.get('scanner_id')
        existing_target_id = request.form.get('existing_target_id')
        session['scan_start_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
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
    
    task_id = session['task_id']
    target_name = session['target']
    target_hosts = session['target']

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
    
    options = scanner.get_scan_options(username, password)
    
    return jsonify(options)

@app.route('/scan_status')
def scan_status():
    if 'task_id' not in session:
        flash('No scan in progress', 'error')
        return redirect(url_for('scan'))
        
    status = scanner.get_scan_status(task_id=session['task_id'], username=session['gvm_username'], password=session['gvm_password'])
    
    if status['status'] == 'Done':
        flash('Scan completed successfully!', 'success')
        return redirect(url_for('get_scan_results'))
    
    return render_template('scan_status.html', status=status)

@app.route('/get_scan_results')
def get_scan_results():
    if 'task_id' not in session:
        flash('No scan results available', 'error')
        return redirect(url_for('scan'))
    
    task_id = session.get('task_id')
    
    # First, check if results for this task already exist in the database
    existing_results = data_access.get_gvm_results(task_id)
    
    # If results don't exist in the database, get them from the scanner and save them
    if not existing_results:
        # Get results from the scanner
        results = scanner.get_results(
            username=session.get('gvm_username'), 
            password=session.get('gvm_password')
        )
        
        if not results or 'error' in results:
            flash('Error retrieving scan results: ' + results.get('error', 'Unknown error'), 'error')
            return redirect(url_for('scan'))
        
        # Save the results to the database with the task_id as identifier
        success = data_access.save_gvm_results(task_id, results)
        if not success:
            flash('Error saving scan results', 'error')
            return redirect(url_for('scan'))
    else:
        # Use existing results from the database
        results = existing_results
    
    # Calculate scan duration if start time is available
    scan_duration = "N/A"
    if 'scan_start_time' in session:
        start_time = datetime.datetime.strptime(session['scan_start_time'], "%Y-%m-%d %H:%M:%S")
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        scan_duration = str(duration).split('.')[0]  # Remove microseconds
    
    # Add missing template variables
    return render_template('scan_results.html',
        results=results,
        scan_id=task_id,
        result_url=url_for('get_scan_results', _external=True),
        scan_date=datetime.datetime.now().strftime("%Y-%m-%d"),
        scan_time=datetime.datetime.now().strftime("%H:%M:%S"),
        scan_duration=scan_duration,
        scan_status="Complete",
        scan_progress=100,
        scan_result="Complete")

@app.route('/alerts')
def alerts():
    user_actions = [
        {'url': '/api/export/alerts', 'icon': 'fa-download', 'text': 'Export', 'class': 'export-btn'},
        {'url': '/alerts/clear', 'icon': 'fa-trash', 'text': 'Clear', 'class': 'clear-btn', 'method': 'post'}
    ]
    return render_template('alerts.html', user_actions=user_actions)

@app.route('/alerts/clear', methods=['POST'])
def clear_alerts():
    try:
        with data_access._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM nids_alerts")
            conn.commit()
        flash('All alerts have been cleared', 'success')
    except Exception as e:
        flash(f'Error clearing alerts: {str(e)}', 'error')
    
    return redirect(url_for('alerts'))

@app.route('/api/alerts')
def get_alerts():
    """Fetch alerts data from database"""
    try:
        with data_access._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, source_ip, destination_ip, source_port, destination_port, 
                protocol, threat_type, severity, description, timestamp 
                FROM nids_alerts 
                ORDER BY timestamp DESC
            """)
            alerts = cursor.fetchall()
        
        # Convert datetime objects to string for JSON serialization
        for alert in alerts:
            if isinstance(alert['timestamp'], datetime.datetime):
                alert['timestamp'] = alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return jsonify({"error": str(e)})

@app.route('/api/export/alerts')
def export_alerts():
    # Get database manager
    db_manager = DBManager()
    
    # Get alerts from database
    with db_manager._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM nids_alerts")
        alerts = [dict(row) for row in cursor.fetchall()]
    
    # Convert to JSON
    json_data = json.dumps(alerts)
    
    # Create response with correct headers
    response = Response(
        json_data,
        mimetype='application/json',
        headers={
            'Content-Disposition': 'attachment; filename=alerts_export.json'
        }
    )
    
    return response

@app.route('/api/alerts/summary')
def get_alerts_summary():
    """Get a summary of recent alerts for dashboard"""
    try:
        with data_access._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get total count
            cursor.execute("SELECT COUNT(*) as total FROM nids_alerts")
            total = cursor.fetchone()['total']
            
            # Get counts by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM nids_alerts 
                GROUP BY severity
            """)
            severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Get recent alerts (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) as recent 
                FROM nids_alerts 
                WHERE timestamp >= datetime('now', '-1 day')
            """)
            recent = cursor.fetchone()['recent']
            
        return jsonify({
            'total': total,
            'recent': recent,
            'critical': severity_counts.get('Critical', 0),
            'high': severity_counts.get('High', 0),
            'medium': severity_counts.get('Medium', 0),
            'low': severity_counts.get('Low', 0)
        })
    except Exception as e:
        logger.error(f"Error fetching alerts summary: {str(e)}")
        return jsonify({"error": str(e)})


@app.route('/test')
def test():
    return render_template('test.html')

if __name__ == '__main__':
    # Start the NIDS in a background thread 
    nids_thread = threading.Thread(target=start_nids_thread)
    nids_thread.daemon = True  # Daemonize thread
    nids_thread.start()

    app.run(debug=True)