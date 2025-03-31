# app.py
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, send_file
import datetime
import random
import os
import threading
import json
import logging
from werkzeug.utils import secure_filename


from api.osint.email_search import EmailSearch
from api.osint.username_search import UsernameSearch
from api.osint.osint_data import OsintData
from api.gvm_integration import GVMScanner

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
app.secret_key = os.urandom(24)  # For flash messages
data_access = OsintData('osint.db')


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

@app.route('/api/threats')
def get_threats():
    """API endpoint to get threat data"""
    threats = data_access.get_threat_data()
    return jsonify(threats)

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
        scanner = GVMScanner()
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
def scan_status():
    if 'task_id' not in session:
        flash('No scan in progress', 'error')
        return redirect(url_for('scan'))
        
    scanner = GVMScanner()
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
    
    scanner = GVMScanner()
    results = scanner.get_results(username=session['gvm_username'], password=session['gvm_password'])
    
    # Add missing template variables
    return render_template('scan_results.html', 
                          results=results,
                          scan_id=session.get('task_id', 'N/A'),
                          result_url=url_for('get_scan_results', _external=True),
                          scan_date=datetime.datetime.now().strftime("%Y-%m-%d"),
                          scan_time=datetime.datetime.now().strftime("%H:%M:%S"),
                          scan_duration="N/A",  # You might want to calculate this
                          scan_status="Complete",
                          scan_progress=100,
                          scan_result="Complete")


@app.route('/test')
def test():
    return render_template('test.html')

if __name__ == '__main__':
    app.run(debug=True)