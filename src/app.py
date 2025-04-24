# Import routes
from routes.threats import threats_bp
from routes.vulnerabilities import vulnerabilities_bp
from routes.alerts import alerts_bp
from routes.scanning import scan_bp

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, current_app
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
from config import Config

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
app.db_manager = DBManager(app.config['DATABASE_PATH'])
app.db_manager._ensure_tables_exist()

# Initialize scanner and store it in app context
app.scanner = GVMScanner()

# Register blueprints
app.register_blueprint(threats_bp)
app.register_blueprint(vulnerabilities_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(scan_bp)

# Create required directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
        results = app.scanner.run_scan(username, password, target_name, target_hosts)
        
        if 'error' in results:
            scan_results['status'] = f"Error: {results['error']}"
            return
            
        # Update global results
        scan_results['results'] = results['results']
        scan_results['summary'] = results['summary']
        scan_results['total'] = results['total']
        scan_results['last_scan'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_results['status'] = 'Completed'
        app.scanner.results.append(scan_results)
    except Exception as e:
        scan_results['status'] = f"Error: {str(e)}"

@app.route('/')
def index():
    user_actions = [{'url': '/refresh', 'icon': 'fa-search', 'text': 'Refresh', 'class': 'refresh-btn'}]
    return render_template('dashboard.html', user_actions=user_actions)

@app.route('/api/employee/<int:employee_id>')
def get_employee(employee_id):
    """API endpoint to get employee details"""
    employee = current_app.db_manager.get_employee_details(employee_id)
    return jsonify(employee)

def allowed_file(filename):
    """Check if the uploaded file is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

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
            result = app.db_manager.import_employees_from_csv(file_path)
            
            if result["success"]:
                flash(f'Successfully imported {result["imported_count"]} employees!')
            else:
                flash(f'Error importing employees: {result["error"]}')
                
            return redirect(url_for('threats'))
        
    return render_template('import_csv.html')

@app.route('/api/stats')
def get_stats():
    
    if len(app.scanner.results) == 0:
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
            "total": app.scanner.results[-1]['total'],
            "critical": app.scanner.results[-1]['summary'].get('Critical', 0),
            "high": app.scanner.results[-1]['summary'].get('High', 0),
            "medium": app.scanner.results[-1]['summary'].get('Medium', 0),
            "low": app.scanner.results[-1]['summary'].get('Low', 0),
            "last_scan": app.scanner.results[-1]['last_scan'],
            "status": app.scanner.results[-1]['status']
        }
    }
    return jsonify(stats)

@app.route('/api/trends')
def get_trends():
    """Fetch trends data for the past 7 days"""
    with app.db_manager._get_connection() as conn:
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
                    app.db_manager.insert_to_database('phishing_urls', '(url, collection_date)', (url, timestamps))
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


@app.route('/test')
def test():
    return render_template('test.html')

# In routes/alerts.py or another appropriate file
@app.route('/start_nids', methods=['POST'])
def start_nids():
    """Manually start the NIDS"""
    # Check if NIDS is already running
    if hasattr(app, 'nids_running') and app.nids_running:
        flash('NIDS is already running', 'info')
        return redirect(url_for('alerts.alerts'))
    
    # Start NIDS in background thread
    nids_thread = threading.Thread(target=start_nids_thread, args=(app,))
    nids_thread.daemon = True
    nids_thread.start()
    
    # Mark NIDS as running
    app.nids_running = True
    
    flash('NIDS started successfully', 'success')
    return redirect(url_for('alerts.alerts'))

def start_nids_thread(app):
    """Start Network Intrusion Detection System in background thread"""
    logger.info("Starting Network Intrusion Detection System in background thread...")
    try:
        nids = IntrusionDetectionSystem()
        nids.db_manager = app.db_manager
        alert = nids.start(interface=app.config['NIDS_INTERFACE'])
        if alert:
            app.db_manager.save_alert(alert)
    except Exception as e:
        logger.error(f"Error starting NIDS: {str(e)}")

if __name__ == '__main__':
    # Only start NIDS if explicitly configured to do so
    if app.config['AUTO_START_NIDS']:
        nids_thread = threading.Thread(target=start_nids_thread, args=(app,))
        nids_thread.daemon = True
        nids_thread.start()
        app.nids_running = True
    
    app.run(debug=app.config['DEBUG'])