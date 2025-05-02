# Import routes
from routes.threats import threats_bp
from routes.vulnerabilities import vulnerabilities_bp
from routes.alerts import alerts_bp
from routes.scanning import scan_bp

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, current_app, session
import datetime
import random
import os
import logging
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import threading
from functools import wraps

from api.osint.email_search import EmailSearch
from api.osint.username_search import UsernameSearch
from api.osint.open_phish import fetch_phishing_urls, extract_domains

from api.recon.scanner_factory import ScannerFactory

from api.realtime.nids import IntrusionDetectionSystem

from db.db_manager import DBManager
from db.db_connector import DBConnector
from config import Config

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Debug environment variables
logger.debug("Environment variables for database connection:")
for key in ["TAILNET_HOST", "TAILNET_PORT", "TAILNET_USER", "TAILNET_PASS", "TAILNET_DB"]:
    value = os.environ.get(key)
    # Don't log the actual password value
    if key == "TAILNET_PASS" and value:
        logger.debug(f"{key}: [REDACTED]")
    else:
        logger.debug(f"{key}: {value}")

# Initialize database
print(app.config['TAILNET_CONNECTION_SETTINGS'])
connector = DBConnector(app.config['TAILNET_CONNECTION_SETTINGS'])
app.db_manager = DBManager(connector)
app.db_manager._ensure_tables_exist()

# Use the default scanner specified in the config or fall back to GVM
default_scanner = getattr(Config, 'DEFAULT_SCANNER', 'gvm')
app.scanners = ScannerFactory()
app.scanner = app.scanners.get_scanner(default_scanner)

# Register blueprints
app.register_blueprint(threats_bp)
app.register_blueprint(vulnerabilities_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(scan_bp)

# Create required directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Add this decorator function to protect routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Add these routes for user authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    next_url = request.args.get('next', url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Verify credentials with database
        user = app.db_manager.get_user_by_username(username)
        
        if user and check_password_hash(user['password_hash'], password):
            # Store user info in session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            flash('Successfully logged in', 'success')
            # Redirect to the originally requested page
            return redirect(next_url)
        else:
            flash('Invalid username or password', 'error')
    
    # GET request - show login form
    return render_template('login.html', next=next_url)

@app.route('/logout')
def logout():
    """User logout route"""
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

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
@login_required
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

def fetch_and_save_phishing():
    """Fetch and save phishing URLs from OpenPhish"""
    domains_fn = 'ALL-phishing-domains.lst'
    links_fn = 'ALL-phishing-links.lst'
    base_url = 'https://phish.co.za/latest/'
    domains_url = base_url + domains_fn
    links_url = base_url + links_fn
    #data = fetch_phishing_urls(domains_url, domains_fn)
    data = fetch_phishing_urls(links_url, links_fn)
    if data:
        app.db_manager.save_phishing_data(data['content'], data['timestamp'])
        logger.debug(f"Fetched {len(data['content'])} URLs from OpenPhish")
    else:
        logger.error("Failed to fetch phishing URLs")

@app.route('/api/trends')
def get_trends():
    """Fetch trends data for the past 7 days"""
    with app.db_manager.get_cursor() as cursor:
        cursor.execute("""SELECT COUNT(*) AS count 
                            FROM phishing_urls 
                            WHERE timestamp >= (NOW() - INTERVAL 7 DAY)
                            """)
        result = cursor.fetchone()

        # if no data in database, fetch from github data
        if result['count'] == 0:
            logger.debug("No data in database. Fetching phishing URLs.")
            fetch_and_save_phishing()

        # if a full week of data isn't in the database, and app start time is more than 7 days ago, fetch from OpenPhish
        if result['count'] < 7 and app.start_time < datetime.datetime.now() - datetime.timedelta(days=7):
            logger.debug("Less than 7 days of data. Checking for recent phishing urls")
            # Fetch phishing URLs from OpenPhish
            fetch_and_save_phishing()

        # Now fetch phishing data grouped by day
        cursor.execute("""
            SELECT DATE(timestamp) AS day, COUNT(*) AS count
            FROM phishing_urls
            WHERE timestamp >= (NOW() - INTERVAL 7 DAY)
            GROUP BY day
            ORDER BY day
        """)
        phishing_rows = cursor.fetchall()
        day_to_count = {row['day'].strftime("%Y-%m-%d"): row['count'] for row in phishing_rows}
        days = [(datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        phishing_counts = [day_to_count.get(day, 0) for day in days]

        logger.debug(f"Phishing URLs per day in the last 7 days: {phishing_counts}")
            
    return jsonify({
        "days": days,
        "malware": [random.randint(10, 50) for _ in range(7)],
        "phishing": phishing_counts,
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
    app.start_time = datetime.datetime.now()
    # Only start NIDS if explicitly configured to do so
    if app.config['AUTO_START_NIDS']:
        nids_thread = threading.Thread(target=start_nids_thread, args=(app,))
        nids_thread.daemon = True
        nids_thread.start()
        app.nids_running = True
    
    app.run(debug=app.config['DEBUG'])