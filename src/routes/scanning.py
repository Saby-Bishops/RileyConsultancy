from flask import Blueprint, jsonify, render_template, flash, redirect, url_for, request, session, current_app
import logging
import datetime

logger = logging.getLogger(__name__)
scan_bp = Blueprint('scanning', __name__)

@scan_bp.route('/scanner_login', methods=['GET', 'POST'])
def scanner_login():
    """Generic login route for scanner authentication"""
    next_url = request.args.get('next', url_for('vulnerabilities.vulnerabilities'))
    scanner_type = request.args.get('scanner_type', session.get('scanner_type', 'gvm'))
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        scanner_type = request.form.get('scanner_type', 'gvm')
        
        # Get the appropriate scanner
        scanner = current_app.scanners.get_scanner(scanner_type)
        
        # Verify credentials with scanner
        result = scanner.test_connection(username, password)
        
        if 'error' in result:
            flash(result['error'], 'error')
            return render_template('scanner_login.html', next=next_url, scanner_type=scanner_type)
        
        # Store credentials and scanner type in session
        session['scanner_username'] = username
        session['scanner_password'] = password
        session['scanner_type'] = scanner_type
        
        # Update the app's scanner
        current_app.scanner = scanner
        
        flash(f'Successfully logged in to {scanner_type.upper()} scanner', 'success')
        
        # Redirect to the originally requested page
        return redirect(next_url)
    
    # GET request - show login form
    return render_template('scanner_login.html', next=next_url, scanner_type=scanner_type)

@scan_bp.route('/change_scanner', methods=['GET', 'POST'])
def change_scanner():
    """Change the current scanner"""
    if request.method == 'POST':
        scanner_type = request.form.get('scanner_type', 'gvm')
        session['scanner_type'] = scanner_type
        
        # Update the app's scanner
        current_app.scanner = current_app.scanners.get_scanner(scanner_type)
        
        flash(f'Switched to {scanner_type.upper()} scanner', 'success')
        return redirect(url_for('scanning.scan'))
    
    # GET request - show scanner selection form
    return render_template('change_scanner.html', 
                          current_scanner=session.get('scanner_type', 'gvm'),
                          scanners=[{'id': 'gvm', 'name': 'GVM Scanner'}, 
                                   {'id': 'nmap', 'name': 'Nmap Scanner'}])

@scan_bp.route('/scan', methods=['GET', 'POST'])
def scan():
    # Make sure user is authenticated with scanner credentials if needed
    if 'scanner_username' not in session or 'scanner_password' not in session:
        # Default to empty credentials for scanners that don't need auth
        session['scanner_username'] = ''
        session['scanner_password'] = ''
    
    # Get scanner type from session or default to the one configured in the app
    scanner_type = session.get('scanner_type', getattr(current_app.config, 'DEFAULT_SCANNER', 'gvm'))
    
    # Make sure user is authenticated with GVM
    if 'scanner_username' not in session or 'scanner_password' not in session:
        return redirect(url_for('scanning.scanner_login', next=url_for('scanning.scan')))
    
    if request.method == 'POST':
        # Use stored credentials
        username = session['scanner_username']
        password = session['scanner_password']
        target_name = request.form.get('target_name')
        target_hosts = request.form.get('target_hosts')
        target_ports = request.form.get('target_ports')
        scan_config_id = request.form.get('scan_config_id')
        scanner_id = request.form.get('scanner_id')
        existing_target_id = request.form.get('existing_target_id')
        session['scan_start_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session['target'] = target_hosts
        
        # Start the scan
        result = current_app.scanner.run_scan(
            username, 
            password, 
            target_name, 
            target_hosts,
            target_ports,
            scan_config_id, 
            scanner_id,
            existing_target_id
        )
        
        if 'error' in result:
            flash(result['error'], 'error')
            return redirect(url_for('scanning.scan'))
        
        # Store task_id in session to check status later
        session['task_id'] = result['task_id']
        
        flash('Scan started successfully!', 'success')
        return redirect(url_for('scanning.scan_status'))
    
    else:
        # Get available options from the scanner
        options = current_app.scanner.get_scan_options(
            session.get('scanner_username', ''), 
            session.get('scanner_password', '')
        )
        
        if 'error' in options:
            flash('Could not load scan options. Please check your credentials.', 'error')
            scan_options = None
        else:
            scan_options = options
            
        return render_template('scan_form.html', 
                               scan_options=scan_options, 
                               scanner_type=scanner_type)
    
@scan_bp.route('/rescan', methods=['GET', 'POST'])
def rescan():
    if 'task_id' not in session:
        flash('No scan in progress', 'error')
        return redirect(url_for('scanning.scan'))
    
    task_id = session['task_id']
    target_name = session.get('target', '')
    target_hosts = session.get('target', '')

    # Re-run the scan with the same parameters
    result = current_app.scanner.run_scan(
        session.get('scanner_username', ''),
        session.get('scanner_password', ''),
        target_name,
        target_hosts,
        '', # No ports specified for rescan
        '', # Use default scan config
        '', # Use default scanner
        None # No existing target
    )
    
    if 'error' in result:
        flash(result['error'], 'error')
        return redirect(url_for('scanning.scan'))
    
    # Update task_id with the new scan
    session['task_id'] = result['task_id']
    session['scan_start_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    flash('Rescan started successfully!', 'success')
    return redirect(url_for('scanning.scan_status'))


@scan_bp.route('/get_scan_options', methods=['POST'])
def get_scan_options():
    """AJAX endpoint to get scan options after user enters credentials"""
    scanner_type = request.form.get('scanner_type', 'gvm')
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Store credentials and scanner type in session
    session['scanner_username'] = username
    session['scanner_password'] = password
    session['scanner_type'] = scanner_type
    
    # Get options from the scanner
    options = current_app.scanner.get_scan_options(username, password)
    
    return jsonify(options)

@scan_bp.route('/scan_status')
def scan_status():
    if 'task_id' not in session:
        flash('No scan in progress', 'error')
        return redirect(url_for('scanning.scan'))
        
    status = current_app.scanner.get_scan_status(task_id=session['task_id'], username=session['scanner_username'], password=session['scanner_password'])
    
    if status['status'] == 'Done':
        flash('Scan completed successfully!', 'success')
        return redirect(url_for('scanning.get_scan_results'))
    
    return render_template('scan_status.html', status=status)

@scan_bp.route('/get_scan_results')
def get_scan_results():
    if 'task_id' not in session:
        flash('No scan results available', 'error')
        return redirect(url_for('scanning.scan'))
    
    task_id = session.get('task_id')
    
    # First, check if results for this task already exist in the database
    existing_results = current_app.db_manager.get_gvm_results(task_id)
    
    # If results don't exist in the database, get them from the scanner and save them
    if not existing_results:
        # Get results from the scanner
        results = current_app.scanner.get_results(
            username=session.get('scanner_username'), 
            password=session.get('scanner_password')
        )
        
        if not results or 'error' in results:
            flash('Error retrieving scan results: ' + results.get('error', 'Unknown error'), 'error')
            return redirect(url_for('scanning.scan'))
        
        # Save the results to the database with the task_id as identifier
        success = current_app.db_manager.save_gvm_results(task_id, results)
        if not success:
            flash('Error saving scan results', 'error')
            return redirect(url_for('scanning.scan'))
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
        result_url=url_for('scanning.get_scan_results', _external=True),
        scan_date=datetime.datetime.now().strftime("%Y-%m-%d"),
        scan_time=datetime.datetime.now().strftime("%H:%M:%S"),
        scan_duration=scan_duration,
        scan_status="Complete",
        scan_progress=100,
        scan_result="Complete")