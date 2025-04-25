from flask import Blueprint, jsonify, render_template, redirect, url_for, session, current_app
import random

vulnerabilities_bp = Blueprint('vulnerabilities', __name__)

@vulnerabilities_bp.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Fetch vulnerabilities data"""
    if len(current_app.scanner.results) == 0:
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
            "total": current_app.scanner.results[-1]['total'],
            "critical": current_app.scanner.results[-1]['summary'].get('Critical', 0),
            "high": current_app.scanner.results[-1]['summary'].get('High', 0),
            "medium": current_app.scanner.results[-1]['summary'].get('Medium', 0),
            "low": current_app.scanner.results[-1]['summary'].get('Low', 0),
            "last_scan": current_app.scanner.results[-1]['last_scan'],
            "status": current_app.scanner.results[-1]['status']
        }
    }
    return jsonify(stats)

@vulnerabilities_bp.route('/vulnerabilities')
def vulnerabilities():
    # Check if GVM credentials are already in session
    if 'scanner_username' not in session or 'scanner_password' not in session:
        # No credentials, redirect to GVM login page with a return URL
        return redirect(url_for('scanning.scanner_login', next=url_for('vulnerabilities.vulnerabilities')))
    
    user_actions = [
        {'url': '/scan', 'icon': 'fa-search', 'text': 'New Scan', 'class': 'scan-btn'},
        {'url': '/rescan', 'icon': 'fa-sync-alt', 'text': 'Rescan', 'class': 'rescan-btn', 'method': 'post'}
    ]
    return render_template('vulnerabilities.html', user_actions=user_actions)