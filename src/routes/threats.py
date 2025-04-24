from flask import Blueprint, render_template, send_file, jsonify, current_app

threats_bp = Blueprint('threats', __name__)

@threats_bp.route('/api/export/threats')
def export_threats():
    """Export threats data as JSON"""
    filename = current_app.db_manager.export_threats_json()
    return send_file(filename, as_attachment=True)

@threats_bp.route('/threats')
def threats():
    user_actions = [
        {'url': '/api/export/threats', 'icon': 'fa-download', 'text': 'Export', 'class': 'export-btn'},
        {'url': '/import', 'icon': 'fa-upload', 'text': 'Import', 'class': 'import-btn'}
    ]
    return render_template('threats.html', user_actions=user_actions)

@threats_bp.route('/api/threats')
def get_threats():
    """Fetch cleaned threat data from db"""
    try:
        with current_app.db_manager._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT ip_address, domain, threat_type, threat_level, source, detected_at FROM threat_data ORDER BY detected_at DESC")
            threats = cursor.fetchall()

        return jsonify(threats)  # Return only useful fields
    except Exception as e:
        return jsonify({"error": str(e)})