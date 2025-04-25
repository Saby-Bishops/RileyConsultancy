from flask import Blueprint, jsonify, render_template, flash, redirect, url_for, Response, current_app
import logging
import json
import datetime

logger = logging.getLogger(__name__)
alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/alerts')
def alerts():
    user_actions = [
        {'url': '/api/export/alerts', 'icon': 'fa-download', 'text': 'Export', 'class': 'export-btn'},
        {'url': '/alerts/clear', 'icon': 'fa-trash', 'text': 'Clear', 'class': 'clear-btn', 'method': 'post'}
    ]
    return render_template('alerts.html', user_actions=user_actions)

@alerts_bp.route('/alerts/clear', methods=['POST'])
def clear_alerts():
    try:
        with current_app.db_manager._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("DELETE FROM nids_alerts")
            conn.commit()
        flash('All alerts have been cleared', 'success')
    except Exception as e:
        flash(f'Error clearing alerts: {str(e)}', 'error')
    
    return redirect(url_for('alerts.alerts'))

@alerts_bp.route('/api/alerts')
def get_alerts():
    """Fetch alerts data from database"""
    try:
        with current_app.db_manager._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
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

@alerts_bp.route('/api/export/alerts')
def export_alerts():
    # Get alerts from database
    with current_app.db_manager._get_connection() as conn:
        cursor = conn.cursor(dictionary=True)
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

@alerts_bp.route('/api/alerts/summary')
def get_alerts_summary():
    """Get a summary of recent alerts for dashboard"""
    try:
        with current_app.db_manager._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            
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