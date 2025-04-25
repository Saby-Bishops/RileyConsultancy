from flask import Flask, session
import os
import logging
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.recon.nmap_scanner import NmapScanner

# Setup logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    stream=sys.stdout)
logger = logging.getLogger("nmap_scanner_test")

# Create a simple Flask app for testing
app = Flask(__name__)
app.secret_key = 'test_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'

# Create our scanner
scanner = NmapScanner()

def test_connection():
    """Test if nmap is available on the system"""
    logger.info("Testing nmap connection...")
    result = scanner.test_connection()
    logger.info(f"Connection test result: {result}")
    return result

def test_scan_options():
    """Test retrieving scan options"""
    logger.info("Getting scan options...")
    options = scanner.get_scan_options()
    logger.info(f"Available scan configs: {[c['name'] for c in options['scan_configs']]}")
    return options

def test_run_scan(target_hosts="127.0.0.1", scan_config="basic"):
    """Run a test scan against a target"""
    logger.info(f"Starting {scan_config} scan against {target_hosts}...")
    result = scanner.run_scan(
        target_name="Test Scan",
        target_hosts=target_hosts,
        scan_config_id=scan_config
    )
    
    if 'error' in result:
        logger.error(f"Scan error: {result['error']}")
        return None
    
    task_id = result['task_id']
    logger.info(f"Scan started with task_id: {task_id}")
    return task_id

def test_scan_status(task_id):
    """Monitor scan status until completion"""
    import time
    
    if not task_id:
        logger.error("No task ID provided")
        return
    
    logger.info(f"Monitoring scan status for task {task_id}...")
    
    while True:
        status = scanner.get_scan_status(task_id)
        logger.info(f"Status: {status['status']} - Progress: {status['progress']}%")
        
        if status['status'] in ['Done', 'Failed']:
            return status
        
        # Wait before checking again
        time.sleep(5)

def test_get_results(task_id):
    """Get and display scan results"""
    logger.info(f"Retrieving results for task {task_id}...")
    results = scanner.get_results(task_id=task_id)
    
    if isinstance(results, dict) and 'error' in results:
        logger.error(f"Error getting results: {results['error']}")
        return None
    
    # Display summary of results
    severities = {}
    for result in results:
        severity = result.get('severity', 'Unknown')
        severities[severity] = severities.get(severity, 0) + 1
        
    logger.info(f"Results by severity: {severities}")
    logger.info(f"Total findings: {len(results)}")
    
    # Display a few sample findings
    if results:
        logger.info("Sample findings:")
        for i, result in enumerate(results[:3]):  # Show up to 3 samples
            logger.info(f"Finding {i+1}: {result.get('name')} - {result.get('severity')} - {result.get('description')[:100]}...")
    
    return results

def run_full_test(target="127.0.0.1", scan_type="basic"):
    """Run a complete test of the Nmap scanner"""
    with app.app_context():
        # Test connection
        conn_result = test_connection()
        if 'error' in conn_result:
            logger.error("Connection test failed. Aborting.")
            return
        
        # Test scan options
        test_scan_options()
        
        # Run a scan
        task_id = test_run_scan(target, scan_type)
        if not task_id:
            logger.error("Failed to start scan. Aborting.")
            return
        
        # Monitor status
        status = test_scan_status(task_id)
        if status['status'] != 'Done':
            logger.error(f"Scan failed with status: {status}")
            return
        
        # Get results
        results = test_get_results(task_id)
        return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Test Nmap Scanner functionality')
    parser.add_argument('--target', default='127.0.0.1', help='Target to scan (default: 127.0.0.1)')
    parser.add_argument('--scan-type', default='basic', choices=['basic', 'default', 'intense', 'vuln', 'port'], 
                        help='Scan type to use (default: basic)')
    
    args = parser.parse_args()
    
    logger.info(f"Starting test with target={args.target}, scan_type={args.scan_type}")
    run_full_test(args.target, args.scan_type)