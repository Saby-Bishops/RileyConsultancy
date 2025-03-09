# gvm_scanner.py
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Get a logger for this module

class GVMScanner:
    def __init__(self, socket_path='/var/run/gvmd/gvmd.sock'):
        self.socket_path = socket_path
        connection = UnixSocketConnection(path=self.socket_path)
        transform = EtreeTransform()
        self.gmp = Gmp(connection, transform=transform)
    
    def authenticate(self, username, password):
        """Authenticate with the GVM service"""
        try:
            self.gmp.authenticate(username, password)
            return True
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
    
    def create_target(self, name, hosts, comment="Created by ThreatGuard"):
        """Create a target for scanning"""
        try:
            response = self.gmp.create_target(
                name=name,
                hosts=hosts,
                comment=comment
            )
            target_id = response.get('id')
            return target_id
        except Exception as e:
            print(f"Error creating target: {e}")
            return None
    
    def start_scan(self, scan_config_id, target_id, scanner_id, name):
        """Start a vulnerability scan"""
        try:
            response = self.gmp.create_task(
                name=name,
                config_id=scan_config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )
            logger.debug(f"Create Task Response: {response.keys()}")  # Debug log
            task_id = response.get('id')
            
            # Start the scan
            response = self.gmp.start_task(task_id=task_id)
            if response.get('status') != '202':
                raise Exception(f"Error starting scan: Status {response.get('status')} {response.get('status_text')}")
            
            return task_id
        except Exception as e:
            print(f"Error starting scan: {e}")
            return None
    
    def get_scan_status(self, task_id, username, password):
        """Get the status of a running scan"""
        if not self.authenticate(username, password):
            return {"error": "Authentication failed"}
        try:
            response = self.gmp.get_task(task_id=task_id)
            if response.get('status') != '200':
                raise Exception(f"Error getting scan status: Status {response.get('status')} {response.get('status_text')}")
            logger.debug(f"Get Task Response: {response.keys()}")  # Debug log

            status = response.xpath('//status/text()')[0]
            progress = response.xpath('//progress/text()')[0]
            logger.debug(f"Task Status: {status}")  # Debug log
            logger.debug(f"Task Progress: {progress}")  # Debug log
            return {
                'status': status,
                'progress': int(progress)
            }
        except Exception as e:
            print(f"Error getting scan status: {e}")
            return None
    
    def get_results(self, username, password, filter_severity=None):
        """Get scan results, optionally filtered by severity"""
        if not self.authenticate(username, password):
            return {"error": "Authentication failed"}
        try:
            response = self.gmp.get_reports()
            logger.debug(f"Get Reports Response: {response.keys()}")  # Debug log            
            # Parse results
            results = []
            result_elements = response.xpath('//report')
            logger.debug(f"Number of results: {len(result_elements)}")  # Debug log

            for result in result_elements:
                severity = result.find('.//severity')
                logger.debug(f"Severity: {severity.text}")  # Debug log
                severity_value = float(severity.text) if severity is not None and severity.text else 0.0
                
                # Skip if filtering by severity
                if filter_severity and severity_value < filter_severity:
                    continue
                
                name = result.find('.//name')
                host = result.find('.//host')
                port = result.find('.//port')
                description = result.find('.//description')
                cvss_base = result.find('.//cvss_base')
                
                results.append({
                    'id': result.get('id'),
                    'name': name.text if name is not None else 'Unknown',
                    'host': host.text if host is not None else 'Unknown',
                    'port': port.text if port is not None else 'Unknown',
                    'severity': self._get_severity_level(severity_value),
                    'severity_value': severity_value,
                    'description': description.text if description is not None else 'No description available',
                    'cvss_base': cvss_base.text if cvss_base is not None else 'N/A',
                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                logger.debug(f"Added result: {results[-1]}")  # Debug log
            
            # Get summary information
            vulns_by_severity = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            }
            
            for result in results:
                vulns_by_severity[result['severity']] += 1
            
            return {
                'results': results,
                'summary': vulns_by_severity,
                'total': len(results)
            }
        except Exception as e:
            print(f"Error getting results: {e}")
            return None
    
    def _get_severity_level(self, severity_value):
        """Convert numeric severity to text level"""
        if severity_value >= 9.0:
            return "Critical"
        elif severity_value >= 7.0:
            return "High"
        elif severity_value >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def get_scan_options(self, username, password):
        """Get available scanners, configs, and targets"""
        if not self.authenticate(username, password):
            return {"error": "Authentication failed"}
        
        # Get available scanners
        scanners = []
        scanner_response = self.gmp.get_scanners()
        for scanner in scanner_response.xpath('scanner'):
            scanner_id = scanner.get('id')
            scanner_name = scanner.xpath('name/text()')[0]
            scanners.append({
                'id': scanner_id,
                'name': scanner_name
            })
        
        # Get available scan configs
        configs = []
        config_response = self.gmp.get_scan_configs()
        for config in config_response.xpath('config'):
            config_id = config.get('id')
            config_name = config.xpath('name/text()')[0]
            configs.append({
                'id': config_id,
                'name': config_name
            })
        
        # Get available targets
        targets = []
        target_response = self.gmp.get_targets()
        for target in target_response.xpath('target'):
            target_id = target.get('id')
            target_name = target.xpath('name/text()')[0]
            targets.append({
                'id': target_id,
                'name': target_name
            })
        
        return {
            'scanners': scanners,
            'configs': configs,
            'targets': targets
        }
        
    def run_scan(self, username, password, target_name, target_hosts, scan_config_id, scanner_id, existing_target_id=None):
        """Run a complete scan workflow with specified config and scanner"""
        if not self.authenticate(username, password):
            return {"error": "Authentication failed"}
        
        # Use existing target or create a new one
        if existing_target_id:
            target_id = existing_target_id
        else:
            # Create target
            target_id = self.create_target(target_name, target_hosts)
            if not target_id:
                return {"error": "Failed to create target"}
        
        # Start scan
        scan_name = f"Scan of {target_name} - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        try:
            task_id = self.start_scan(scan_config_id, target_id, scanner_id, scan_name)
            if not task_id:
                raise Exception("Failed to start scan")
            
            return {
            'task_id': task_id,
            'status': 'started'
            }
        except Exception as e:
            return {"error": str(e)}
        
    def rerun_scan(self, task_id, username, password):
        """Rerun a scan task"""
        if not self.authenticate(username, password):
            return {"error": "Authentication failed"}
        
        try:
            response = self.gmp.start_task(task_id=task_id)
            if response.get('status') != '202':
                raise Exception(f"Error starting scan: Status {response.get('status')} {response.get('status_text')}")
            
            return {
                'task_id': task_id,
                'status': 'started'
            }
        except Exception as e:
            return {"error": str(e)}