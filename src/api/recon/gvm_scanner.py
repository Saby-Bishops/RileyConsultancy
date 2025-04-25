# gvm_scanner.py
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
import datetime
import logging
import dbus
import os
from lxml import etree

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Get a logger for this module

class GVMScanner:
    def __init__(self, socket_path='/var/run/gvmd/gvmd.sock'):
        self.socket_path = socket_path
        self.results = []

    def start_gvm_service(self):
        """Try to start the GVM service using D-Bus/systemd API"""
        try:
            logger.info("Attempting to start GVM service via D-Bus...")
            
            # Connect to the system bus
            system_bus = dbus.SystemBus()
            
            # Get the systemd service
            systemd = system_bus.get_object('org.freedesktop.systemd1', 
                                            '/org/freedesktop/systemd1')
            
            # Get the manager interface
            manager = dbus.Interface(systemd, 'org.freedesktop.systemd1.Manager')
            
            # Start the unit
            job = manager.StartUnit('gvmd.service', 'replace')
            
            logger.info("GVM service start job initiated")
            return True
        except Exception as e:
            logger.error(f"Error while starting GVM service via D-Bus: {e}")
            return False
        
    def check_socket_exists(self):
        """Check if the GVM socket file exists"""
        exists = os.path.exists(self.socket_path)
        if exists:
            logger.info(f"Socket {self.socket_path} exists")
        else:
            logger.warning(f"Socket {self.socket_path} does not exist")
        return exists
    
    def create_connection(self):
        """Create a new connection to GVM"""
        if not self.check_socket_exists():
            logger.warning("Socket doesn't exist, attempting to start service")
            if not self.start_gvm_service():
                logger.error("Failed to start GVM service")
                return False
            
            # Check again after trying to start
            if not self.check_socket_exists():
                logger.error("Socket still doesn't exist after service start attempt")
                return False
        
        try:
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            self.gmp = Gmp(connection, transform=transform)
            return True
        except Exception as e:
            logger.error(f"Error creating connection: {e}")
            return False
    
    def authenticate(self, username, password):
        """Authenticate with the GVM service"""
        try:
            # Make sure gmp is initialized
            if self.gmp is None:
                if not self.create_connection():
                    raise Exception("Failed to create connection to GVM service")
                    
            self.gmp.authenticate(username, password)
            logger.info("Successfully authenticated with GVM")
            return True
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def create_target(self, name, hosts, ports, comment="Created by ThreatGuard"):
        """Create a target for scanning"""
        try:
            response = self.gmp.create_target(
                name=name,
                hosts=hosts,
                port_list_id=ports,
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
            logger.debug(f"Raw get_task XML response: {etree.tostring(response, pretty_print=True).decode('utf-8')}")
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
            logger.debug(f"Raw get_reports XML response: {etree.tostring(response, pretty_print=True).decode('utf-8')}")
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
        
    def run_scan(self, username, password, target_name, target_hosts, target_ports, scan_config_id, scanner_id, existing_target_id=None):
        """Run a complete scan workflow with specified config and scanner"""
        if not self.authenticate(username, password):
            return {"error": "Authentication failed"}
        
        # Use existing target or create a new one
        if existing_target_id:
            target_id = existing_target_id
        else:
            # Create target
            target_id = self.create_target(target_name, target_hosts, target_ports)
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

    def test_connection(self, username, password):
        """Test GVM connection with provided credentials and ensure service is running"""
        try:
            # First check if the socket exists
            if not self.check_socket_exists():
                # Socket doesn't exist, try to start the service
                if not self.start_gvm_service():
                    return {'status': 'error', 'message': 'GVM service is not running and could not be started'}
                
                # Check again after trying to start
                if not self.check_socket_exists():
                    return {'status': 'error', 'message': 'GVM service appears to be started but socket file still missing'}
            
            # Now try to create the connection
            if not self.create_connection():
                return {'status': 'error', 'message': 'Failed to establish connection to GVM socket'}
            
            # Finally try to authenticate
            if not self.authenticate(username, password):
                return {'status': 'error', 'message': 'Authentication failed with provided credentials'}
            
            # If we got here, everything worked
            return {'status': 'success', 'message': 'Successfully connected and authenticated with GVM'}
            
        except Exception as e:
            logger.error(f"Unexpected error in test_connection: {e}")
            return {'status': 'error', 'message': f'Unexpected error: {str(e)}'}