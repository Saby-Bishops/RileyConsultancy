import subprocess
import logging
import re
import xml.etree.ElementTree as ET
import tempfile
import os
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self):
        self.results = []  # Store scan results

    def test_connection(self, username=None, password=None):
        """Test if nmap is available"""
        try:
            # Run a simple nmap command to test if it's installed
            result = subprocess.run(['nmap', '--version'], 
                                   capture_output=True, 
                                   text=True)
            
            if result.returncode == 0:
                return {"status": "success"}
            else:
                return {"error": "Nmap is not properly installed or accessible"}
        except Exception as e:
            logger.error(f"Error testing nmap connection: {str(e)}")
            return {"error": f"Failed to run nmap: {str(e)}"}

    def get_scan_options(self, username=None, password=None):
        """Get available scan options for nmap"""
        # For nmap, we'll provide some predefined scan types
        scan_configs = [
            {"id": "basic", "name": "Basic Scan"},
            {"id": "default", "name": "Default Scan"},
            {"id": "intense", "name": "Intense Scan"},
            {"id": "vuln", "name": "Vulnerability Scan"},
            {"id": "port", "name": "Port Scan"}
        ]
        
        scanners = [
            {"id": "nmap", "name": "Nmap Scanner"}
        ]
        
        return {
            "scan_configs": scan_configs,
            "scanners": scanners,
            "targets": []  # Empty list as we create targets on the fly
        }

    def run_scan(self, username=None, password=None, target_name="", target_hosts="", 
                 target_ports="", scan_config_id="default", scanner_id="nmap", existing_target_id=None):
        """Run an nmap scan with the specified parameters"""
        if not target_hosts:
            return {"error": "Target hosts are required"}
        
        # Generate a task ID
        task_id = str(uuid.uuid4())
        
        # Create a temporary file to store the XML output
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp:
            xml_output_file = tmp.name
        
        try:
            # Build the nmap command based on the scan type
            cmd = ['nmap']
            
            # Configure scan based on scan_config_id
            if scan_config_id == "basic":
                cmd.extend(['-sV'])
            elif scan_config_id == "intense":
                cmd.extend(['-sS', '-sV', '-A', '-T4'])
            elif scan_config_id == "vuln":
                cmd.extend(['-sV', '--script', 'vuln'])
            elif scan_config_id == "port":
                cmd.extend(['-p-'])
            # Default scan
            else:
                cmd.extend(['-sV', '-O'])
            
            # Add target ports if specified
            if target_ports:
                cmd.extend(['-p', target_ports])
            
            # Add XML output format
            cmd.extend(['-oX', xml_output_file])
            
            # Add target hosts
            cmd.append(target_hosts)
            
            logger.info(f"Running nmap command: {' '.join(cmd)}")
            
            # Run the scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store scan information
            scan_info = {
                'status': 'Running',
                'target': target_hosts,
                'ports': target_ports,
                'scan_type': scan_config_id,
                'task_id': task_id,
                'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'process': process,
                'xml_output_file': xml_output_file
            }
            
            self.results.append(scan_info)
            
            return {
                'task_id': task_id,
                'status': 'Running'
            }
            
        except Exception as e:
            logger.error(f"Error starting nmap scan: {str(e)}")
            if os.path.exists(xml_output_file):
                os.unlink(xml_output_file)
            return {"error": f"Failed to start nmap scan: {str(e)}"}

    def get_scan_status(self, task_id, username=None, password=None):
        """Get the status of a running nmap scan"""
        # Find the scan info for the given task_id
        scan_info = next((s for s in self.results if s.get('task_id') == task_id), None)
        
        if not scan_info:
            return {"status": "Not found", "progress": 0, "task_id": task_id}
        
        # Check if the process has completed
        if 'process' in scan_info:
            process = scan_info['process']
            poll_result = process.poll()
            
            if poll_result is None:
                # Process is still running
                # Try to estimate progress (this is just a rough estimate)
                return {"status": "Running", "progress": 50, "task_id": task_id}
            elif poll_result == 0:
                # Process completed successfully
                stdout, stderr = process.communicate()
                
                # Process the XML output to get results
                results = self._parse_xml_results(scan_info['xml_output_file'])
                
                # Update scan info
                scan_info.pop('process', None)  # Remove process object
                scan_info['status'] = 'Done'
                scan_info['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                scan_info['results'] = results
                
                # Calculate summary of vulnerability severity
                summary = self._calculate_severity_summary(results)
                scan_info['summary'] = summary
                scan_info['total'] = sum(summary.values())
                
                return {"status": "Done", "progress": 100, "task_id": task_id}
            else:
                # Process failed
                stdout, stderr = process.communicate()
                scan_info.pop('process', None)
                scan_info['status'] = 'Failed'
                scan_info['error'] = stderr
                
                return {"status": "Failed", "progress": 0, "task_id": task_id, "error": stderr}
        
        # If the process info is not available but we have results, the scan is done
        if 'results' in scan_info:
            return {"status": "Done", "progress": 100, "task_id": task_id}
        
        return {"status": scan_info.get('status', 'Unknown'), "progress": 0, "task_id": task_id}

    def _parse_xml_results(self, xml_file):
        """Parse nmap XML results and convert to a structured format"""
        try:
            if not os.path.exists(xml_file):
                logger.error(f"XML file not found: {xml_file}")
                return []
            
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = []
            
            # Process each host
            for host in root.findall('host'):
                ip = host.find('address[@addrtype="ipv4"]')
                ip_address = ip.get('addr') if ip is not None else "Unknown"
                
                hostname_elem = host.find('hostnames/hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else ""
                
                # Process each port
                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else "unknown"
                    
                    service_elem = port.find('service')
                    service = service_elem.get('name') if service_elem is not None else "unknown"
                    product = service_elem.get('product') if service_elem is not None else ""
                    version = service_elem.get('version') if service_elem is not None else ""
                    
                    # Get vulnerability scripts
                    scripts = port.findall('script')
                    vulns = []
                    
                    for script in scripts:
                        script_id = script.get('id')
                        output = script.get('output')
                        
                        # Determine severity based on script name or output
                        severity = "Medium"  # Default severity
                        
                        if "VULNERABLE" in output:
                            severity = "High"
                        elif "CVE" in output:
                            severity = "High"
                        elif "vulnerability" in output.lower():
                            severity = "Medium"
                        elif "warning" in output.lower():
                            severity = "Low"
                        
                        # Extract CVEs from output
                        cve_matches = re.findall(r'CVE-\d{4}-\d+', output)
                        cves = list(set(cve_matches))  # Remove duplicates
                        
                        vulns.append({
                            "name": script_id,
                            "severity": severity,
                            "description": output,
                            "cves": cves
                        })
                    
                    # If port is open but no vulnerabilities found, add it as informational
                    if state == "open" and not vulns:
                        vulns.append({
                            "name": f"Open {service} port",
                            "severity": "Info",
                            "description": f"Port {port_id}/{protocol} is open and running {service} {product} {version}",
                            "cves": []
                        })
                    
                    # Add results for this port
                    for vuln in vulns:
                        results.append({
                            "ip": ip_address,
                            "hostname": hostname,
                            "port": port_id,
                            "protocol": protocol,
                            "service": service,
                            "product": product,
                            "version": version,
                            "name": vuln["name"],
                            "severity": vuln["severity"],
                            "description": vuln["description"],
                            "cves": vuln["cves"]
                        })
            
            # Clean up the XML file
            try:
                os.unlink(xml_file)
            except Exception as e:
                logger.warning(f"Failed to delete temporary XML file: {str(e)}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error parsing nmap results: {str(e)}")
            return []

    def _calculate_severity_summary(self, results):
        """Calculate a summary of vulnerabilities by severity"""
        summary = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for result in results:
            severity = result.get("severity", "Info")
            summary[severity] = summary.get(severity, 0) + 1
        
        return summary

    def get_results(self, username=None, password=None, task_id=None):
        """Get scan results"""
        if not task_id:
            # Return the latest scan results if task_id is not specified
            if not self.results:
                return {"error": "No scan results available"}
            latest = next((s for s in reversed(self.results) if 'results' in s), None)
            if not latest:
                return {"error": "No completed scan results available"}
            return latest.get('results', [])
        
        # Find the scan info for the given task_id
        scan_info = next((s for s in self.results if s.get('task_id') == task_id), None)
        
        if not scan_info:
            return {"error": f"No scan found with task_id: {task_id}"}
        
        if 'results' not in scan_info:
            return {"error": f"Scan with task_id {task_id} has not completed yet"}
        
        return scan_info['results']