# api/recon/scanner_factory.py
import logging
from api.recon.gvm_scanner import GVMScanner
from api.recon.nmap_scanner import NmapScanner

logger = logging.getLogger(__name__)

class ScannerFactory:
    @staticmethod
    def get_scanner(scanner_type='gvm'):
        """
        Factory method to get the appropriate scanner based on type
        Args:
            scanner_type (str): The type of scanner to use ('gvm' or 'nmap')
        Returns:
            A scanner object (GVMScanner or NmapScanner)
        """
        scanner_type = scanner_type.lower()
        try:
            if scanner_type == 'gvm':
                logger.info("Creating GVM Scanner")
                scanner = GVMScanner()
                
                # Check if service is available
                service_status = scanner.check_socket_exists()
                if not service_status:
                    logger.warning("GVM socket not found, attempting to start service")
                    # Try to start the service
                    if scanner.start_gvm_service():
                        # Wait briefly and check again
                        import time
                        time.sleep(2)  # Give service time to start
                        if scanner.check_socket_exists():
                            logger.info("GVM service started successfully")
                        else:
                            logger.error("Failed to start GVM service, falling back to Nmap Scanner")
                            scanner = NmapScanner()
                    else:
                        logger.error("Failed to start GVM service, falling back to Nmap Scanner")
                        scanner = NmapScanner()
                        
                return scanner
                
            elif scanner_type == 'nmap':
                logger.info("Using Nmap Scanner")
                return NmapScanner()
            else:
                logger.warning(f"Unknown scanner type '{scanner_type}', falling back to Nmap Scanner")
                return NmapScanner()
        except Exception as e:
            logger.error(f"Error creating scanner: {str(e)}, falling back to Nmap Scanner")
            return NmapScanner()