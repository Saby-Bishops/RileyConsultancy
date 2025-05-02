import pandas as pd
import json
import os
from datetime import datetime
import torch
from typing import Dict, List, Any, Optional
import logging
from flask import current_app as app

from llm.client import LLMClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatIntelligenceReportGenerator:
    def __init__(
        self,
        model_endpoint: str,
        db_manager,  # Will accept your DBManager instance
        output_dir: str = "reports"
    ):
        """
        Initialize the report generator with model and database manager.
        
        Args:
            db_manager: Instance of DBManager for database operations
            model_name: HuggingFace model identifier
            output_dir: Directory where reports will be saved
        """
        self.db_manager = db_manager
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        
        self.client = LLMClient(model_endpoint)
    
    def fetch_threat_data(
        self, 
        start_date: Optional[str] = None, 
        end_date: Optional[str] = None,
        threat_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fetch threat intelligence data using the DBManager.
        
        Args:
            start_date: Optional start date filter (YYYY-MM-DD)
            end_date: Optional end date filter (YYYY-MM-DD)
            threat_types: Optional list of threat types to filter
            
        Returns:
            Dictionary containing different categories of threat data
        """
        # Initialize data structure to hold all threat intel
        threat_data = {
            "osint_data": [],
            "vulnerabilities": [],
            "network_traffic": [],
            "threat_actors": [],
            "indicators_of_compromise": []
        }
        
        try:
            # Fetch OSINT data
            logger.info("Fetching OSINT data")
            osint_data = self.db_manager.get_osint_data(
                start_date=start_date,
                end_date=end_date,
                threat_types=threat_types
            )
            threat_data["osint_data"] = osint_data
            
            # Fetch vulnerabilities
            logger.info("Fetching vulnerability data")
            vulnerabilities = self.db_manager.get_vulnerabilities(
                start_date=start_date,
                end_date=end_date
            )
            threat_data["vulnerabilities"] = vulnerabilities
            
            # Fetch network traffic from pyshark
            logger.info("Fetching network traffic data")
            network_traffic = self.db_manager.get_network_traffic(
                start_date=start_date,
                end_date=end_date
            )
            threat_data["network_traffic"] = network_traffic
            
            # Fetch threat actor information
            logger.info("Fetching threat actor data")
            threat_actors = self.db_manager.get_threat_actors(
                start_date=start_date,
                end_date=end_date
            )
            threat_data["threat_actors"] = threat_actors
            
            # Fetch indicators of compromise
            logger.info("Fetching IOC data")
            indicators_of_compromise = self.db_manager.get_indicators_of_compromise(
                start_date=start_date,
                end_date=end_date
            )
            threat_data["indicators_of_compromise"] = indicators_of_compromise
            
            logger.info(f"Fetched data summary: OSINT={len(threat_data['osint_data'])}, "
                      f"Vulns={len(threat_data['vulnerabilities'])}, "
                      f"Traffic={len(threat_data['network_traffic'])}, "
                      f"Actors={len(threat_data['threat_actors'])}, "
                      f"IOCs={len(threat_data['indicators_of_compromise'])}")
            
            return threat_data
            
        except Exception as e:
            logger.error(f"Error fetching data: {e}")
            return threat_data
        
    def generate_mock_threat_data(self):
        """
        Generate realistic mock threat intelligence data for testing the report generator.
        
        Returns:
            Dict containing simulated threat data
        """
        import random
        from datetime import datetime, timedelta
        
        # Helper function to generate random dates within last month
        def random_date(days_back=30):
            today = datetime.now()
            random_days = random.randint(0, days_back)
            return (today - timedelta(days=random_days)).strftime("%Y-%m-%d %H:%M:%S")
        
        # Mock OSINT data
        osint_data = [
            {
                "source": "Twitter Security Feed",
                "description": "Multiple reports of phishing campaign targeting financial institutions with emails claiming to be from regulatory bodies",
                "timestamp": random_date(),
                "confidence_score": "High",
                "threat_type": "Phishing"
            },
            {
                "source": "Security Blog",
                "description": "New ransomware variant 'LockBit 3.0' observed in the wild with enhanced encryption capabilities",
                "timestamp": random_date(),
                "confidence_score": "Medium",
                "threat_type": "Ransomware"
            },
            {
                "source": "Dark Web Forum",
                "description": "APT group 'Cobalt Spider' selling access to compromised healthcare networks",
                "timestamp": random_date(),
                "confidence_score": "Medium",
                "threat_type": "Initial Access Broker"
            }
        ]
        
        # Mock vulnerability data
        vulnerabilities = [
            {
                "cve_id": "CVE-2023-1234",
                "cvss_score": "8.7",
                "description": "Remote code execution vulnerability in Apache Log4j library",
                "affected_systems": "All systems running Log4j versions 2.0-2.14.1",
                "patch_status": "Patched in version 2.15.0"
            },
            {
                "cve_id": "CVE-2023-5678",
                "cvss_score": "7.5",
                "description": "SQL injection vulnerability in WordPress plugin Contact Form 7",
                "affected_systems": "WordPress installations with Contact Form 7 < 5.5.3",
                "patch_status": "Patched"
            },
            {
                "cve_id": "CVE-2023-9012",
                "cvss_score": "9.8",
                "description": "Zero-day vulnerability in Microsoft Exchange Server allowing unauthenticated attackers to execute code with SYSTEM privileges",
                "affected_systems": "Microsoft Exchange Server 2019, 2016, and 2013",
                "patch_status": "Emergency patch available"
            }
        ]
        
        # Mock network traffic data
        network_traffic = [
            {
                "source_ip": "45.123.45.67",
                "destination_ip": "192.168.1.25",
                "protocol": "HTTP",
                "timestamp": random_date(),
                "flags": "SYN, ACK",
                "is_suspicious": "Yes - Known malicious IP"
            },
            {
                "source_ip": "103.41.23.78",
                "destination_ip": "192.168.1.30",
                "protocol": "HTTPS",
                "timestamp": random_date(),
                "flags": "SYN",
                "is_suspicious": "Yes - Unusual port scanning activity"
            },
            {
                "source_ip": "192.168.1.42",
                "destination_ip": "91.234.56.79",
                "protocol": "DNS",
                "timestamp": random_date(),
                "flags": "None",
                "is_suspicious": "Yes - Communication with known C2 server"
            }
        ]
        
        # Mock threat actor information
        threat_actors = [
            {
                "name": "APT29 (Cozy Bear)",
                "motivation": "Espionage, data theft",
                "tactics_techniques_procedures": "Spear-phishing, supply chain attacks, zero-day exploits",
                "associated_campaigns": "SolarWinds compromise, COVID-19 research targeting"
            },
            {
                "name": "FIN7",
                "motivation": "Financial gain",
                "tactics_techniques_procedures": "Spear-phishing, POS malware, social engineering",
                "associated_campaigns": "Retail and hospitality sector attacks"
            }
        ]
        
        # Mock indicators of compromise
        indicators_of_compromise = [
            {
                "ioc_type": "File Hash (SHA-256)",
                "ioc_value": "a5bd8f71b9c0c4b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
                "confidence": "High",
                "first_seen": random_date(40),
                "last_seen": random_date(5)
            },
            {
                "ioc_type": "Domain",
                "ioc_value": "malicious-update-server.com",
                "confidence": "High",
                "first_seen": random_date(60),
                "last_seen": random_date(2)
            },
            {
                "ioc_type": "IP Address",
                "ioc_value": "45.123.45.67",
                "confidence": "Medium",
                "first_seen": random_date(30),
                "last_seen": random_date(1)
            },
            {
                "ioc_type": "URL",
                "ioc_value": "https://legitimate-looking-site.com/update/client.exe",
                "confidence": "High",
                "first_seen": random_date(15),
                "last_seen": random_date(1)
            }
        ]
        
        # Combine all data into the expected structure
        threat_data = {
            "osint_data": osint_data,
            "vulnerabilities": vulnerabilities,
            "network_traffic": network_traffic,
            "threat_actors": threat_actors,
            "indicators_of_compromise": indicators_of_compromise
        }
        
        return threat_data
    
    def preprocess_data(self, threat_data: Dict[str, Any]) -> str:
        """
        Preprocess and structure the data for the LLM.
        
        Args:
            threat_data: Dictionary containing all threat intel data
            
        Returns:
            Formatted string with structured data ready for the LLM
        """
        # Create a structured summary of the data
        context = []

        data_available = any([
            threat_data.get("osint_data"),
            threat_data.get("vulnerabilities"),
            threat_data.get("network_traffic"),
            threat_data.get("threat_actors"),
            threat_data.get("indicators_of_compromise")
        ])
        
        if not data_available:
            logger.warning("No threat data available! Generating placeholder report.")
            mock_data = self.generate_mock_threat_data()
            context.append("## OSINT Intelligence (Mock Data)")
            for item in mock_data["osint_data"]:
                context.append(f"- Source: {item.get('source', 'Unknown')}")
                context.append(f"  Description: {item.get('description', 'No description')}")
                context.append(f"  Timestamp: {item.get('timestamp', 'Unknown')}")
                context.append(f"  Confidence: {item.get('confidence_score', 'Unknown')}")
                context.append(f"  Threat Type: {item.get('threat_type', 'Unknown')}")
                context.append("")

            for vuln in mock_data["vulnerabilities"]:
                context.append(f"- CVE ID: {vuln.get('cve_id', 'No CVE')}")
                context.append(f"  CVSS Score: {vuln.get('cvss_score', 'Unknown')}")
                context.append(f"  Description: {vuln.get('description', 'No description')}")
                context.append(f"  Affected Systems: {vuln.get('affected_systems', 'Unknown')}")
                context.append(f"  Patch Status: {vuln.get('patch_status', 'Unknown')}")
                context.append("")
            for traffic in mock_data["network_traffic"]:
                context.append(f"- Source IP: {traffic.get('source_ip', 'Unknown')}")
                context.append(f"  Destination IP: {traffic.get('destination_ip', 'Unknown')}")
                context.append(f"  Protocol: {traffic.get('protocol', 'Unknown')}")
                context.append(f"  Timestamp: {traffic.get('timestamp', 'Unknown')}")
                context.append(f"  Flags: {traffic.get('flags', 'None')}")
                context.append(f"  Suspicious: {traffic.get('is_suspicious', 'Unknown')}")
                context.append("")
            for actor in mock_data["threat_actors"]:
                context.append(f"- Name: {actor.get('name', 'Unknown')}")
                context.append(f"  Motivation: {actor.get('motivation', 'Unknown')}")
                context.append(f"  TTPs: {actor.get('tactics_techniques_procedures', 'Unknown')}")
                context.append(f"  Associated Campaigns: {actor.get('associated_campaigns', 'Unknown')}")
                context.append("")
            for ioc in mock_data["indicators_of_compromise"]:
                context.append(f"- Type: {ioc.get('ioc_type', 'Unknown')}")
                context.append(f"  Value: {ioc.get('ioc_value', 'Unknown')}")
                context.append(f"  Confidence: {ioc.get('confidence', 'Unknown')}")
                context.append(f"  First Seen: {ioc.get('first_seen', 'Unknown')}")
                context.append(f"  Last Seen: {ioc.get('last_seen', 'Unknown')}")
                context.append("")
            return "\n".join(context)
        
        # Add OSINT data
        if threat_data["osint_data"]:
            context.append("## OSINT Intelligence")
            for item in threat_data["osint_data"]:
                context.append(f"- Source: {item.get('source', 'Unknown')}")
                context.append(f"  Description: {item.get('description', 'No description')}")
                context.append(f"  Timestamp: {item.get('timestamp', 'Unknown')}")
                context.append(f"  Confidence: {item.get('confidence_score', 'Unknown')}")
                context.append(f"  Threat Type: {item.get('threat_type', 'Unknown')}")
                context.append("")
            
        
        # Add vulnerability data
        if threat_data["vulnerabilities"]:
            context.append("## Vulnerabilities")
            for vuln in threat_data["vulnerabilities"]:
                context.append(f"- CVE ID: {vuln.get('cve_id', 'No CVE')}")
                context.append(f"  CVSS Score: {vuln.get('cvss_score', 'Unknown')}")
                context.append(f"  Description: {vuln.get('description', 'No description')}")
                context.append(f"  Affected Systems: {vuln.get('affected_systems', 'Unknown')}")
                context.append(f"  Patch Status: {vuln.get('patch_status', 'Unknown')}")
                context.append("")
        
        # Add network traffic data
        if threat_data["network_traffic"]:
            context.append("## Network Traffic Analysis")
            for traffic in threat_data["network_traffic"]:
                context.append(f"- Source IP: {traffic.get('source_ip', 'Unknown')}")
                context.append(f"  Destination IP: {traffic.get('destination_ip', 'Unknown')}")
                context.append(f"  Protocol: {traffic.get('protocol', 'Unknown')}")
                context.append(f"  Timestamp: {traffic.get('timestamp', 'Unknown')}")
                context.append(f"  Flags: {traffic.get('flags', 'None')}")
                context.append(f"  Suspicious: {traffic.get('is_suspicious', 'Unknown')}")
                context.append("")
        
        # Add threat actor information
        if threat_data["threat_actors"]:
            context.append("## Threat Actors")
            for actor in threat_data["threat_actors"]:
                context.append(f"- Name: {actor.get('name', 'Unknown')}")
                context.append(f"  Motivation: {actor.get('motivation', 'Unknown')}")
                context.append(f"  TTPs: {actor.get('tactics_techniques_procedures', 'Unknown')}")
                context.append(f"  Associated Campaigns: {actor.get('associated_campaigns', 'Unknown')}")
                context.append("")
        
        # Add indicators of compromise
        if threat_data["indicators_of_compromise"]:
            context.append("## Indicators of Compromise")
            for ioc in threat_data["indicators_of_compromise"]:
                context.append(f"- Type: {ioc.get('ioc_type', 'Unknown')}")
                context.append(f"  Value: {ioc.get('ioc_value', 'Unknown')}")
                context.append(f"  Confidence: {ioc.get('confidence', 'Unknown')}")
                context.append(f"  First Seen: {ioc.get('first_seen', 'Unknown')}")
                context.append(f"  Last Seen: {ioc.get('last_seen', 'Unknown')}")
                context.append("")
        
        return "\n".join(context)
    
    def generate_report(
        self,
        threat_data: Dict[str, Any],
        report_type: str = "comprehensive",
        max_length: int = 2048
    ) -> str:
        """
        Generate a threat intelligence report using the LLM.
        
        Args:
            threat_data: Dictionary containing all threat intel data
            report_type: Type of report to generate (e.g., "comprehensive", "executive", "technical")
            max_length: Maximum token length for generation
            
        Returns:
            Generated threat intelligence report
        """
        # Preprocess the data into a format suitable for the LLM
        context = self.preprocess_data(threat_data)

        # Log the context to see if it's empty
        logger.info(f"Preprocessed context length: {len(context)} characters")
        if len(context) < 50:  # Arbitrary small number
            logger.warning("Context is very short, may result in poor report generation")
            logger.debug(f"Context: {context}")
        
        # Create the prompt for the LLM
        if report_type == "executive":
            prompt = """You are an expert cybersecurity analyst tasked with creating an executive summary of threat intelligence.
Focus on high-level findings, business impact, and strategic recommendations.
Based on the following threat intelligence data, create a concise executive summary:

{context}

Generate an executive summary with the following sections:
1. Key Findings
2. Threat Landscape Overview
3. Business Impact Assessment
4. Strategic Recommendations
5. Priority Actions
"""
        elif report_type == "technical":
            prompt = """You are an expert cybersecurity analyst tasked with creating a detailed technical threat intelligence report.
Focus on technical details, TTPs, IOCs, and specific remediation steps.
Based on the following threat intelligence data, create a comprehensive technical report:

{context}

Generate a technical report with the following sections:
1. Technical Findings
2. Vulnerability Analysis
3. Threat Actor Tactics, Techniques, and Procedures
4. Indicators of Compromise Details
5. Recommended Technical Mitigations
6. Network Defense Recommendations
"""
        else:  # comprehensive
            prompt = """You are an expert cybersecurity analyst tasked with creating a comprehensive threat intelligence report.
Analyze the following threat intelligence data and create a well-structured report that identifies 
patterns, highlights critical threats, provides context, and offers actionable recommendations.

{context}

Generate a comprehensive threat intelligence report with the following sections:
1. Executive Summary
2. Key Findings
3. Threat Actor Analysis
4. Vulnerability Assessment
5. Network Traffic Analysis
6. Indicators of Compromise
7. Impact Analysis
8. Recommendations and Mitigations
9. Conclusion
"""
        
        # Fill in the context
        prompt = prompt.format(context=context)
        # Log the final prompt size
        logger.info(f"Final prompt length: {len(prompt)} characters")
        
        logger.info(f"Generating {report_type} report")
        
        response = self.client.generate(
            prompt=prompt,
            max_length=max_length,
            temperature=0.7,
            top_p=0.9
        )
        
        if 'error' in response:
            logger.error(f"Error from LLM server: {response['error']}")
            return f"Error generating report: {response['error']}"
        
        # Extract the generated text from the response
        report = response.get('generated_text', '').strip()
        
        logger.info(f"Report generation complete: {len(report)} characters")
        return report
    
    def save_report(self, report, report_type, days_range=30, threat_types=None):
        """
        Save a generated report to the filesystem and database
        
        Args:
            report: Report content
            report_type: Type of report (comprehensive, executive, technical, etc.)
            days_range: Number of days the report covers
            threat_types: List of threat types included in the report
            
        Returns:
            filepath: Path to the saved report file
        """
        # Create a unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"{report_type}_report_{timestamp}"
        filename = f"{report_name}.txt"  # or .pdf, .txt depending on your implementation
        
        # Save to filesystem (adjust path as needed)
        reports_dir = app.config['REPORTS_DIR']
        filepath = os.path.join(reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # Save to database
        relative_path = os.path.join('static', 'reports', filename)
        
        # Convert threat_types list to string for storage
        threat_types_str = ','.join(threat_types) if threat_types else ''
        
        with app.db_manager.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO reports (name, type, filepath, days_range, threat_types)
                VALUES (%s, %s, %s, %s, %s)
            """, (report_name, report_type, relative_path, days_range, threat_types_str))
        
        return relative_path