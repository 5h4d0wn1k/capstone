import nmap
import socket
import ssl
import threading
from queue import Queue
from loguru import logger
import requests
import concurrent.futures
from typing import Dict, List, Optional, Union
import platform
import subprocess
import os
import json
from datetime import datetime, timedelta

# Optional imports
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    logger.warning("Yara module not available. Some features will be disabled.")
    YARA_AVAILABLE = False

try:
    from virustotal_api import VirusTotal
    VT_AVAILABLE = True
except ImportError:
    logger.warning("VirusTotal API not available. Some features will be disabled.")
    VT_AVAILABLE = False

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    logger.warning("Elasticsearch not available. Some features will be disabled.")
    ES_AVAILABLE = False

try:
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    logger.warning("Machine learning modules not available. Some features will be disabled.")
    ML_AVAILABLE = False

class OffensiveTools:
    def __init__(self, config: Dict):
        self.config = config
        self.scan_queue = Queue()
        self.results_queue = Queue()
        self.workers = []
        self.max_workers = config.get('num_workers', 5)
        self.running = False
        self.es_client = None
        self.vt_client = None
        self.yara_rules = {}
        self.ml_models = {}
        self.initialize_components()
        
    def initialize_components(self):
        """Initialize all offensive security components"""
        self.initialize_scanner()
        self.initialize_threat_intel()
        self.initialize_ml_models()
        if YARA_AVAILABLE:
            self.initialize_yara_rules()
        self.initialize_vulnerability_scanner()
        
    def initialize_scanner(self):
        """Initialize enhanced network scanner"""
        try:
            self.nm = nmap.PortScanner()
            # Enable advanced scanning features
            self.nm.scan_techniques = ['-sS', '-sV', '-sC', '-A']
            logger.info("Nmap scanner initialized with advanced features")
        except Exception as e:
            logger.warning(f"Nmap not available: {e}. Using fallback scanning method.")
            self.nm = None

    def initialize_threat_intel(self):
        """Initialize threat intelligence components"""
        try:
            # Initialize VirusTotal API
            vt_api_key = self.config.get('virustotal_api_key')
            if vt_api_key and VT_AVAILABLE:
                self.vt_client = VirusTotal(vt_api_key)
            
            # Initialize Elasticsearch for threat intel storage
            es_config = self.config.get('elasticsearch', {})
            if es_config and ES_AVAILABLE:
                self.es_client = Elasticsearch([es_config['host']], 
                                            http_auth=(es_config['user'], es_config['password']))
        except Exception as e:
            logger.error(f"Failed to initialize threat intel components: {e}")

    def initialize_ml_models(self):
        """Initialize machine learning models for threat detection"""
        try:
            # Initialize anomaly detection model
            if ML_AVAILABLE:
                self.ml_models['anomaly_detector'] = IsolationForest(
                    contamination=0.1,
                    random_state=42
                )
            
            # Load pre-trained models if available
            model_path = self.config.get('ml_models_path')
            if model_path and os.path.exists(model_path) and ML_AVAILABLE:
                self.load_pretrained_models(model_path)
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    def initialize_yara_rules(self):
        """Initialize YARA rules for malware detection"""
        try:
            rules_path = self.config.get('yara_rules_path')
            if rules_path and os.path.exists(rules_path):
                for rule_file in os.listdir(rules_path):
                    if rule_file.endswith('.yar'):
                        rule_path = os.path.join(rules_path, rule_file)
                        self.yara_rules[rule_file] = yara.compile(rule_path)
        except Exception as e:
            logger.error(f"Failed to initialize YARA rules: {e}")

    def advanced_scan(self, target: str, scan_type: str = 'full') -> Dict:
        """Perform advanced scanning with multiple techniques"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'findings': []
        }
        
        try:
            if scan_type == 'full' or scan_type == 'network':
                results['network_scan'] = self.perform_network_scan(target)
            
            if scan_type == 'full' or scan_type == 'vulnerability':
                results['vulnerability_scan'] = self.perform_vulnerability_scan(target)
            
            if scan_type == 'full' or scan_type == 'malware':
                results['malware_scan'] = self.perform_malware_scan(target)
            
            # Enrich results with threat intelligence
            results['threat_intel'] = self.enrich_with_threat_intel(results)
            
            # Analyze results with ML models
            if ML_AVAILABLE:
                results['ml_analysis'] = self.analyze_with_ml(results)
            
            # Store results in Elasticsearch
            if self.es_client:
                self.store_scan_results(results)
                
        except Exception as e:
            logger.error(f"Advanced scan failed: {e}")
            results['error'] = str(e)
            
        return results

    def perform_network_scan(self, target: str) -> Dict:
        """Perform comprehensive network scan"""
        results = {}
        if self.nm:
            try:
                # Perform comprehensive network scan
                self.nm.scan(target, arguments='-sS -sV -sC -A -p-')
                results = self.nm.analyse_nmap_xml_scan()
                
                # Additional custom port scanning
                results['custom_ports'] = self.scan_custom_ports(target)
            except Exception as e:
                logger.error(f"Network scan failed: {e}")
                results['error'] = str(e)
        return results

    def perform_vulnerability_scan(self, target: str) -> Dict:
        """Perform vulnerability assessment"""
        results = {
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        try:
            # Implement various vulnerability checks
            results['vulnerabilities'].extend(self.check_common_vulnerabilities(target))
            results['vulnerabilities'].extend(self.check_misconfigurations(target))
            results['vulnerabilities'].extend(self.check_default_credentials(target))
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results['vulnerabilities'])
            
            # Generate recommendations
            results['recommendations'] = self.generate_recommendations(results['vulnerabilities'])
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            results['error'] = str(e)
            
        return results

    def perform_malware_scan(self, target: str) -> Dict:
        """Perform malware and suspicious behavior detection"""
        results = {
            'malware_detected': [],
            'suspicious_behaviors': [],
            'yara_matches': []
        }
        
        try:
            # Scan with YARA rules
            if YARA_AVAILABLE and self.yara_rules:
                for rule_name, rule in self.yara_rules.items():
                    matches = rule.match(target)
                    if matches:
                        results['yara_matches'].extend(matches)
            
            # Check for suspicious behaviors
            results['suspicious_behaviors'] = self.detect_suspicious_behaviors(target)
            
            # Scan with VirusTotal if available
            if self.vt_client:
                vt_results = self.scan_with_virustotal(target)
                results['virustotal'] = vt_results
                
        except Exception as e:
            logger.error(f"Malware scan failed: {e}")
            results['error'] = str(e)
            
        return results

    def analyze_with_ml(self, data: Dict) -> Dict:
        """Analyze scan results using machine learning models"""
        analysis_results = {
            'anomalies': [],
            'threat_score': 0,
            'predictions': {}
        }
        
        try:
            # Prepare features for ML analysis
            features = self.extract_features(data)
            
            # Perform anomaly detection
            if 'anomaly_detector' in self.ml_models:
                predictions = self.ml_models['anomaly_detector'].predict(features)
                analysis_results['anomalies'] = self.process_anomalies(predictions, data)
            
            # Calculate threat score
            analysis_results['threat_score'] = self.calculate_threat_score(analysis_results['anomalies'])
            
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            analysis_results['error'] = str(e)
            
        return analysis_results

    def store_scan_results(self, results: Dict):
        """Store scan results in Elasticsearch"""
        try:
            if self.es_client:
                index_name = f"siem-offensive-{datetime.now().strftime('%Y.%m')}"
                self.es_client.index(
                    index=index_name,
                    body=results
                )
        except Exception as e:
            logger.error(f"Failed to store results in Elasticsearch: {e}")

    def start_scan_workers(self):
        """Start worker threads for scanning"""
        for _ in range(self.max_workers):
            worker = threading.Thread(target=self._scan_worker, daemon=True)
            worker.start()
            self.workers.append(worker)
            
    def _scan_worker(self):
        """Worker thread for scanning targets"""
        while True:
            try:
                target = self.scan_queue.get()
                if target is None:
                    break
                    
                results = self.scan_host(target)
                self.results_queue.put(results)
                
            except Exception as e:
                logger.error(f"Worker error: {e}")
            finally:
                self.scan_queue.task_done()
                
    def stop_workers(self):
        """Stop all worker threads"""
        for _ in self.workers:
            self.scan_queue.put(None)
        for worker in self.workers:
            worker.join()
        self.workers = []

    def start(self):
        """Start offensive tools and scanning"""
        logger.info("Starting offensive tools")
        self.running = True
        
        # Start worker threads
        for _ in range(self.max_workers):
            worker = threading.Thread(target=self._scan_worker, daemon=True)
            worker.start()
            self.workers.append(worker)
            
    def stop(self):
        """Stop offensive tools and scanning"""
        logger.info("Stopping offensive tools")
        self.running = False
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        self.workers.clear()

    def scan_host(self, target: str, ports: str = None) -> Dict:
        """Scan a host using available methods"""
        results = {'target': target, 'ports': {}, 'vulnerabilities': []}
        
        if self.nm:
            try:
                # Use Nmap if available
                args = self.config.get('scan_options', {}).get('arguments', '-sV -sC')
                self.nm.scan(target, ports, arguments=args)
                if target in self.nm.all_hosts():
                    results['ports'] = self.nm[target]['tcp']
            except Exception as e:
                logger.error(f"Nmap scan failed: {e}. Falling back to basic port scan.")
                
        # Fallback to basic port scanning if Nmap fails or isn't available
        if not results['ports']:
            results['ports'] = self.basic_port_scan(target, ports)
            
        # Additional security checks
        results['ssl_info'] = self.check_ssl_vulnerabilities(target)
        results['default_creds'] = self.check_default_credentials(target)
        
        return results
    
    def basic_port_scan(self, target: str, ports: str = None) -> Dict:
        """Basic port scanner using sockets"""
        results = {}
        port_list = self.parse_ports(ports)
        
        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.identify_service(target, port)
                    results[port] = {
                        'state': 'open',
                        'service': service
                    }
                sock.close()
            except Exception as e:
                logger.debug(f"Port scan error on {target}:{port} - {e}")
                
        return results
    
    def identify_service(self, target: str, port: int) -> str:
        """Attempt to identify service on port"""
        common_ports = {
            80: 'http',
            443: 'https',
            22: 'ssh',
            21: 'ftp',
            3389: 'rdp',
            445: 'smb'
        }
        return common_ports.get(port, 'unknown')
    
    def check_ssl_vulnerabilities(self, target: str) -> Dict:
        """Check for SSL/TLS vulnerabilities"""
        results = {'has_ssl': False, 'vulnerabilities': []}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    results['has_ssl'] = True
                    results['cert_info'] = cert
        except Exception as e:
            logger.debug(f"SSL check failed for {target}: {e}")
        return results
    
    def check_default_credentials(self, target: str) -> List[Dict]:
        """Check for default credentials on common services"""
        results = []
        web_ports = [80, 443, 8080]
        
        for port in web_ports:
            try:
                url = f"http{'s' if port == 443 else ''}://{target}:{port}"
                for cred in self.default_credentials:
                    response = requests.get(url, auth=(cred['username'], cred['password']), timeout=5)
                    if response.status_code == 200:
                        results.append({
                            'port': port,
                            'credentials': cred,
                            'service': 'http'
                        })
            except Exception as e:
                logger.debug(f"Credential check failed for {target}:{port} - {e}")
                
        return results
    
    def parse_ports(self, ports: str) -> List[int]:
        """Parse port string into list of ports"""
        if not ports:
            return [20, 21, 22, 23, 25, 53, 80, 443, 445, 3389]
        
        port_list = []
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))
        return port_list
