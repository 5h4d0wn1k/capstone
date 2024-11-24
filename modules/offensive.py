import nmap
import socket
import ssl
import threading
from queue import Queue
from loguru import logger
import requests
import concurrent.futures
from typing import Dict, List, Optional
import platform
import subprocess
import os

class OffensiveTools:
    def __init__(self, config: Dict):
        self.config = config
        self.scan_queue = Queue()
        self.results_queue = Queue()
        self.workers = []
        self.max_workers = config.get('num_workers', 5)
        self.running = False
        self.initialize_scanner()
        
    def initialize_scanner(self):
        """Initialize network scanner with fallback options"""
        try:
            self.nm = nmap.PortScanner()
            logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            logger.warning(f"Nmap not available: {e}. Using fallback scanning method.")
            self.nm = None
            
        # Initialize additional scanning capabilities
        self.initialize_ssl_scanner()
        self.initialize_credential_checker()
        
    def initialize_ssl_scanner(self):
        """Initialize SSL/TLS scanner"""
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    def initialize_credential_checker(self):
        """Initialize default credential checker"""
        self.default_credentials = self.config.get('default_credentials', [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'root', 'password': 'root'}
        ])
        
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
