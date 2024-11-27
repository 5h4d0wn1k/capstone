#!/usr/bin/env python3

import nmap
import scapy.all as scapy
from typing import Dict, List, Any, Optional
import logging
import asyncio
import aiohttp
import ssl
import socket
import paramiko
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import yaml
import subprocess
from pathlib import Path

class OffensiveTools:
    def __init__(self, config: Dict[str, Any]):
        """Initialize offensive security testing tools"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        self.executor = ThreadPoolExecutor(max_workers=10)
        
    async def perform_network_scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform comprehensive network scan"""
        try:
            # Nmap scan
            self.logger.info(f"Starting network scan on {target}")
            self.nm.scan(target, ports, arguments="-sS -sV -O -A")
            
            results = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'hosts': {}
            }
            
            for host in self.nm.all_hosts():
                host_info = {
                    'state': self.nm[host].state(),
                    'os': self.nm[host].get('osmatch', []),
                    'ports': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        host_info['ports'][port] = {
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                
                results['hosts'][host] = host_info
            
            return results
            
        except Exception as e:
            self.logger.error(f"Network scan failed: {str(e)}")
            raise
    
    async def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Perform vulnerability scan using various tools"""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'vulnerabilities': []
            }
            
            # Basic port scan
            open_ports = await self.scan_ports(target)
            results['open_ports'] = open_ports
            
            # Service enumeration
            services = await self.enumerate_services(target, open_ports)
            results['services'] = services
            
            # Web vulnerability scan
            if 80 in open_ports or 443 in open_ports:
                web_vulns = await self.web_vulnerability_scan(target)
                results['vulnerabilities'].extend(web_vulns)
            
            # SSH testing if port 22 is open
            if 22 in open_ports:
                ssh_vulns = await self.test_ssh_security(target)
                results['vulnerabilities'].extend(ssh_vulns)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan failed: {str(e)}")
            raise
    
    async def scan_ports(self, target: str, start_port: int = 1, end_port: int = 1000) -> List[int]:
        """Scan for open ports"""
        open_ports = []
        
        async def check_port(port: int):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        
        tasks = [check_port(port) for port in range(start_port, end_port + 1)]
        await asyncio.gather(*tasks)
        return sorted(open_ports)
    
    async def enumerate_services(self, target: str, ports: List[int]) -> Dict[int, Dict]:
        """Enumerate services running on open ports"""
        services = {}
        
        for port in ports:
            try:
                service_info = await self.identify_service(target, port)
                services[port] = service_info
            except Exception as e:
                self.logger.error(f"Service enumeration failed for port {port}: {str(e)}")
        
        return services
    
    async def identify_service(self, target: str, port: int) -> Dict[str, str]:
        """Identify service running on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
            # Send HTTP request if common web ports
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024)
            sock.close()
            
            return {
                'banner': banner.decode('utf-8', errors='ignore'),
                'service': self.guess_service(port, banner)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def guess_service(self, port: int, banner: bytes) -> str:
        """Guess service based on port and banner"""
        common_ports = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }
        
        return common_ports.get(port, 'Unknown')
    
    async def web_vulnerability_scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan for common web vulnerabilities"""
        vulnerabilities = []
        
        # Test for common vulnerabilities
        tests = [
            self.test_sql_injection,
            self.test_xss,
            self.test_directory_traversal,
            self.test_default_credentials
        ]
        
        for test in tests:
            try:
                results = await test(target)
                vulnerabilities.extend(results)
            except Exception as e:
                self.logger.error(f"Web vulnerability test failed: {str(e)}")
        
        return vulnerabilities
    
    async def test_sql_injection(self, target: str) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        payloads = ["' OR '1'='1", "1' OR '1'='1", "1; DROP TABLE users"]
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    async with session.get(f"http://{target}/?id={payload}") as response:
                        if "error" in await response.text().lower():
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'payload': payload,
                                'url': str(response.url),
                                'severity': 'High'
                            })
                except Exception as e:
                    self.logger.error(f"SQL injection test failed: {str(e)}")
        
        return vulnerabilities
    
    async def test_xss(self, target: str) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    async with session.get(f"http://{target}/?q={payload}") as response:
                        if payload in await response.text():
                            vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'payload': payload,
                                'url': str(response.url),
                                'severity': 'High'
                            })
                except Exception as e:
                    self.logger.error(f"XSS test failed: {str(e)}")
        
        return vulnerabilities
    
    async def test_directory_traversal(self, target: str) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd"
        ]
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    async with session.get(f"http://{target}/files?path={payload}") as response:
                        content = await response.text()
                        if "root:" in content or "[extensions]" in content:
                            vulnerabilities.append({
                                'type': 'Directory Traversal',
                                'payload': payload,
                                'url': str(response.url),
                                'severity': 'High'
                            })
                except Exception as e:
                    self.logger.error(f"Directory traversal test failed: {str(e)}")
        
        return vulnerabilities
    
    async def test_default_credentials(self, target: str) -> List[Dict[str, Any]]:
        """Test for default credentials"""
        common_creds = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', 'password'),
            ('administrator', 'administrator')
        ]
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for username, password in common_creds:
                try:
                    async with session.post(
                        f"http://{target}/login",
                        data={'username': username, 'password': password}
                    ) as response:
                        if response.status == 200 and "welcome" in (await response.text()).lower():
                            vulnerabilities.append({
                                'type': 'Default Credentials',
                                'credentials': f'{username}:{password}',
                                'url': str(response.url),
                                'severity': 'Critical'
                            })
                except Exception as e:
                    self.logger.error(f"Default credentials test failed: {str(e)}")
        
        return vulnerabilities
    
    async def test_ssh_security(self, target: str) -> List[Dict[str, Any]]:
        """Test SSH security configuration"""
        vulnerabilities = []
        
        try:
            transport = paramiko.Transport((target, 22))
            transport.start_client()
            
            # Check supported algorithms
            kex_algorithms = transport.get_security_options().kex
            ciphers = transport.get_security_options().ciphers
            
            # Check for weak algorithms
            weak_kex = [k for k in kex_algorithms if 'sha1' in k or 'md5' in k]
            weak_ciphers = [c for c in ciphers if '3des' in c.lower() or 'arcfour' in c.lower()]
            
            if weak_kex:
                vulnerabilities.append({
                    'type': 'Weak SSH KEX Algorithm',
                    'algorithms': weak_kex,
                    'severity': 'Medium'
                })
            
            if weak_ciphers:
                vulnerabilities.append({
                    'type': 'Weak SSH Cipher',
                    'ciphers': weak_ciphers,
                    'severity': 'Medium'
                })
            
            transport.close()
            
        except Exception as e:
            self.logger.error(f"SSH security test failed: {str(e)}")
        
        return vulnerabilities
    
    def generate_report(self, results: Dict[str, Any], output_file: str):
        """Generate detailed report of findings"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_hosts': len(results.get('hosts', {})),
                    'total_vulnerabilities': len(results.get('vulnerabilities', [])),
                    'critical_vulnerabilities': len([v for v in results.get('vulnerabilities', []) 
                                                   if v.get('severity') == 'Critical']),
                    'high_vulnerabilities': len([v for v in results.get('vulnerabilities', []) 
                                               if v.get('severity') == 'High'])
                },
                'details': results
            }
            
            # Save report
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Report generated: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            raise
