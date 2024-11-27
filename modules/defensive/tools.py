"""Defensive security tools implementation."""

import os
import sys
import subprocess
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
import platform
from loguru import logger
import psutil
import winreg
import win32security
import win32api
import win32con
import win32file
import win32process
import ntsecuritycon
import hashlib

class DefensiveTools:
    """Windows defensive security tools."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize defensive tools.
        
        Args:
            config: Tool configuration
        """
        self.config = config
        self.enabled = config.get("enabled", True)
        self.initialize_tools()
        
    def initialize_tools(self) -> None:
        """Initialize defensive tools and required privileges."""
        try:
            # Get process token
            process = win32api.GetCurrentProcess()
            token = win32security.OpenProcessToken(
                process,
                win32security.TOKEN_ALL_ACCESS
            )
            
            # Enable required privileges
            privileges = [
                win32security.LookupPrivilegeValue(
                    None, win32security.SE_SECURITY_NAME
                ),
                win32security.LookupPrivilegeValue(
                    None, win32security.SE_BACKUP_NAME
                ),
                win32security.LookupPrivilegeValue(
                    None, win32security.SE_RESTORE_NAME
                ),
                win32security.LookupPrivilegeValue(
                    None, win32security.SE_TAKE_OWNERSHIP_NAME
                )
            ]
            
            # Adjust token privileges
            for privilege in privileges:
                win32security.AdjustTokenPrivileges(
                    token, 0,
                    [(privilege, win32security.SE_PRIVILEGE_ENABLED)]
                )
                
            logger.info("Initialized defensive tools with required privileges")
            
        except Exception as e:
            logger.error(f"Error initializing defensive tools: {e}")
            
    def harden_registry(self) -> Dict[str, Any]:
        """Apply security hardening to Windows Registry.
        
        Returns:
            Status dictionary
        """
        results = {
            "success": True,
            "changes": [],
            "errors": []
        }
        
        try:
            # Registry hardening settings
            hardening_settings = {
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System": {
                    "EnableLUA": 1,  # Enable UAC
                    "ConsentPromptBehaviorAdmin": 2,  # Prompt for consent
                    "PromptOnSecureDesktop": 1,  # Use secure desktop
                    "EnableInstallerDetection": 1,  # Detect installer elevation
                    "EnableSecureUIAPaths": 1,  # Use secure UI paths
                    "EnableVirtualization": 1  # Enable virtualization
                },
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer": {
                    "NoAutorun": 1,  # Disable autorun
                    "NoDriveTypeAutoRun": 255  # Disable autorun for all drives
                },
                r"SYSTEM\CurrentControlSet\Control\Lsa": {
                    "LimitBlankPasswordUse": 1,  # Limit blank password use
                    "NoLMHash": 1,  # Disable LM hash
                    "RestrictAnonymous": 1,  # Restrict anonymous access
                    "RestrictAnonymousSAM": 1  # Restrict anonymous SAM access
                }
            }
            
            # Apply settings
            for key_path, settings in hardening_settings.items():
                try:
                    # Open or create key
                    key = winreg.CreateKeyEx(
                        winreg.HKEY_LOCAL_MACHINE,
                        key_path,
                        0,
                        winreg.KEY_ALL_ACCESS
                    )
                    
                    # Set values
                    for name, value in settings.items():
                        try:
                            winreg.SetValueEx(
                                key,
                                name,
                                0,
                                winreg.REG_DWORD,
                                value
                            )
                            results["changes"].append(
                                f"Set {key_path}\\{name} = {value}"
                            )
                        except Exception as e:
                            results["errors"].append(
                                f"Error setting {name}: {e}"
                            )
                            
                    winreg.CloseKey(key)
                    
                except Exception as e:
                    results["errors"].append(
                        f"Error accessing key {key_path}: {e}"
                    )
                    
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Registry hardening failed: {e}")
            
        return results
        
    def harden_filesystem(self) -> Dict[str, Any]:
        """Apply security hardening to filesystem.
        
        Returns:
            Status dictionary
        """
        results = {
            "success": True,
            "changes": [],
            "errors": []
        }
        
        try:
            # Critical system directories to harden
            critical_dirs = [
                r"C:\Windows\System32",
                r"C:\Windows\SysWOW64",
                r"C:\Program Files",
                r"C:\Program Files (x86)"
            ]
            
            # Get Administrators group SID
            admins_sid = win32security.ConvertStringSidToSid(
                "S-1-5-32-544"
            )
            
            # Get SYSTEM SID
            system_sid = win32security.ConvertStringSidToSid(
                "S-1-5-18"
            )
            
            for directory in critical_dirs:
                try:
                    if not os.path.exists(directory):
                        continue
                        
                    # Get security descriptor
                    sd = win32security.GetFileSecurity(
                        directory,
                        win32security.DACL_SECURITY_INFORMATION
                    )
                    
                    # Create new DACL
                    dacl = win32security.ACL()
                    
                    # Add ACEs for Administrators and SYSTEM
                    for sid in [admins_sid, system_sid]:
                        dacl.AddAccessAllowedAce(
                            win32security.ACL_REVISION,
                            ntsecuritycon.FILE_ALL_ACCESS,
                            sid
                        )
                        
                    # Set new DACL
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(
                        directory,
                        win32security.DACL_SECURITY_INFORMATION,
                        sd
                    )
                    
                    results["changes"].append(
                        f"Hardened permissions for {directory}"
                    )
                    
                except Exception as e:
                    results["errors"].append(
                        f"Error hardening {directory}: {e}"
                    )
                    
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Filesystem hardening failed: {e}")
            
        return results
        
    def harden_network(self) -> Dict[str, Any]:
        """Apply network security hardening.
        
        Returns:
            Status dictionary
        """
        results = {
            "success": True,
            "changes": [],
            "errors": []
        }
        
        try:
            # Windows Firewall rules
            firewall_rules = [
                # Block inbound by default
                "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
                
                # Enable Windows Firewall
                "netsh advfirewall set allprofiles state on",
                
                # Block common attack vectors
                "netsh advfirewall firewall add rule name='Block RDP Brute Force' dir=in action=block protocol=tcp localport=3389",
                "netsh advfirewall firewall add rule name='Block SMB' dir=in action=block protocol=tcp localport=445",
                "netsh advfirewall firewall add rule name='Block NetBIOS' dir=in action=block protocol=tcp localport=137-139"
            ]
            
            # Apply firewall rules
            for rule in firewall_rules:
                try:
                    subprocess.run(
                        rule,
                        shell=True,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    results["changes"].append(f"Applied firewall rule: {rule}")
                except subprocess.CalledProcessError as e:
                    results["errors"].append(
                        f"Error applying firewall rule: {e.stderr}"
                    )
                    
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Network hardening failed: {e}")
            
        return results
        
    def harden_services(self) -> Dict[str, Any]:
        """Harden Windows services configuration.
        
        Returns:
            Status dictionary
        """
        results = {
            "success": True,
            "changes": [],
            "errors": []
        }
        
        try:
            # Services to disable
            services_to_disable = [
                "RemoteRegistry",  # Remote Registry
                "TlntSvr",        # Telnet
                "SNMP",           # SNMP Service
                "SharedAccess",   # Internet Connection Sharing
                "RpcLocator",     # Remote Procedure Call Locator
                "RemoteAccess",   # Routing and Remote Access
                "WinRM"          # Windows Remote Management
            ]
            
            # Disable services
            for service in services_to_disable:
                try:
                    subprocess.run(
                        f"sc config {service} start= disabled",
                        shell=True,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    subprocess.run(
                        f"sc stop {service}",
                        shell=True,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    results["changes"].append(f"Disabled service: {service}")
                except subprocess.CalledProcessError as e:
                    results["errors"].append(
                        f"Error disabling service {service}: {e.stderr}"
                    )
                    
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Service hardening failed: {e}")
            
        return results
        
    def apply_security_baseline(self) -> Dict[str, Any]:
        """Apply comprehensive security baseline.
        
        Returns:
            Status dictionary
        """
        results = {
            "success": True,
            "timestamp": datetime.utcnow().isoformat(),
            "components": {}
        }
        
        # Apply all hardening measures
        components = [
            ("registry", self.harden_registry),
            ("filesystem", self.harden_filesystem),
            ("network", self.harden_network),
            ("services", self.harden_services)
        ]
        
        for name, func in components:
            try:
                component_results = func()
                results["components"][name] = component_results
                if not component_results["success"]:
                    results["success"] = False
            except Exception as e:
                results["components"][name] = {
                    "success": False,
                    "error": str(e)
                }
                results["success"] = False
                
        return results
        
    def analyze_traffic(self) -> list:
        """Analyze network traffic for potential threats.
        
        Returns:
            List of analyzed traffic entries
        """
        traffic = self.get_network_traffic()
        analyzed_traffic = []
        
        for entry in traffic:
            analysis = {
                'timestamp': datetime.utcnow().isoformat(),
                'source': entry['src'],
                'destination': entry['dst'],
                'port': entry['port'],
                'risk_level': self._assess_traffic_risk(entry)
            }
            analyzed_traffic.append(analysis)
            
        return analyzed_traffic
        
    def detect_threats(self, log_entry: Dict[str, Any]) -> float:
        """Detect potential threats from log entries.
        
        Args:
            log_entry: Log entry to analyze
            
        Returns:
            Threat level (0-100)
        """
        threat_level = 0
        
        # Check for failed login attempts
        if log_entry.get('event_type') == 'login_attempt' and log_entry.get('status') == 'failed':
            attempts = log_entry.get('attempts', 1)
            threat_level += min(attempts * 20, 100)  # 20 points per attempt, max 100
            
        # Add source IP to watchlist if threat level is high
        if threat_level >= self.config.get('alert_threshold', 80):
            self._add_to_watchlist(log_entry.get('source_ip'))
            
        return threat_level
        
    def analyze_logs(self) -> list:
        """Analyze system logs for security events.
        
        Returns:
            List of analyzed log entries
        """
        logs = self.get_system_logs()
        analyzed_logs = []
        
        for entry in logs:
            analysis = {
                'timestamp': datetime.utcnow().isoformat(),
                'type': entry['type'],
                'message': entry['message'],
                'severity': self._assess_log_severity(entry)
            }
            analyzed_logs.append(analysis)
            
        return analyzed_logs
        
    def add_firewall_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new firewall rule.
        
        Args:
            rule: Firewall rule configuration
            
        Returns:
            True if rule was added successfully
        """
        try:
            self._firewall_rules.append(rule)
            return True
        except Exception as e:
            logger.error(f"Error adding firewall rule: {e}")
            return False
            
    def get_firewall_rules(self) -> list:
        """Get current firewall rules.
        
        Returns:
            List of firewall rules
        """
        return self._firewall_rules
        
    def handle_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Handle security incident.
        
        Args:
            incident: Incident details
            
        Returns:
            Response actions taken
        """
        response = {
            'timestamp': datetime.utcnow().isoformat(),
            'incident_type': incident['type'],
            'source': incident['source'],
            'action_taken': []
        }
        
        # Handle brute force attempts
        if incident['type'] == 'brute_force':
            # Block source IP
            self.add_firewall_rule({
                'action': 'block',
                'source_ip': incident['source'],
                'reason': 'brute force attempt'
            })
            response['action_taken'].append('blocked_source_ip')
            
            # Add to watchlist
            self._add_to_watchlist(incident['source'])
            response['action_taken'].append('added_to_watchlist')
            
        return response
        
    def _assess_traffic_risk(self, traffic: Dict[str, Any]) -> int:
        """Assess risk level of network traffic.
        
        Args:
            traffic: Traffic entry to assess
            
        Returns:
            Risk level (0-100)
        """
        risk_level = 0
        
        # Check for suspicious ports
        suspicious_ports = {22, 23, 3389, 445}
        if traffic['port'] in suspicious_ports:
            risk_level += 30
            
        # Check if source is in watchlist
        if traffic['src'] in self._watchlist:
            risk_level += 50
            
        return min(risk_level, 100)
        
    def _assess_log_severity(self, log_entry: Dict[str, Any]) -> int:
        """Assess severity of log entry.
        
        Args:
            log_entry: Log entry to assess
            
        Returns:
            Severity level (0-100)
        """
        severity = 0
        
        if log_entry['type'] == 'error':
            severity += 70
        elif log_entry['type'] == 'warning':
            severity += 40
            
        if 'unauthorized' in log_entry['message'].lower():
            severity += 30
            
        return min(severity, 100)
        
    def _add_to_watchlist(self, ip_address: str) -> None:
        """Add IP address to watchlist.
        
        Args:
            ip_address: IP address to add
        """
        if not hasattr(self, '_watchlist'):
            self._watchlist = set()
            
        self._watchlist.add(ip_address)
        logger.info(f"Added {ip_address} to watchlist")
        
    def get_network_traffic(self) -> list:
        """Get current network traffic.
        
        Returns:
            List of network traffic entries
        """
        # Implement logic to get network traffic
        pass
        
    def get_system_logs(self) -> list:
        """Get system logs.
        
        Returns:
            List of system log entries
        """
        # Implement logic to get system logs
        pass
        
    def monitor_processes(self) -> Dict[str, Any]:
        """Monitor running processes for suspicious activity.
        
        Returns:
            Monitoring results
        """
        results = {
            "success": True,
            "suspicious": [],
            "errors": []
        }
        
        try:
            # Get all running processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Check each process
            for proc in processes:
                try:
                    suspicious = False
                    reasons = []
                    
                    # Check if process is running as SYSTEM
                    if proc['username'] and 'SYSTEM' in proc['username'].upper():
                        suspicious = True
                        reasons.append("Running as SYSTEM")
                        
                    # Check for suspicious process names
                    suspicious_names = [
                        'mimikatz', 'psexec', 'netcat', 'powersploit',
                        'metasploit', 'meterpreter', 'empire'
                    ]
                    
                    if proc['name']:
                        name_lower = proc['name'].lower()
                        for sus_name in suspicious_names:
                            if sus_name in name_lower:
                                suspicious = True
                                reasons.append(f"Suspicious process name: {sus_name}")
                                
                    # Check command line for suspicious patterns
                    if proc['cmdline']:
                        cmdline = ' '.join(proc['cmdline']).lower()
                        suspicious_patterns = [
                            '-encode', 'bypass', 'downloadstring',
                            'hidden', 'secretsdump', 'hashdump'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if pattern in cmdline:
                                suspicious = True
                                reasons.append(f"Suspicious command line: {pattern}")
                                
                    if suspicious:
                        results["suspicious"].append({
                            "pid": proc['pid'],
                            "name": proc['name'],
                            "username": proc['username'],
                            "cmdline": proc['cmdline'],
                            "reasons": reasons
                        })
                        
                except Exception as e:
                    results["errors"].append(
                        f"Error checking process {proc.get('pid')}: {e}"
                    )
                    
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Process monitoring failed: {e}")
            
        return results
        
    def check_file_integrity(self, paths: List[str]) -> Dict[str, Any]:
        """Check file integrity of critical system files.
        
        Args:
            paths: List of file paths to check
            
        Returns:
            Integrity check results
        """
        results = {
            "success": True,
            "changes": [],
            "errors": []
        }
        
        try:
            import hashlib
            
            # Load or create integrity database
            db_path = os.path.join(
                os.path.dirname(__file__),
                'data',
                'integrity_db.json'
            )
            
            if os.path.exists(db_path):
                try:
                    with open(db_path, 'r') as f:
                        integrity_db = json.load(f)
                except:
                    integrity_db = {}
            else:
                integrity_db = {}
                
            # Check each path
            for path in paths:
                try:
                    if not os.path.exists(path):
                        results["errors"].append(f"Path not found: {path}")
                        continue
                        
                    # Calculate current hash
                    hasher = hashlib.sha256()
                    with open(path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b''):
                            hasher.update(chunk)
                    current_hash = hasher.hexdigest()
                    
                    # Get file metadata
                    stat = os.stat(path)
                    current_meta = {
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                        'mode': stat.st_mode
                    }
                    
                    # Compare with stored values
                    if path in integrity_db:
                        stored = integrity_db[path]
                        if current_hash != stored['hash']:
                            results["changes"].append({
                                "path": path,
                                "type": "content",
                                "old_hash": stored['hash'],
                                "new_hash": current_hash
                            })
                            
                        if current_meta != stored['metadata']:
                            results["changes"].append({
                                "path": path,
                                "type": "metadata",
                                "old_meta": stored['metadata'],
                                "new_meta": current_meta
                            })
                            
                    # Update database
                    integrity_db[path] = {
                        'hash': current_hash,
                        'metadata': current_meta,
                        'last_check': datetime.now().isoformat()
                    }
                    
                except Exception as e:
                    results["errors"].append(f"Error checking {path}: {e}")
                    
            # Save updated database
            try:
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                with open(db_path, 'w') as f:
                    json.dump(integrity_db, f, indent=2)
            except Exception as e:
                results["errors"].append(f"Error saving integrity database: {e}")
                
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Integrity check failed: {e}")
            
        return results
        
    def analyze_network_connections(self) -> Dict[str, Any]:
        """Analyze active network connections for suspicious activity.
        
        Returns:
            Analysis results
        """
        results = {
            "success": True,
            "suspicious": [],
            "errors": []
        }
        
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            
            # Known suspicious ports
            suspicious_ports = {
                4444: "Metasploit default",
                1337: "Common backdoor",
                6666: "Common backdoor",
                31337: "Elite backdoor"
            }
            
            # Check each connection
            for conn in connections:
                try:
                    if not conn.raddr:  # Skip if no remote address
                        continue
                        
                    suspicious = False
                    reasons = []
                    
                    # Check for suspicious ports
                    remote_port = conn.raddr.port
                    if remote_port in suspicious_ports:
                        suspicious = True
                        reasons.append(
                            f"Suspicious port {remote_port}: {suspicious_ports[remote_port]}"
                        )
                        
                    # Get process info
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        proc_user = proc.username()
                    except:
                        proc_name = "Unknown"
                        proc_user = "Unknown"
                        
                    # Check if connection is from non-standard process
                    if proc_name.lower() not in ['svchost', 'lsass', 'services']:
                        if conn.status == 'LISTEN':
                            suspicious = True
                            reasons.append(f"Non-standard process {proc_name} listening")
                            
                    if suspicious:
                        results["suspicious"].append({
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status": conn.status,
                            "pid": conn.pid,
                            "process": proc_name,
                            "user": proc_user,
                            "reasons": reasons
                        })
                        
                except Exception as e:
                    results["errors"].append(
                        f"Error analyzing connection {conn}: {e}"
                    )
                    
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Network analysis failed: {e}")
            
        return results
