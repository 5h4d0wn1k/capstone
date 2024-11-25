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
                        f"Hardened permissions on {directory}"
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
