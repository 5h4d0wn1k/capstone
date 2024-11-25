#!/usr/bin/env python3

import os
import psutil
import threading
import time
from datetime import datetime
from loguru import logger

class ProcessMonitor:
    """Monitor system processes and detect suspicious activity."""
    
    def __init__(self):
        """Initialize process monitor."""
        self.running = False
        self.process_list = {}
        self.monitor_thread = None
        self.suspicious_processes = []
        
    def start(self):
        """Start process monitoring."""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_processes)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            logger.info("Process monitor started")
            
    def stop(self):
        """Stop process monitoring."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Process monitor stopped")
        
    def _monitor_processes(self):
        """Monitor processes continuously."""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    process_info = proc.info
                    pid = process_info['pid']
                    
                    # Add network connections if available
                    try:
                        connections = proc.connections()
                        process_info['connections'] = [
                            {
                                'local_ip': conn.laddr.ip if conn.laddr else None,
                                'local_port': conn.laddr.port if conn.laddr else None,
                                'remote_ip': conn.raddr.ip if conn.raddr else None,
                                'remote_port': conn.raddr.port if conn.raddr else None,
                                'status': conn.status
                            }
                            for conn in connections
                        ]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        process_info['connections'] = []
                        
                    # Check if process is suspicious
                    if self.is_suspicious_process(process_info):
                        if pid not in self.suspicious_processes:
                            self.suspicious_processes.append(pid)
                            logger.warning(f"Suspicious process detected: {process_info['name']} (PID: {pid})")
                            
                    self.process_list[pid] = process_info
                    
            except Exception as e:
                logger.error(f"Error monitoring processes: {e}")
                
            time.sleep(1)  # Update every second
            
    def get_processes(self):
        """Get current process list."""
        return list(self.process_list.values())
        
    def is_suspicious_process(self, process):
        """
        Check if a process is suspicious based on various indicators.
        
        Args:
            process (dict): Process information dictionary
            
        Returns:
            bool: True if process is suspicious, False otherwise
        """
        # CPU usage threshold (90%)
        if process.get('cpu_percent', 0) > 90:
            return True
            
        # Memory usage threshold (80%)
        if process.get('memory_percent', 0) > 80:
            return True
            
        # Check for suspicious network connections
        connections = process.get('connections', [])
        for conn in connections:
            remote_ip = conn.get('remote_ip')
            if remote_ip and remote_ip not in ['127.0.0.1', '::1']:
                # TODO: Add more sophisticated IP reputation checking
                return True
                
        # Check for suspicious process names
        suspicious_names = ['cmd.exe', 'powershell.exe', 'netcat', 'ncat']
        if process.get('name', '').lower() in suspicious_names:
            return True
            
        return False
        
    def get_suspicious_processes(self):
        """Get list of suspicious processes."""
        return [self.process_list[pid] for pid in self.suspicious_processes if pid in self.process_list]
