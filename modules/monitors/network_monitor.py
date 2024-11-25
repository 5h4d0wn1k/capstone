#!/usr/bin/env python3

import psutil
import threading
import time
from datetime import datetime
from loguru import logger

class NetworkMonitor:
    """Monitor network connections and traffic."""
    
    def __init__(self):
        """Initialize network monitor."""
        self.running = False
        self.monitor_thread = None
        self.connections = []
        self.traffic_stats = {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0
        }
        
    def start(self):
        """Start network monitoring."""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_network)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            logger.info("Network monitor started")
            
    def stop(self):
        """Stop network monitoring."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Network monitor stopped")
        
    def _monitor_network(self):
        """Monitor network activity continuously."""
        while self.running:
            try:
                # Update network connections
                self.connections = []
                for conn in psutil.net_connections(kind='inet'):
                    connection_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    self.connections.append(connection_info)
                    
                # Update network traffic stats
                net_io = psutil.net_io_counters()
                self.traffic_stats = {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                }
                
            except Exception as e:
                logger.error(f"Error monitoring network: {e}")
                
            time.sleep(1)  # Update every second
            
    def get_connections(self):
        """Get current network connections."""
        return self.connections
        
    def get_traffic_stats(self):
        """Get current network traffic statistics."""
        return self.traffic_stats
        
    def is_suspicious_connection(self, connection):
        """
        Check if a network connection is suspicious.
        
        Args:
            connection (dict): Connection information dictionary
            
        Returns:
            bool: True if connection is suspicious, False otherwise
        """
        # Check for suspicious ports
        suspicious_ports = [22, 23, 445, 3389]  # SSH, Telnet, SMB, RDP
        if connection.get('remote_address'):
            try:
                port = int(connection['remote_address'].split(':')[1])
                if port in suspicious_ports:
                    return True
            except (ValueError, IndexError):
                pass
                
        # Check for suspicious IPs
        # TODO: Add IP reputation checking
        
        return False
