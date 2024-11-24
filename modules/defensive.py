import os
import sys
from loguru import logger
import threading
from queue import Queue, Empty
import time
from typing import Dict, List, Optional
import platform
import subprocess
from scapy.all import sniff, IP, TCP
import psutil
import hashlib
from datetime import datetime
import re
import yaml

class DefensiveTools:
    def __init__(self, config: Dict):
        """Initialize defensive security tools"""
        self.config = config
        self.initialize_components()
        self.setup_monitoring()
        
    def initialize_components(self):
        """Initialize defensive components"""
        # Initialize queues for events and alerts
        self.event_queue = Queue()
        self.alert_queue = Queue()
        
        # Initialize monitoring flags
        self.monitoring = False
        self.packet_capture = False
        self.running = False
        
        # Initialize counters and thresholds
        self.failed_login_attempts = {}
        self.suspicious_ips = set()
        self.blocked_ips = set()
        
        # Load thresholds from config
        self.thresholds = self.config.get('thresholds', {
            'failed_login_max': 5,
            'suspicious_connections': 10,
            'cpu_usage_threshold': 90,
            'memory_usage_threshold': 90,
            'disk_usage_threshold': 90
        })
        
    def setup_monitoring(self):
        """Setup monitoring components"""
        # Initialize monitoring threads
        self.threads = []
        
        # Network monitoring thread
        self.threads.append(threading.Thread(
            target=self._network_monitor,
            daemon=True,
            name="NetworkMonitor"
        ))
        
        # System monitoring thread
        self.threads.append(threading.Thread(
            target=self._system_monitor,
            daemon=True,
            name="SystemMonitor"
        ))
        
        # File integrity monitoring thread
        self.threads.append(threading.Thread(
            target=self._file_integrity_monitor,
            daemon=True,
            name="FileMonitor"
        ))
        
        # Alert processing thread
        self.threads.append(threading.Thread(
            target=self._process_alerts,
            daemon=True,
            name="AlertProcessor"
        ))
        
    def start_monitoring(self):
        """Start all monitoring threads"""
        logger.info("Starting defensive monitoring")
        self.monitoring = True
        self.running = True
        
        for thread in self.threads:
            try:
                thread.start()
                logger.info(f"Started {thread.name}")
            except Exception as e:
                logger.error(f"Failed to start {thread.name}: {e}")
                
        # Start packet capture if available
        if self._check_pcap_available():
            self.start_packet_capture()
            
    def stop_monitoring(self):
        """Stop all monitoring threads"""
        logger.info("Stopping defensive monitoring")
        self.monitoring = False
        self.running = False
        self.packet_capture = False
        
        for thread in self.threads:
            try:
                thread.join(timeout=5)
                logger.info(f"Stopped {thread.name}")
            except Exception as e:
                logger.error(f"Error stopping {thread.name}: {e}")
                
    def _check_pcap_available(self) -> bool:
        """Check if packet capture is available"""
        try:
            from scapy.all import conf
            if conf.L2listen() is not None:
                return True
        except Exception:
            pass
        return False
        
    def start_packet_capture(self):
        """Start packet capture"""
        if self._check_pcap_available():
            self.packet_capture = True
            threading.Thread(
                target=self._packet_capture,
                daemon=True,
                name="PacketCapture"
            ).start()
            logger.info("Started packet capture")
        else:
            logger.warning("Packet capture not available")
            
    def _packet_capture(self):
        """Capture and analyze network packets"""
        def packet_callback(packet):
            if not self.packet_capture:
                return
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check for suspicious patterns
                if self._is_suspicious_traffic(packet):
                    self.suspicious_ips.add(src_ip)
                    self._raise_alert({
                        'type': 'suspicious_traffic',
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'timestamp': datetime.now().isoformat()
                    })
                    
        try:
            sniff(prn=packet_callback, store=0)
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            
    def _network_monitor(self):
        """Monitor network connections"""
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        remote_ip = conn.raddr.ip if conn.raddr else None
                        if remote_ip and self._is_suspicious_ip(remote_ip):
                            self._raise_alert({
                                'type': 'suspicious_connection',
                                'ip': remote_ip,
                                'port': conn.raddr.port if conn.raddr else None,
                                'timestamp': datetime.now().isoformat()
                            })
                            
            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                
            time.sleep(5)
            
    def _system_monitor(self):
        """Monitor system resources"""
        while self.monitoring:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.thresholds['cpu_usage_threshold']:
                    self._raise_alert({
                        'type': 'high_cpu_usage',
                        'value': cpu_percent,
                        'threshold': self.thresholds['cpu_usage_threshold'],
                        'timestamp': datetime.now().isoformat()
                    })
                    
                # Memory usage
                memory = psutil.virtual_memory()
                if memory.percent > self.thresholds['memory_usage_threshold']:
                    self._raise_alert({
                        'type': 'high_memory_usage',
                        'value': memory.percent,
                        'threshold': self.thresholds['memory_usage_threshold'],
                        'timestamp': datetime.now().isoformat()
                    })

                # Disk usage
                for partition in psutil.disk_partitions():
                    usage = psutil.disk_usage(partition.mountpoint)
                    if usage.percent > self.thresholds['disk_usage_threshold']:
                        self._raise_alert({
                            'type': 'high_disk_usage',
                            'partition': partition.mountpoint,
                            'value': usage.percent,
                            'threshold': self.thresholds['disk_usage_threshold'],
                            'timestamp': datetime.now().isoformat()
                        })
                        
            except Exception as e:
                logger.error(f"System monitoring error: {e}")
                
            time.sleep(60)
            
    def _file_integrity_monitor(self):
        """Monitor critical files for changes"""
        file_hashes = {}
        monitored_paths = self.config.get('monitored_files', [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/hosts'
        ])
        
        def get_file_hash(filepath: str) -> Optional[str]:
            try:
                with open(filepath, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
            except Exception:
                return None
                
        # Initialize file hashes
        for filepath in monitored_paths:
            if os.path.exists(filepath):
                file_hashes[filepath] = get_file_hash(filepath)
                
        while self.monitoring:
            try:
                for filepath in monitored_paths:
                    if os.path.exists(filepath):
                        current_hash = get_file_hash(filepath)
                        if filepath in file_hashes and current_hash != file_hashes[filepath]:
                            self._raise_alert({
                                'type': 'file_modified',
                                'file': filepath,
                                'timestamp': datetime.now().isoformat()
                            })
                        file_hashes[filepath] = current_hash
                        
            except Exception as e:
                logger.error(f"File monitoring error: {e}")
                
            time.sleep(300)
            
    def _process_alerts(self):
        """Process alerts from the queue"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._handle_alert(alert)
            except Empty:  
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
                if not self.running:
                    break
                
    def _handle_alert(self, alert: Dict):
        """Handle different types of security alerts"""
        logger.warning(f"Security Alert: {alert}")
        
        # Add alert handling logic here
        alert_type = alert.get('type')
        
        if alert_type == 'suspicious_traffic':
            self._handle_suspicious_traffic(alert)
        elif alert_type == 'suspicious_connection':
            self._handle_suspicious_connection(alert)
        elif alert_type in ['high_cpu_usage', 'high_memory_usage', 'high_disk_usage']:
            self._handle_resource_alert(alert)
        elif alert_type == 'file_modified':
            self._handle_file_modification(alert)
            
    def _handle_suspicious_traffic(self, alert: Dict):
        """Handle suspicious traffic alerts"""
        source_ip = alert.get('source_ip')
        if source_ip:
            if source_ip in self.suspicious_ips:
                self.blocked_ips.add(source_ip)
                logger.warning(f"Blocked suspicious IP: {source_ip}")
                
    def _handle_suspicious_connection(self, alert: Dict):
        """Handle suspicious connection alerts"""
        ip = alert.get('ip')
        if ip:
            self.suspicious_ips.add(ip)
            logger.warning(f"Added IP to suspicious list: {ip}")
            
    def _handle_resource_alert(self, alert: Dict):
        """Handle resource usage alerts"""
        logger.warning(
            f"High resource usage: {alert.get('type')} at {alert.get('value')}% "
            f"(threshold: {alert.get('threshold')}%)"
        )
        
    def _handle_file_modification(self, alert: Dict):
        """Handle file modification alerts"""
        logger.warning(f"Critical file modified: {alert.get('file')}")
        
    def _is_suspicious_traffic(self, packet) -> bool:
        """Check if network traffic is suspicious"""
        if IP in packet and TCP in packet:
            # Check for common attack patterns
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN flag
                return True
            if flags & 0x01:  # FIN flag
                return True
                
        return False
        
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        return (
            ip in self.suspicious_ips or
            ip in self.blocked_ips
        )
        
    def _raise_alert(self, alert: Dict):
        """Add alert to processing queue"""
        self.alert_queue.put(alert)

    def start(self):
        """Start defensive tools"""
        logger.info("Starting defensive tools")
        self.start_monitoring()

    def stop(self):
        """Stop defensive tools"""
        logger.info("Stopping defensive tools")
        self.stop_monitoring()
