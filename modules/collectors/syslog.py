from typing import Dict, Optional, Tuple
from loguru import logger
import socket
import threading
import queue
import json
from datetime import datetime
import re
from .base import BaseEventCollector

class SyslogCollector(BaseEventCollector):
    """Syslog message collector"""
    
    def __init__(self, config: Dict):
        """Initialize Syslog Collector"""
        super().__init__(config)
        self.port = config.get('port', 514)
        self.protocol = config.get('protocol', 'UDP').upper()
        self.buffer_size = config.get('buffer_size', 8192)
        self.socket = None
        self.last_message_time = datetime.now()
        
        # Compile regex patterns for syslog parsing
        self.patterns = {
            'rfc3164': re.compile(r'<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)'),
            'rfc5424': re.compile(r'<(\d+)>1\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(-|\[\d+\])\s+(.*)'),
        }
        
    def initialize_collector(self):
        """Initialize the syslog collector"""
        try:
            # Create socket based on protocol
            if self.protocol == 'UDP':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set socket options
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind socket
            self.socket.bind(('0.0.0.0', self.port))
            
            # Listen if TCP
            if self.protocol == 'TCP':
                self.socket.listen(5)
            
            logger.info(f"Syslog Collector initialized on port {self.port} ({self.protocol})")
            self.health_status = True
            
        except Exception as e:
            logger.error(f"Failed to initialize Syslog Collector: {e}")
            self.health_status = False
            raise

    def is_healthy(self) -> bool:
        """Check if the collector is healthy"""
        try:
            # Check if socket is still valid
            if not self.socket:
                return False
                
            # Check if we've received messages recently (within last 5 minutes)
            time_since_last_message = (datetime.now() - self.last_message_time).total_seconds()
            if time_since_last_message > 300:  # 5 minutes
                logger.warning("No syslog messages received in the last 5 minutes")
                return False
                
            # Check if queue is not full
            if self.event_queue.full():
                logger.warning("Syslog event queue is full")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
            
    def collect_events(self):
        """Collect syslog events"""
        while self.running:
            try:
                if self.protocol == 'UDP':
                    data, addr = self.socket.recvfrom(self.buffer_size)
                else:
                    conn, addr = self.socket.accept()
                    data = conn.recv(self.buffer_size)
                    
                if data:
                    self.last_message_time = datetime.now()
                    message = data.decode('utf-8', errors='ignore')
                    
                    # Try both RFC3164 and RFC5424 formats
                    parsed = self._parse_syslog_message(message)
                    if parsed:
                        self.event_queue.put(parsed)
                        
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error collecting syslog events: {e}")
                if not self.running:
                    break
                    
    def _parse_syslog_message(self, message: str) -> Optional[Dict]:
        """Parse syslog message in either RFC3164 or RFC5424 format"""
        try:
            # Try RFC5424 first (newer format)
            match = self.patterns['rfc5424'].match(message)
            if match:
                facility_priority, timestamp, hostname, app_name, procid, msgid, structured_data, msg = match.groups()
                return {
                    'timestamp': timestamp,
                    'hostname': hostname,
                    'application': app_name,
                    'process_id': procid,
                    'message_id': msgid,
                    'structured_data': structured_data,
                    'message': msg,
                    'format': 'RFC5424'
                }
                
            # Try RFC3164 (older format)
            match = self.patterns['rfc3164'].match(message)
            if match:
                facility_priority, timestamp, hostname, tag, msg = match.groups()
                return {
                    'timestamp': timestamp,
                    'hostname': hostname,
                    'tag': tag,
                    'message': msg,
                    'format': 'RFC3164'
                }
                
            # If neither format matches, store as raw
            return {
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'format': 'RAW'
            }
            
        except Exception as e:
            logger.error(f"Error parsing syslog message: {e}")
            return None

    def _normalize_event(self, event: Dict) -> Dict:
        """Normalize syslog event to common format"""
        return {
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'source': 'syslog',
            'facility': event.get('facility'),
            'severity': event.get('severity'),
            'hostname': event.get('hostname'),
            'message': event.get('message'),
            'raw_data': event
        }

    def stop(self):
        """Stop the syslog collector"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.error(f"Error closing syslog socket: {e}")
        super().stop()
