"""Syslog collector implementation."""

import socket
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from loguru import logger

class SyslogCollector:
    """Syslog message collector."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize collector.
        
        Args:
            config: Collector configuration
        """
        self.config = config.get('syslog_collector', {})
        self.enabled = self.config.get('enabled', True)
        self.host = self.config.get('host', '0.0.0.0')
        self.port = self.config.get('port', 514)
        self.buffer_size = self.config.get('buffer_size', 8192)
        self.events = []
        self._stop_event = threading.Event()
        self._thread = None
        self._socket = None
        
    def start(self) -> None:
        """Start collecting syslog messages."""
        if not self.enabled:
            logger.warning("Syslog collector is disabled")
            return
            
        try:
            # Create UDP socket
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((self.host, self.port))
            
            # Start collection thread
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._collect_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info(f"Syslog collector started on {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start Syslog collector: {e}")
            
    def stop(self) -> None:
        """Stop collecting syslog messages."""
        self._stop_event.set()
        if self._socket:
            self._socket.close()
        if self._thread:
            self._thread.join()
        logger.info("Syslog collector stopped")
        
    def _collect_loop(self) -> None:
        """Main collection loop."""
        while not self._stop_event.is_set():
            try:
                # Receive message
                data, addr = self._socket.recvfrom(self.buffer_size)
                message = data.decode('utf-8')
                
                # Parse and process message
                event = self._parse_message(message, addr)
                if event:
                    self._process_event(event)
                    
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.error(f"Error in Syslog collection loop: {e}")
                    
    def _parse_message(self, message: str, addr: tuple) -> Optional[Dict[str, Any]]:
        """Parse syslog message.
        
        Args:
            message: Raw syslog message
            addr: Source address tuple (host, port)
            
        Returns:
            Parsed event data or None if parsing fails
        """
        try:
            # Basic syslog message parsing
            # Format: <priority>timestamp hostname tag: message
            parts = message.split(' ', 3)
            if len(parts) < 4:
                return None
                
            priority, timestamp, hostname, content = parts
            
            # Parse priority
            if priority.startswith('<') and priority.endswith('>'):
                priority = int(priority[1:-1])
                facility = priority >> 3
                severity = priority & 0x07
            else:
                facility = 0
                severity = 5  # Notice
                
            # Parse content
            tag, msg = content.split(':', 1) if ':' in content else (content, '')
            
            data = {
                'timestamp': datetime.now().isoformat(),
                'facility': facility,
                'severity': severity,
                'hostname': hostname,
                'tag': tag.strip(),
                'message': msg.strip(),
                'source_ip': addr[0],
                'source_port': addr[1]
            }
            
            return data
            
        except Exception as e:
            logger.error(f"Error parsing Syslog message: {e}")
            return None
            
    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process syslog event.
        
        Args:
            event: Event to process
        """
        try:
            # Add to events list
            self.events.append(event)
            
            # Log high severity events
            if event['severity'] <= 3:  # Error, Critical, Alert, Emergency
                logger.warning(
                    f"High severity Syslog message from {event['hostname']}: "
                    f"{event['message']}"
                )
                
        except Exception as e:
            logger.error(f"Error processing Syslog event: {e}")
            
    def get_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get collected events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of events
        """
        if limit:
            return self.events[-limit:]
        return self.events.copy()
        
    def clear_events(self) -> None:
        """Clear collected events."""
        self.events.clear()
