#!/usr/bin/env python3

import win32evtlog
import win32con
import threading
import time
from datetime import datetime
from loguru import logger

class RegistryMonitor:
    """Monitor Windows Registry changes."""
    
    def __init__(self):
        """Initialize registry monitor."""
        self.running = False
        self.monitor_thread = None
        self.events = []
        self.alerts = []
        
    def start(self):
        """Start registry monitoring."""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_registry)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            logger.info("Registry monitor started")
            
    def stop(self):
        """Stop registry monitoring."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Registry monitor stopped")
        
    def _monitor_registry(self):
        """Monitor registry changes continuously."""
        while self.running:
            try:
                handle = win32evtlog.OpenEventLog(None, "Security")
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                
                for event in events:
                    if event.EventID == 4657:  # Registry value modified
                        event_data = {
                            'timestamp': event.TimeGenerated.isoformat(),
                            'event_id': event.EventID,
                            'source': event.SourceName,
                            'key': event.StringInserts[0] if event.StringInserts else None,
                            'type': event.StringInserts[1] if event.StringInserts and len(event.StringInserts) > 1 else None,
                            'value': event.StringInserts[2] if event.StringInserts and len(event.StringInserts) > 2 else None
                        }
                        
                        self.events.append(event_data)
                        
                        # Check if change is suspicious
                        if self.is_suspicious_change(event_data):
                            alert = {
                                'timestamp': event_data['timestamp'],
                                'severity': 'High',
                                'message': f"Suspicious registry change detected: {event_data['key']}"
                            }
                            self.alerts.append(alert)
                            logger.warning(f"Suspicious registry change: {event_data['key']}")
                            
            except Exception as e:
                logger.error(f"Error monitoring registry: {e}")
                
            time.sleep(1)  # Update every second
            
    def get_events(self):
        """Get list of registry events."""
        return self.events
        
    def get_alerts(self):
        """Get list of registry alerts."""
        return self.alerts
        
    def is_suspicious_change(self, event):
        """
        Check if a registry change is suspicious.
        
        Args:
            event (dict): Event information dictionary
            
        Returns:
            bool: True if change is suspicious, False otherwise
        """
        key = event.get('key', '').lower()
        
        # Check for autorun locations
        suspicious_keys = [
            'software\\microsoft\\windows\\currentversion\\run',
            'software\\microsoft\\windows\\currentversion\\runonce',
            'software\\wow6432node\\microsoft\\windows\\currentversion\\run',
            'system\\currentcontrolset\\services'
        ]
        if any(sus_key in key for sus_key in suspicious_keys):
            return True
            
        # Check for system policies
        if 'securitypolicy' in key or 'groupolicy' in key:
            return True
            
        # Check for suspicious values
        value = event.get('value', '').lower()
        suspicious_values = ['.exe', '.dll', '.bat', '.ps1', '.vbs']
        if any(sus_val in value for sus_val in suspicious_values):
            return True
            
        return False
