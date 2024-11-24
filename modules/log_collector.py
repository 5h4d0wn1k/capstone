import os
import time
from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger
import threading
from queue import Queue
import re
import glob
import json
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32evtlog
import win32con
import win32evtlogutil
import win32security

class LogCollector:
    def __init__(self, config: Dict):
        """Initialize log collector"""
        self.config = config
        self.initialize_collection()
        
    def initialize_collection(self):
        """Initialize log collection components"""
        # Initialize collection flags and queues
        self.collecting = False
        self.event_queue = Queue()
        
        # Initialize log sources
        self.log_sources = self.config.get('log_sources', {
            'windows_event_logs': ['System', 'Security', 'Application'],
            'custom_logs': [],
            'iis_logs': [],
            'firewall_logs': []
        })
        
        # Initialize log patterns
        self.patterns = self.config.get('patterns', {
            'error': r'error|exception|fail|critical',
            'warning': r'warn|warning|alert',
            'suspicious': r'invalid|unauthorized|denied|blocked'
        })
        
        # Initialize observers and handlers
        self.observers = []
        self.handlers = []
        
        # Setup log monitoring
        self.setup_log_monitoring()
        
    def setup_log_monitoring(self):
        """Setup log file monitoring"""
        # Windows Event Log monitoring thread
        self.handlers.append(threading.Thread(
            target=self._monitor_windows_events,
            daemon=True,
            name="WindowsEventMonitor"
        ))
        
        # Custom log file monitoring
        for log_path in self.log_sources.get('custom_logs', []):
            if os.path.exists(log_path):
                observer = Observer()
                event_handler = LogFileHandler(self)
                observer.schedule(event_handler, os.path.dirname(log_path), recursive=False)
                self.observers.append(observer)
                
        # IIS log monitoring
        if self.log_sources.get('iis_logs'):
            self.handlers.append(threading.Thread(
                target=self._monitor_iis_logs,
                daemon=True,
                name="IISLogMonitor"
            ))
            
        # Firewall log monitoring
        if self.log_sources.get('firewall_logs'):
            self.handlers.append(threading.Thread(
                target=self._monitor_firewall_logs,
                daemon=True,
                name="FirewallLogMonitor"
            ))
            
    def start_collection(self):
        """Start log collection"""
        logger.info("Starting log collection")
        self.collecting = True
        
        # Start file observers
        for observer in self.observers:
            observer.start()
            
        # Start monitoring threads
        for handler in self.handlers:
            try:
                handler.start()
                logger.info(f"Started {handler.name}")
            except Exception as e:
                logger.error(f"Failed to start {handler.name}: {e}")
                
    def stop_collection(self):
        """Stop log collection"""
        logger.info("Stopping log collection")
        self.collecting = False
        
        # Stop file observers
        for observer in self.observers:
            observer.stop()
            observer.join()
            
        # Stop monitoring threads
        for handler in self.handlers:
            try:
                handler.join(timeout=5)
                logger.info(f"Stopped {handler.name}")
            except Exception as e:
                logger.error(f"Error stopping {handler.name}: {e}")
                
    def _monitor_windows_events(self):
        """Monitor Windows Event Logs"""
        while self.collecting:
            try:
                for log_type in self.log_sources['windows_event_logs']:
                    handle = win32evtlog.OpenEventLog(None, log_type)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events = win32evtlog.ReadEventLog(
                        handle,
                        flags,
                        0
                    )
                    
                    for event in events:
                        if self._is_relevant_event(event):
                            self._process_windows_event(event, log_type)
                            
                    win32evtlog.CloseEventLog(handle)
                    
            except Exception as e:
                logger.error(f"Error monitoring Windows events: {e}")
                
            time.sleep(10)
            
    def _monitor_iis_logs(self):
        """Monitor IIS Logs"""
        while self.collecting:
            try:
                for log_dir in self.log_sources['iis_logs']:
                    log_files = glob.glob(os.path.join(log_dir, '*.log'))
                    for log_file in log_files:
                        self._process_iis_log(log_file)
                        
            except Exception as e:
                logger.error(f"Error monitoring IIS logs: {e}")
                
            time.sleep(60)
            
    def _monitor_firewall_logs(self):
        """Monitor Firewall Logs"""
        while self.collecting:
            try:
                for log_file in self.log_sources['firewall_logs']:
                    self._process_firewall_log(log_file)
                    
            except Exception as e:
                logger.error(f"Error monitoring firewall logs: {e}")
                
            time.sleep(60)
            
    def _is_relevant_event(self, event) -> bool:
        """Check if a Windows event is relevant"""
        try:
            # Check event type
            if event.EventType in [win32con.EVENTLOG_ERROR_TYPE, win32con.EVENTLOG_WARNING_TYPE]:
                return True
                
            # Check event ID for known security events
            security_events = {4624, 4625, 4648, 4719, 4964}  # Common security event IDs
            if event.EventID in security_events:
                return True
                
            return False
            
        except Exception:
            return False
            
    def _process_windows_event(self, event, log_type: str):
        """Process a Windows Event Log entry"""
        try:
            event_data = {
                'timestamp': datetime.now().isoformat(),
                'log_type': log_type,
                'event_id': event.EventID,
                'event_type': event.EventType,
                'source_name': event.SourceName,
                'computer_name': event.ComputerName,
                'message': win32evtlogutil.SafeFormatMessage(event, log_type)
            }
            
            self.event_queue.put(event_data)
            
        except Exception as e:
            logger.error(f"Error processing Windows event: {e}")

    def start(self):
        """Start the log collector"""
        logger.info("Starting log collector")
        self.start_collection()

    def stop(self):
        """Stop the log collector"""
        logger.info("Stopping log collector")
        self.stop_collection()

    def _process_iis_log(self, log_file: str):
        """Process an IIS log file"""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                        
                    fields = line.strip().split(' ')
                    if len(fields) < 15:  # Basic IIS log format check
                        continue
                        
                    log_entry = {
                        'timestamp': fields[0] + ' ' + fields[1],
                        'client_ip': fields[8],
                        'method': fields[3],
                        'uri': fields[4],
                        'status': fields[7],
                        'user_agent': fields[9]
                    }
                    
                    # Check for suspicious patterns
                    if self._is_suspicious_iis_entry(log_entry):
                        self._raise_alert({
                            'type': 'suspicious_web_request',
                            'source': 'iis_log',
                            'data': log_entry,
                            'timestamp': datetime.now().isoformat()
                        })
                        
        except Exception as e:
            logger.error(f"Error processing IIS log {log_file}: {e}")
            
    def _process_firewall_log(self, log_file: str):
        """Process a firewall log file"""
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                        
                    fields = line.strip().split(' ')
                    if len(fields) < 5:  # Basic firewall log format check
                        continue
                        
                    log_entry = {
                        'timestamp': fields[0],
                        'action': fields[1],
                        'protocol': fields[2],
                        'source_ip': fields[3],
                        'destination_ip': fields[4]
                    }
                    
                    # Check for suspicious patterns
                    if self._is_suspicious_firewall_entry(log_entry):
                        self._raise_alert({
                            'type': 'suspicious_network_traffic',
                            'source': 'firewall_log',
                            'data': log_entry,
                            'timestamp': datetime.now().isoformat()
                        })
                        
        except Exception as e:
            logger.error(f"Error processing firewall log {log_file}: {e}")
            
    def _is_suspicious_event(self, event: Dict) -> bool:
        """Check if a Windows event is suspicious"""
        # Check event message for suspicious patterns
        message = event.get('message', '').lower()
        
        return any(
            re.search(pattern, message, re.IGNORECASE)
            for pattern in self.patterns.values()
        )
        
    def _is_suspicious_iis_entry(self, entry: Dict) -> bool:
        """Check if an IIS log entry is suspicious"""
        suspicious_patterns = [
            r'\.\./',  # Directory traversal
            r'select.*from',  # SQL injection
            r'union.*select',  # SQL injection
            r'exec.*sp_',  # SQL injection
            r'alert\(.*\)',  # XSS
            r'<script.*>',  # XSS
            r'cmd\.exe',  # Command injection
            r'powershell\.exe'  # PowerShell execution
        ]
        
        uri = entry.get('uri', '').lower()
        return any(re.search(pattern, uri, re.IGNORECASE) for pattern in suspicious_patterns)
        
    def _is_suspicious_firewall_entry(self, entry: Dict) -> bool:
        """Check if a firewall log entry is suspicious"""
        suspicious_ports = {22, 23, 445, 3389, 4444, 5555}  # Common attack ports
        
        try:
            # Check for blocked traffic
            if entry.get('action', '').lower() == 'drop':
                return True
                
            # Check for suspicious ports
            if ':' in entry.get('destination_ip', ''):
                port = int(entry['destination_ip'].split(':')[1])
                if port in suspicious_ports:
                    return True
                    
            return False
            
        except Exception:
            return False
            
    def _raise_alert(self, alert: Dict):
        """Add alert to event queue"""
        self.event_queue.put(alert)
        logger.warning(f"Log Collector Alert: {alert}")


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, collector):
        self.collector = collector
        
    def on_modified(self, event):
        if not event.is_directory:
            try:
                with open(event.src_path, 'r') as f:
                    for line in f:
                        if any(re.search(pattern, line, re.IGNORECASE)
                              for pattern in self.collector.patterns.values()):
                            self.collector._raise_alert({
                                'type': 'suspicious_log_entry',
                                'source': 'custom_log',
                                'file': event.src_path,
                                'line': line.strip(),
                                'timestamp': datetime.now().isoformat()
                            })
                            
            except Exception as e:
                logger.error(f"Error processing log file {event.src_path}: {e}")
