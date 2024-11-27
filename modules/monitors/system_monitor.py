"""System monitoring implementation for SIEM platform."""

import os
import sys
import time
import json
import psutil
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from loguru import logger
import win32evtlog
import win32con
import win32evtlogutil
import win32security
import win32api
import win32process

class SystemMonitor:
    """System monitoring and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize system monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config.get('system_monitor', {})
        self.enabled = self.config.get('enabled', True)
        self.monitor_interval = self.config.get('monitor_interval', 60)  # 1 minute
        self.resource_threshold = self.config.get('resource_threshold', 90)  # 90%
        self.events = []
        self._stop_event = threading.Event()
        self._thread = None
        
    def start(self) -> None:
        """Start system monitoring."""
        if not self.enabled:
            logger.warning("System monitor is disabled")
            return
            
        try:
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._monitor_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info("System monitoring started")
            
        except Exception as e:
            logger.error(f"Failed to start system monitor: {e}")
            
    def stop(self) -> None:
        """Stop system monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        logger.info("System monitoring stopped")
        
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Collect system metrics
                metrics = self.collect_system_metrics()
                self.analyze_metrics(metrics)
                
                # Check for critical events
                events = self.check_system_events()
                self.analyze_events(events)
                
                # Wait for next interval
                self._stop_event.wait(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system performance metrics.
        
        Returns:
            System metrics
        """
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': psutil.cpu_percent(interval=1),
                    'count': psutil.cpu_count(),
                    'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                    'stats': psutil.cpu_stats()._asdict(),
                    'times': psutil.cpu_times()._asdict()
                },
                'memory': {
                    'virtual': psutil.virtual_memory()._asdict(),
                    'swap': psutil.swap_memory()._asdict()
                },
                'disk': {
                    'partitions': [p._asdict() for p in psutil.disk_partitions()],
                    'usage': {p.mountpoint: psutil.disk_usage(p.mountpoint)._asdict() 
                             for p in psutil.disk_partitions()}
                },
                'network': {
                    'interfaces': psutil.net_if_stats(),
                    'connections': len(psutil.net_connections()),
                    'io_counters': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else None
                },
                'processes': {
                    'count': len(psutil.pids()),
                    'top_cpu': self._get_top_processes('cpu'),
                    'top_memory': self._get_top_processes('memory')
                }
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {}
            
    def _get_top_processes(self, sort_by: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top processes by resource usage.
        
        Args:
            sort_by: Resource to sort by ('cpu' or 'memory')
            limit: Number of processes to return
            
        Returns:
            List of process information
        """
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            # Sort processes
            if sort_by == 'cpu':
                key = 'cpu_percent'
            else:
                key = 'memory_percent'
                
            return sorted(processes, key=lambda x: x.get(key, 0), reverse=True)[:limit]
            
        except Exception as e:
            logger.error(f"Error getting top processes: {e}")
            return []
            
    def check_system_events(self) -> List[Dict[str, Any]]:
        """Check Windows system events.
        
        Returns:
            List of relevant system events
        """
        events = []
        try:
            # Event types to monitor
            event_types = [
                'System',
                'Application',
                'Security'
            ]
            
            for event_type in event_types:
                try:
                    handle = win32evtlog.OpenEventLog(None, event_type)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events_batch = win32evtlog.ReadEventLog(
                        handle,
                        flags,
                        0
                    )
                    
                    for event in events_batch:
                        try:
                            # Convert event to dictionary
                            event_dict = {
                                'source': event.SourceName,
                                'time_generated': event.TimeGenerated.isoformat(),
                                'event_id': event.EventID,
                                'type': event.EventType,
                                'category': event.EventCategory,
                                'message': win32evtlogutil.SafeFormatMessage(event, event_type)
                            }
                            
                            # Filter relevant events
                            if self._is_relevant_event(event_dict):
                                events.append(event_dict)
                                
                        except Exception as e:
                            logger.error(f"Error processing event: {e}")
                            
                    win32evtlog.CloseEventLog(handle)
                    
                except Exception as e:
                    logger.error(f"Error reading {event_type} event log: {e}")
                    
        except Exception as e:
            logger.error(f"Error checking system events: {e}")
            
        return events
        
    def _is_relevant_event(self, event: Dict[str, Any]) -> bool:
        """Check if event is relevant for monitoring.
        
        Args:
            event: Event information
            
        Returns:
            True if event is relevant
        """
        # Critical event types
        critical_sources = [
            'Microsoft-Windows-Security-Auditing',
            'Microsoft-Windows-Windows Defender',
            'Microsoft-Windows-WindowsUpdateClient',
            'Service Control Manager',
            'System'
        ]
        
        # Critical event IDs
        critical_events = {
            'Security': [4624, 4625, 4648, 4719, 4964],  # Login events, policy changes
            'System': [1074, 6005, 6006, 6008],  # Shutdown, startup events
            'Application': [1000, 1001, 1002]  # Application errors
        }
        
        try:
            # Check source
            if event['source'] in critical_sources:
                return True
                
            # Check event ID
            for log_type, event_ids in critical_events.items():
                if event['event_id'] in event_ids:
                    return True
                    
            return False
            
        except Exception:
            return False
            
    def analyze_metrics(self, metrics: Dict[str, Any]) -> None:
        """Analyze system metrics for issues.
        
        Args:
            metrics: System metrics
        """
        try:
            # Check CPU usage
            if metrics.get('cpu', {}).get('percent', 0) > self.resource_threshold:
                self._add_event('HIGH_CPU_USAGE', 'warning', {
                    'usage': metrics['cpu']['percent'],
                    'threshold': self.resource_threshold,
                    'top_processes': metrics['processes']['top_cpu']
                })
                
            # Check memory usage
            memory = metrics.get('memory', {}).get('virtual', {})
            if memory.get('percent', 0) > self.resource_threshold:
                self._add_event('HIGH_MEMORY_USAGE', 'warning', {
                    'usage': memory['percent'],
                    'threshold': self.resource_threshold,
                    'available': memory.get('available', 0),
                    'top_processes': metrics['processes']['top_memory']
                })
                
            # Check disk usage
            for mount, usage in metrics.get('disk', {}).get('usage', {}).items():
                if usage.get('percent', 0) > self.resource_threshold:
                    self._add_event('HIGH_DISK_USAGE', 'warning', {
                        'mount': mount,
                        'usage': usage['percent'],
                        'threshold': self.resource_threshold,
                        'free': usage.get('free', 0)
                    })
                    
        except Exception as e:
            logger.error(f"Error analyzing metrics: {e}")
            
    def analyze_events(self, events: List[Dict[str, Any]]) -> None:
        """Analyze system events for issues.
        
        Args:
            events: System events
        """
        try:
            for event in events:
                # Analyze based on event type and source
                if event['source'] == 'Microsoft-Windows-Security-Auditing':
                    self._analyze_security_event(event)
                elif event['source'] == 'Microsoft-Windows-Windows Defender':
                    self._analyze_defender_event(event)
                elif event['source'] == 'System':
                    self._analyze_system_event(event)
                    
        except Exception as e:
            logger.error(f"Error analyzing events: {e}")
            
    def _analyze_security_event(self, event: Dict[str, Any]) -> None:
        """Analyze security audit event.
        
        Args:
            event: Security event
        """
        try:
            event_id = event['event_id']
            
            if event_id == 4625:  # Failed logon
                self._add_event('FAILED_LOGIN_ATTEMPT', 'warning', event)
            elif event_id == 4719:  # System audit policy changed
                self._add_event('AUDIT_POLICY_CHANGE', 'warning', event)
            elif event_id == 4964:  # Special groups logon
                self._add_event('SPECIAL_PRIVILEGES_LOGON', 'warning', event)
                
        except Exception as e:
            logger.error(f"Error analyzing security event: {e}")
            
    def _analyze_defender_event(self, event: Dict[str, Any]) -> None:
        """Analyze Windows Defender event.
        
        Args:
            event: Defender event
        """
        try:
            if 'threat' in event['message'].lower():
                self._add_event('MALWARE_DETECTED', 'critical', event)
                
        except Exception as e:
            logger.error(f"Error analyzing defender event: {e}")
            
    def _analyze_system_event(self, event: Dict[str, Any]) -> None:
        """Analyze system event.
        
        Args:
            event: System event
        """
        try:
            event_id = event['event_id']
            
            if event_id in [6005, 6006]:  # System startup/shutdown
                self._add_event('SYSTEM_STATE_CHANGE', 'info', event)
            elif event_id == 6008:  # Unexpected shutdown
                self._add_event('UNEXPECTED_SHUTDOWN', 'warning', event)
                
        except Exception as e:
            logger.error(f"Error analyzing system event: {e}")
            
    def _add_event(self, event_type: str, severity: str, data: Dict[str, Any]) -> None:
        """Add monitoring event.
        
        Args:
            event_type: Type of event
            severity: Event severity
            data: Event data
        """
        try:
            event = {
                'timestamp': datetime.now().isoformat(),
                'type': event_type,
                'severity': severity,
                'data': data
            }
            
            self.events.append(event)
            logger.log(
                severity.upper(),
                f"System monitoring event: {event_type}"
            )
            
        except Exception as e:
            logger.error(f"Error adding event: {e}")
            
    def get_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get monitoring events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of events
        """
        if limit:
            return self.events[-limit:]
        return self.events.copy()
        
    def clear_events(self) -> None:
        """Clear monitoring events."""
        self.events.clear()
