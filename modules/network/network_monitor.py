"""Network monitoring implementation for SIEM platform."""

import os
import sys
import time
import json
import socket
import threading
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
from loguru import logger
import psutil
import winreg
import win32security
import win32api
import nmap

class NetworkMonitor:
    """Network monitoring and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize network monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config.get('network_monitor', {})
        self.enabled = self.config.get('enabled', True)
        self.monitor_interval = self.config.get('monitor_interval', 300)  # 5 minutes
        self.connection_threshold = self.config.get('connection_threshold', 1000)
        self.scan_ports = self.config.get('scan_ports', '1-1024')
        self.events = []
        self._stop_event = threading.Event()
        self._thread = None
        self.initialize_monitor()
        
    def initialize_monitor(self) -> None:
        """Initialize network monitoring components."""
        try:
            # Initialize nmap scanner
            try:
                self.scanner = nmap.PortScanner()
                logger.info("Nmap scanner initialized")
            except Exception as e:
                logger.warning(f"Nmap not available: {e}")
                self.scanner = None
                
            # Load baseline data
            self.baseline = self._load_baseline()
            
        except Exception as e:
            logger.error(f"Error initializing network monitor: {e}")
            
    def _load_baseline(self) -> Dict[str, Any]:
        """Load network baseline data.
        
        Returns:
            Baseline data
        """
        try:
            baseline_file = os.path.join(
                os.path.dirname(__file__),
                'data',
                'network_baseline.json'
            )
            
            if os.path.exists(baseline_file):
                with open(baseline_file, 'r') as f:
                    return json.load(f)
            else:
                logger.info("Creating new network baseline")
                baseline = self._create_baseline()
                
                # Save baseline
                os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
                with open(baseline_file, 'w') as f:
                    json.dump(baseline, f, indent=2)
                    
                return baseline
                
        except Exception as e:
            logger.error(f"Error loading baseline: {e}")
            return {}
            
    def _create_baseline(self) -> Dict[str, Any]:
        """Create network baseline.
        
        Returns:
            Baseline data
        """
        baseline = {
            'created': datetime.now().isoformat(),
            'interfaces': {},
            'connections': {
                'avg_count': 0,
                'common_ports': set()
            },
            'services': {}
        }
        
        try:
            # Network interfaces
            for name, stats in psutil.net_if_stats().items():
                baseline['interfaces'][name] = {
                    'speed': stats.speed,
                    'mtu': stats.mtu,
                    'flags': stats.flags
                }
                
            # Connections baseline
            connections = psutil.net_connections()
            baseline['connections']['avg_count'] = len(connections)
            
            # Common ports
            for conn in connections:
                if conn.laddr:
                    baseline['connections']['common_ports'].add(conn.laddr.port)
                    
            # Convert set to list for JSON serialization
            baseline['connections']['common_ports'] = list(
                baseline['connections']['common_ports']
            )
            
            # Services baseline
            if self.scanner:
                try:
                    # Scan localhost
                    results = self.scanner.scan('127.0.0.1', self.scan_ports)
                    if results.get('scan'):
                        services = results['scan'].get('127.0.0.1', {}).get('tcp', {})
                        baseline['services'] = {
                            str(port): info['name']
                            for port, info in services.items()
                            if info['state'] == 'open'
                        }
                except Exception as e:
                    logger.error(f"Error scanning services: {e}")
                    
            return baseline
            
        except Exception as e:
            logger.error(f"Error creating baseline: {e}")
            return baseline
            
    def start(self) -> None:
        """Start network monitoring."""
        if not self.enabled:
            logger.warning("Network monitor is disabled")
            return
            
        try:
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._monitor_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info("Network monitoring started")
            
        except Exception as e:
            logger.error(f"Failed to start network monitor: {e}")
            
    def stop(self) -> None:
        """Stop network monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        logger.info("Network monitoring stopped")
        
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Collect metrics
                metrics = self.collect_metrics()
                self.analyze_metrics(metrics)
                
                # Perform port scan if available
                if self.scanner:
                    scan_results = self.scan_network()
                    self.analyze_scan_results(scan_results)
                    
                # Wait for next interval
                self._stop_event.wait(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect network metrics.
        
        Returns:
            Network metrics
        """
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'interfaces': {},
                'connections': {
                    'count': 0,
                    'states': {},
                    'ports': set()
                },
                'io_counters': {}
            }
            
            # Interface metrics
            for name, stats in psutil.net_if_stats().items():
                metrics['interfaces'][name] = {
                    'isup': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu
                }
                
            # Connection metrics
            connections = psutil.net_connections()
            metrics['connections']['count'] = len(connections)
            
            for conn in connections:
                # Count by state
                state = conn.status
                metrics['connections']['states'][state] = \
                    metrics['connections']['states'].get(state, 0) + 1
                    
                # Track ports
                if conn.laddr:
                    metrics['connections']['ports'].add(conn.laddr.port)
                    
            # Convert ports set to list
            metrics['connections']['ports'] = list(
                metrics['connections']['ports']
            )
            
            # IO counters
            io_counters = psutil.net_io_counters()
            metrics['io_counters'] = {
                'bytes_sent': io_counters.bytes_sent,
                'bytes_recv': io_counters.bytes_recv,
                'packets_sent': io_counters.packets_sent,
                'packets_recv': io_counters.packets_recv,
                'errin': io_counters.errin,
                'errout': io_counters.errout,
                'dropin': io_counters.dropin,
                'dropout': io_counters.dropout
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return {}
            
    def scan_network(self) -> Dict[str, Any]:
        """Perform network port scan.
        
        Returns:
            Scan results
        """
        try:
            if not self.scanner:
                return {}
                
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Scan network
            network = local_ip.rsplit('.', 1)[0] + '.0/24'
            results = self.scanner.scan(network, self.scan_ports)
            
            return results.get('scan', {})
            
        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            return {}
            
    def analyze_metrics(self, metrics: Dict[str, Any]) -> None:
        """Analyze network metrics.
        
        Args:
            metrics: Network metrics
        """
        try:
            # Check connection count
            conn_count = metrics['connections']['count']
            if conn_count > self.connection_threshold:
                self._add_event('HIGH_CONNECTION_COUNT', 'warning', {
                    'count': conn_count,
                    'threshold': self.connection_threshold,
                    'states': metrics['connections']['states']
                })
                
            # Check interface status
            for name, stats in metrics['interfaces'].items():
                baseline_stats = self.baseline.get('interfaces', {}).get(name)
                if baseline_stats:
                    if not stats['isup'] and baseline_stats.get('isup', True):
                        self._add_event('INTERFACE_DOWN', 'warning', {
                            'interface': name,
                            'stats': stats
                        })
                        
            # Check error rates
            io_counters = metrics['io_counters']
            if io_counters.get('errin', 0) > 0 or io_counters.get('errout', 0) > 0:
                self._add_event('NETWORK_ERRORS', 'warning', {
                    'errin': io_counters['errin'],
                    'errout': io_counters['errout'],
                    'dropin': io_counters['dropin'],
                    'dropout': io_counters['dropout']
                })
                
        except Exception as e:
            logger.error(f"Error analyzing metrics: {e}")
            
    def analyze_scan_results(self, results: Dict[str, Any]) -> None:
        """Analyze network scan results.
        
        Args:
            results: Scan results
        """
        try:
            for host, data in results.items():
                # Skip if no TCP data
                if 'tcp' not in data:
                    continue
                    
                # Check each open port
                for port, info in data['tcp'].items():
                    if info['state'] == 'open':
                        # Check against baseline
                        baseline_service = self.baseline.get('services', {}).get(str(port))
                        current_service = info.get('name', '')
                        
                        if not baseline_service:
                            self._add_event('NEW_SERVICE_DETECTED', 'warning', {
                                'host': host,
                                'port': port,
                                'service': current_service
                            })
                        elif baseline_service != current_service:
                            self._add_event('SERVICE_CHANGED', 'warning', {
                                'host': host,
                                'port': port,
                                'old_service': baseline_service,
                                'new_service': current_service
                            })
                            
        except Exception as e:
            logger.error(f"Error analyzing scan results: {e}")
            
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
                f"Network monitoring event: {event_type}"
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
