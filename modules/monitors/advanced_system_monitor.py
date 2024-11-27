#!/usr/bin/env python3

import psutil
import win32evtlog
import win32con
import win32security
import wmi
import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest
from loguru import logger

class AdvancedSystemMonitor:
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the advanced system monitor"""
        self.wmi = wmi.WMI()
        self.process_history = defaultdict(list)
        self.resource_history = defaultdict(list)
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.suspicious_processes = set()
        self.baseline_metrics = {}
        self.initialize_components(config_path)

    def initialize_components(self, config_path: Optional[str] = None):
        """Initialize monitor components"""
        try:
            self._load_config(config_path)
            self._initialize_ml_model()
            self._establish_baseline()
        except Exception as e:
            logger.error(f"Failed to initialize system monitor: {e}")
            raise

    def _load_config(self, config_path: Optional[str] = None):
        """Load configuration from file"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.suspicious_processes.update(config.get('suspicious_processes', []))

    def _initialize_ml_model(self):
        """Initialize and train the anomaly detection model"""
        history_file = 'system_history.json'
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                historical_data = json.load(f)
                if historical_data:
                    X = np.array(historical_data)
                    self.anomaly_detector.fit(X)

    def _establish_baseline(self):
        """Establish baseline system metrics"""
        metrics = self._collect_system_metrics()
        self.baseline_metrics = {
            'cpu_percent': metrics['cpu_percent'],
            'memory_percent': metrics['memory_percent'],
            'disk_io': metrics['disk_io'],
            'network_io': metrics['network_io'],
            'process_count': metrics['process_count']
        }

    async def start_monitoring(self):
        """Start continuous system monitoring"""
        while True:
            try:
                # Collect and analyze system metrics
                metrics = self._collect_system_metrics()
                analysis = await self._analyze_system_state(metrics)
                
                # Monitor processes
                processes = self._monitor_processes()
                process_analysis = self._analyze_processes(processes)
                
                # Monitor system events
                events = self._collect_system_events()
                event_analysis = self._analyze_events(events)
                
                # Combine all analyses
                combined_analysis = {
                    'timestamp': datetime.now().isoformat(),
                    'system_metrics': analysis,
                    'process_analysis': process_analysis,
                    'event_analysis': event_analysis,
                    'anomalies': []
                }
                
                # Check for anomalies
                if self._is_anomaly(metrics):
                    combined_analysis['anomalies'].append({
                        'type': 'system_metrics',
                        'severity': 'high',
                        'details': 'Unusual system behavior detected'
                    })
                
                # Update history
                self._update_history(metrics)
                
                # Generate alerts if necessary
                await self._generate_alerts(combined_analysis)
                
                # Wait before next iteration
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error during system monitoring: {e}")
                await asyncio.sleep(5)  # Wait longer if there's an error

    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics"""
        try:
            metrics = {
                'timestamp': datetime.now(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'swap_percent': psutil.swap_memory().percent,
                'disk_io': psutil.disk_io_counters()._asdict(),
                'network_io': psutil.net_io_counters()._asdict(),
                'process_count': len(psutil.pids()),
                'handle_count': sum(p.num_handles() for p in psutil.process_iter(['num_handles'])),
                'thread_count': sum(p.num_threads() for p in psutil.process_iter(['num_threads']))
            }
            
            # Add disk usage for all mounted drives
            metrics['disk_usage'] = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    metrics['disk_usage'][partition.mountpoint] = usage._asdict()
                except Exception:
                    continue
            
            return metrics
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {}

    def _monitor_processes(self) -> List[Dict[str, Any]]:
        """Monitor running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 
                                       'create_time', 'connections', 'cmdline']):
            try:
                pinfo = proc.as_dict()
                # Add additional security checks
                pinfo['signed'] = self._check_process_signature(proc.pid)
                pinfo['privileges'] = self._check_process_privileges(proc.pid)
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def _check_process_signature(self, pid: int) -> bool:
        """Check if process binary is digitally signed"""
        try:
            process = psutil.Process(pid)
            if process.exe():
                # Implement signature verification logic here
                return True
        except Exception:
            return False
        return False

    def _check_process_privileges(self, pid: int) -> List[str]:
        """Check process privileges"""
        try:
            process = psutil.Process(pid)
            privileges = []
            # Implement privilege checking logic here
            return privileges
        except Exception:
            return []

    def _collect_system_events(self) -> List[Dict[str, Any]]:
        """Collect recent system events"""
        events = []
        try:
            handle = win32evtlog.OpenEventLog(None, "System")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(handle)
            
            while True:
                events_batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events_batch:
                    break
                    
                for event in events_batch:
                    events.append({
                        'timestamp': event.TimeGenerated.Format(),
                        'source': event.SourceName,
                        'event_id': event.EventID,
                        'type': event.EventType,
                        'category': event.EventCategory
                    })
                    
                if len(events) >= 1000:  # Limit to last 1000 events
                    break
                    
            win32evtlog.CloseEventLog(handle)
        except Exception as e:
            logger.error(f"Error collecting system events: {e}")
        
        return events

    async def _analyze_system_state(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze current system state"""
        analysis = {
            'status': 'normal',
            'warnings': [],
            'critical_issues': []
        }
        
        # Check CPU usage
        if metrics['cpu_percent'] > 90:
            analysis['critical_issues'].append('CPU usage critically high')
        elif metrics['cpu_percent'] > 75:
            analysis['warnings'].append('CPU usage high')
            
        # Check memory usage
        if metrics['memory_percent'] > 90:
            analysis['critical_issues'].append('Memory usage critically high')
        elif metrics['memory_percent'] > 75:
            analysis['warnings'].append('Memory usage high')
            
        # Check disk space
        for mount, usage in metrics['disk_usage'].items():
            if usage['percent'] > 90:
                analysis['critical_issues'].append(f'Disk space critically low on {mount}')
            elif usage['percent'] > 75:
                analysis['warnings'].append(f'Disk space low on {mount}')
        
        # Update status based on issues
        if analysis['critical_issues']:
            analysis['status'] = 'critical'
        elif analysis['warnings']:
            analysis['status'] = 'warning'
            
        return analysis

    def _analyze_processes(self, processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze process behavior"""
        analysis = {
            'suspicious_processes': [],
            'resource_intensive_processes': [],
            'new_processes': []
        }
        
        for process in processes:
            # Check for suspicious processes
            if process['name'] in self.suspicious_processes:
                analysis['suspicious_processes'].append(process)
                
            # Check for resource-intensive processes
            if process['cpu_percent'] > 50 or process['memory_percent'] > 50:
                analysis['resource_intensive_processes'].append(process)
                
            # Check for newly created processes
            if datetime.fromtimestamp(process['create_time']) > datetime.now() - timedelta(minutes=5):
                analysis['new_processes'].append(process)
        
        return analysis

    def _analyze_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze system events"""
        analysis = {
            'error_events': [],
            'warning_events': [],
            'security_events': []
        }
        
        for event in events:
            if event['type'] == win32evtlog.EVENTLOG_ERROR_TYPE:
                analysis['error_events'].append(event)
            elif event['type'] == win32evtlog.EVENTLOG_WARNING_TYPE:
                analysis['warning_events'].append(event)
            elif event['source'] in ['Security', 'Microsoft-Windows-Security-Auditing']:
                analysis['security_events'].append(event)
        
        return analysis

    def _is_anomaly(self, metrics: Dict[str, Any]) -> bool:
        """Use ML to detect system anomalies"""
        try:
            features = self._extract_features(metrics)
            if features is None:
                return False

            X = np.array(features).reshape(1, -1)
            return self.anomaly_detector.predict(X)[0] == -1
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return False

    def _extract_features(self, metrics: Dict[str, Any]) -> Optional[List[float]]:
        """Extract numerical features for ML analysis"""
        try:
            features = [
                float(metrics['cpu_percent']),
                float(metrics['memory_percent']),
                float(metrics['process_count']),
                float(metrics['handle_count']),
                float(metrics['thread_count'])
            ]
            return features
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def _update_history(self, metrics: Dict[str, Any]):
        """Update system metrics history"""
        self.resource_history['system'].append({
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics
        })
        
        # Maintain history size
        if len(self.resource_history['system']) > 1000:
            self.resource_history['system'] = self.resource_history['system'][-1000:]

    async def _generate_alerts(self, analysis: Dict[str, Any]):
        """Generate alerts based on analysis results"""
        alerts = []
        
        # Check for critical system issues
        if analysis['system_metrics']['status'] == 'critical':
            alerts.append({
                'level': 'critical',
                'type': 'system_resources',
                'message': 'Critical system resource issues detected',
                'details': analysis['system_metrics']['critical_issues']
            })
            
        # Check for suspicious processes
        if analysis['process_analysis']['suspicious_processes']:
            alerts.append({
                'level': 'high',
                'type': 'suspicious_process',
                'message': 'Suspicious processes detected',
                'details': analysis['process_analysis']['suspicious_processes']
            })
            
        # Check for anomalies
        if analysis['anomalies']:
            alerts.append({
                'level': 'high',
                'type': 'anomaly',
                'message': 'System behavior anomalies detected',
                'details': analysis['anomalies']
            })
            
        # Send alerts (implement your alert mechanism here)
        if alerts:
            await self._send_alerts(alerts)

    async def _send_alerts(self, alerts: List[Dict[str, Any]]):
        """Send alerts to configured destinations"""
        # Implement your alert sending mechanism here
        # This could include sending to a message queue, email, SMS, etc.
        pass

    def close(self):
        """Clean up resources"""
        # Save historical data for future ML training
        with open('system_history.json', 'w') as f:
            json.dump(self.resource_history, f)
