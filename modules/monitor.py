import psutil
import platform
import threading
from queue import Queue
import time
from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger
import os
import subprocess
import socket

class SystemMonitor:
    def __init__(self, config: Dict):
        """Initialize system monitor"""
        self.config = config
        self.event_queue = Queue()
        self.running = False
        self.last_metric_time = 0
        self.metric_interval = config.get('metric_interval', 60)  # seconds
        self.last_successful_check = time.time()
        self.error_count = 0
        self.max_errors = 3
        self.initialize_monitoring()
        
    def initialize_monitoring(self):
        """Initialize monitoring components"""
        # Initialize monitoring flags and queues
        self.monitoring = False
        # Initialize thresholds
        self.thresholds = self.config.get('thresholds', {
            'cpu_usage': 90,
            'memory_usage': 90,
            'disk_usage': 90,
            'network_usage': 900,  # Mbps
            'process_count': 500
        })
        
        # Initialize monitoring threads
        self.threads = []
        
        # Resource monitoring thread
        self.threads.append(threading.Thread(
            target=self._monitor_resources,
            daemon=True,
            name="ResourceMonitor"
        ))
        
        # Process monitoring thread
        self.threads.append(threading.Thread(
            target=self._monitor_processes,
            daemon=True,
            name="ProcessMonitor"
        ))
        
        # Network monitoring thread
        self.threads.append(threading.Thread(
            target=self._monitor_network,
            daemon=True,
            name="NetworkMonitor"
        ))
        
        # Service monitoring thread
        self.threads.append(threading.Thread(
            target=self._monitor_services,
            daemon=True,
            name="ServiceMonitor"
        ))
        
    def is_healthy(self) -> bool:
        """Check if monitor is healthy"""
        try:
            # Check if running
            if not self.running:
                return False
                
            # Check if metrics are being collected
            current_time = time.time()
            if current_time - self.last_metric_time > self.metric_interval * 2:
                return False
                
            # Check error count
            if self.error_count >= self.max_errors:
                return False
                
            # Try to collect metrics
            metrics = self.get_metrics()
            if not metrics:
                return False
                
            self.last_successful_check = current_time
            self.error_count = 0
            return True
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.error_count += 1
            return False
            
    def start_monitoring(self):
        """Start all monitoring threads"""
        logger.info("Starting system monitoring")
        self.monitoring = True
        
        for thread in self.threads:
            try:
                thread.start()
                logger.info(f"Started {thread.name}")
            except Exception as e:
                logger.error(f"Failed to start {thread.name}: {e}")
                
    def stop_monitoring(self):
        """Stop all monitoring threads"""
        logger.info("Stopping system monitoring")
        self.monitoring = False
        
        for thread in self.threads:
            try:
                thread.join(timeout=5)
                logger.info(f"Stopped {thread.name}")
            except Exception as e:
                logger.error(f"Error stopping {thread.name}: {e}")
                
    def start(self):
        """Start system monitoring"""
        try:
            logger.info("Starting system monitor")
            self.running = True
            self.error_count = 0
            self.last_metric_time = time.time()
            
            # Start monitoring threads
            self.start_monitoring()
            
        except Exception as e:
            logger.error(f"Failed to start system monitor: {e}")
            self.running = False
            raise
            
    def stop(self):
        """Stop system monitoring"""
        logger.info("Stopping system monitor")
        self.running = False
        
    def get_metrics(self) -> Dict:
        """Get current system metrics"""
        try:
            metrics = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': {p.mountpoint: psutil.disk_usage(p.mountpoint).percent 
                               for p in psutil.disk_partitions()},
                'network_connections': len(psutil.net_connections()),
                'process_count': len(list(psutil.process_iter())),
                'last_update': datetime.now().isoformat()
            }
            self.last_metric_time = time.time()
            return metrics
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            self.error_count += 1
            return {}
            
    def _monitor_resources(self):
        """Monitor system resources"""
        while self.monitoring:
            try:
                # CPU Usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.thresholds['cpu_usage']:
                    self._raise_alert({
                        'type': 'high_cpu_usage',
                        'value': cpu_percent,
                        'threshold': self.thresholds['cpu_usage'],
                        'timestamp': datetime.now().isoformat()
                    })
                    
                # Memory Usage
                memory = psutil.virtual_memory()
                if memory.percent > self.thresholds['memory_usage']:
                    self._raise_alert({
                        'type': 'high_memory_usage',
                        'value': memory.percent,
                        'threshold': self.thresholds['memory_usage'],
                        'timestamp': datetime.now().isoformat()
                    })
                    
                # Disk Usage
                for partition in psutil.disk_partitions():
                    usage = psutil.disk_usage(partition.mountpoint)
                    if usage.percent > self.thresholds['disk_usage']:
                        self._raise_alert({
                            'type': 'high_disk_usage',
                            'partition': partition.mountpoint,
                            'value': usage.percent,
                            'threshold': self.thresholds['disk_usage'],
                            'timestamp': datetime.now().isoformat()
                        })
                        
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                
            time.sleep(60)
            
    def _monitor_processes(self):
        """Monitor system processes"""
        last_check = time.time()
        while self.monitoring:
            try:
                current_time = time.time()
                # Only update if enough time has passed (1 second)
                if current_time - last_check < 1.0:
                    time.sleep(0.1)  # Short sleep to prevent CPU overload
                    continue
                    
                last_check = current_time
                # Track all processes and high resource processes separately
                all_processes = []
                high_resource_processes = []
                
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        pinfo = proc.info
                        # Ensure process_count calculation doesn't fail
                        if not isinstance(pinfo, dict):
                            pinfo = {
                                'pid': proc.pid,
                                'name': proc.name(),
                                'cpu_percent': proc.cpu_percent() or 0,
                                'memory_percent': proc.memory_percent() or 0
                            }
                        all_processes.append(pinfo)
                        
                        # Track processes with high resource usage separately
                        if pinfo['cpu_percent'] > 50 or pinfo['memory_percent'] > 50:
                            high_resource_processes.append(pinfo)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        logger.warning(f"Error processing individual process: {e}")
                        continue
                
                # Update metrics immediately
                self.current_metrics.update({
                    'process_count': len(all_processes),
                    'high_resource_processes': len(high_resource_processes),
                    'timestamp': datetime.now().isoformat()
                })
                
                # Check thresholds and raise alerts if needed
                if len(all_processes) > self.thresholds.get('process_count', 500):
                    self._raise_alert({
                        'type': 'high_process_count',
                        'count': len(all_processes),
                        'threshold': self.thresholds.get('process_count', 500),
                        'timestamp': datetime.now().isoformat()
                    })
                
                if high_resource_processes:
                    self._raise_alert({
                        'type': 'high_resource_processes',
                        'count': len(high_resource_processes),
                        'processes': [
                            {
                                'pid': p['pid'],
                                'name': p['name'],
                                'cpu': p['cpu_percent'],
                                'memory': p['memory_percent']
                            }
                            for p in high_resource_processes
                        ],
                        'timestamp': datetime.now().isoformat()
                    })
                
            except Exception as e:
                logger.error(f"Process monitoring error: {e}")
                self.error_count += 1
                if self.error_count >= self.max_errors:
                    logger.error("Max process monitoring errors reached")
                    self.monitoring = False
                    break
            
    def _monitor_network(self):
        """Monitor network usage and connections"""
        last_check = time.time()
        last_bytes_sent = 0
        last_bytes_recv = 0
        
        while self.monitoring:
            try:
                current_time = time.time()
                # Only update if enough time has passed (0.5 seconds)
                if current_time - last_check < 0.5:
                    time.sleep(0.05)  # Very short sleep
                    continue
                
                time_diff = current_time - last_check
                last_check = current_time
                
                # Get current network stats
                net_io = psutil.net_io_counters()
                connections = psutil.net_connections(kind='inet')
                
                # Calculate network usage
                bytes_sent = net_io.bytes_sent
                bytes_recv = net_io.bytes_recv
                
                if last_bytes_sent > 0:  # Skip first iteration
                    # Calculate rates
                    bytes_sent_sec = (bytes_sent - last_bytes_sent) / time_diff
                    bytes_recv_sec = (bytes_recv - last_bytes_recv) / time_diff
                    
                    # Calculate total network usage in Mbps
                    total_usage_mbps = (bytes_sent_sec + bytes_recv_sec) * 8 / 1_000_000
                    
                    # Update metrics immediately
                    self.current_metrics.update({
                        'network_usage_mbps': total_usage_mbps,
                        'bytes_sent_sec': bytes_sent_sec,
                        'bytes_recv_sec': bytes_recv_sec,
                        'established_connections': sum(1 for conn in connections if conn.status == 'ESTABLISHED'),
                        'listening_ports': sum(1 for conn in connections if conn.status == 'LISTEN'),
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Check against threshold (900 Mbps = 90% of 1Gbps)
                    if total_usage_mbps > self.thresholds.get('network_usage', 900):
                        self._raise_alert({
                            'type': 'high_network_usage',
                            'usage_mbps': total_usage_mbps,
                            'threshold_mbps': self.thresholds.get('network_usage', 900),
                            'timestamp': datetime.now().isoformat()
                        })
                
                # Update last values
                last_bytes_sent = bytes_sent
                last_bytes_recv = bytes_recv
                
            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                self.error_count += 1
                if self.error_count >= self.max_errors:
                    logger.error("Max network monitoring errors reached")
                    self.monitoring = False
                    break

    def _monitor_services(self):
        """Monitor system services"""
        while self.monitoring:
            try:
                if platform.system() == 'Windows':
                    # Windows services
                    output = subprocess.check_output(['sc', 'query'], text=True)
                    services = self._parse_windows_services(output)
                else:
                    # Unix/Linux services
                    output = subprocess.check_output(['systemctl', 'list-units', '--type=service'], text=True)
                    services = self._parse_unix_services(output)
                    
                self._check_service_status(services)
                
            except Exception as e:
                logger.error(f"Service monitoring error: {e}")
                
            time.sleep(300)

    def _is_suspicious_process(self, proc: Dict) -> bool:
        """Check if a process is suspicious"""
        suspicious_names = [
            'cmd.exe', 'powershell.exe', 'netcat', 'ncat',
            'mimikatz', 'psexec', 'regsvr32'
        ]
        
        return any(name.lower() in proc['name'].lower() for name in suspicious_names)
        
    def _check_suspicious_ports(self, ports: List[int]):
        """Check for suspicious listening ports"""
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999]  # Common backdoor ports
        
        return [port for port in ports if port in suspicious_ports]
        
    def _is_suspicious_service(self, service: Dict) -> bool:
        """Check if a service is suspicious"""
        suspicious_keywords = ['remote', 'backdoor', 'vnc', 'proxy']
        
        return any(keyword in service['name'].lower() for keyword in suspicious_keywords)
        
    def _parse_windows_services(self, output: str) -> List[Dict]:
        """Parse Windows services output"""
        services = []
        current_service = {}
        
        for line in output.splitlines():
            if line.startswith('SERVICE_NAME'):
                if current_service:
                    services.append(current_service)
                current_service = {'name': line.split(':')[1].strip()}
            elif line.strip().startswith('STATE'):
                current_service['state'] = line.split(':')[1].strip()
                
        if current_service:
            services.append(current_service)
            
        return services
        
    def _parse_unix_services(self, output: str) -> List[Dict]:
        """Parse Unix/Linux services output"""
        services = []
        
        for line in output.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 4:
                services.append({
                    'name': parts[0],
                    'status': parts[2],
                    'description': ' '.join(parts[3:])
                })
                
        return services
        
    def _check_service_status(self, services: List[Dict]):
        """Check service status and raise alerts for suspicious changes"""
        for service in services:
            # Check for stopped critical services
            if service.get('status') == 'STOPPED' and service.get('name') in [
                'sshd', 'httpd', 'nginx', 'mysql', 'postgresql',
                'wuauserv', 'wscsvc', 'WinDefend', 'MsMpSvc'
            ]:
                self._raise_alert({
                    'type': 'critical_service_stopped',
                    'service': service.get('name'),
                    'status': service.get('status'),
                    'timestamp': datetime.now().isoformat()
                })
            
            # Check for suspicious service status changes
            if service.get('status') not in ['RUNNING', 'STOPPED', 'STARTING', 'STOPPING']:
                self._raise_alert({
                    'type': 'suspicious_service_status',
                    'service': service.get('name'),
                    'status': service.get('status'),
                    'timestamp': datetime.now().isoformat()
                })

    def get_system_info(self) -> Dict:
        """Get comprehensive system information"""
        try:
            info = {
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'ram': psutil.virtual_memory().total,
                'cpu_count': psutil.cpu_count(),
                'disk_partitions': [],
                'network_interfaces': []
            }
            
            # Disk information
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info['disk_partitions'].append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except Exception:
                    continue
                    
            # Network information
            for interface, addrs in psutil.net_if_addrs().items():
                nic_info = {'name': interface, 'addresses': []}
                for addr in addrs:
                    nic_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                    })
                info['network_interfaces'].append(nic_info)
                
            return info
            
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}

    def _raise_alert(self, alert: Dict):
        """Add alert to event queue"""
        self.event_queue.put(alert)
        logger.warning(f"System Monitor Alert: {alert}")
