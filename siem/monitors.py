"""Advanced monitoring system."""

import os
import psutil
import win32evtlog
import win32con
import win32api
import win32security
import win32file
import winreg
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Generator
from loguru import logger

class BaseMonitor:
    """Base class for all monitors."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config
        self.running = False
        
    def start(self) -> None:
        """Start monitoring."""
        self.running = True
        
    def stop(self) -> None:
        """Stop monitoring."""
        self.running = False
        
    def get_status(self) -> Dict[str, Any]:
        """Get monitor status.
        
        Returns:
            Status dictionary
        """
        return {
            "running": self.running,
            "type": self.__class__.__name__
        }

class ProcessMonitor(BaseMonitor):
    """Process monitoring."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize process monitor.
        
        Args:
            config: Monitor configuration
        """
        super().__init__(config)
        self.suspicious_processes = config.get("suspicious_processes", [])
        self.max_cpu_percent = config.get("max_cpu_percent", 90)
        self.max_memory_percent = config.get("max_memory_percent", 90)
        
    def get_processes(self) -> List[Dict[str, Any]]:
        """Get running processes.
        
        Returns:
            List of process information
        """
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 
                                       'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                processes.append({
                    "pid": pinfo["pid"],
                    "name": pinfo["name"],
                    "user": pinfo["username"],
                    "cpu_percent": pinfo["cpu_percent"],
                    "memory_percent": pinfo["memory_percent"]
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        return processes
        
    def check_suspicious(self) -> List[Dict[str, Any]]:
        """Check for suspicious processes.
        
        Returns:
            List of suspicious process information
        """
        suspicious = []
        process_memory_history = {}
        
        for proc in self.get_processes():
            # Check against suspicious process names
            if proc["name"].lower() in self.suspicious_processes:
                suspicious.append({
                    "type": "suspicious_name",
                    "process": proc
                })
                
            # Check resource usage
            if proc["cpu_percent"] > self.max_cpu_percent:
                suspicious.append({
                    "type": "high_cpu",
                    "process": proc
                })
                
            if proc["memory_percent"] > self.max_memory_percent:
                suspicious.append({
                    "type": "high_memory",
                    "process": proc
                })
            
            # Memory leak detection
            pid = proc["pid"]
            current_memory = proc["memory_percent"]
            
            if pid in process_memory_history:
                previous_memory = process_memory_history[pid]
                if current_memory > previous_memory * 1.5:  # 50% increase threshold
                    suspicious.append({
                        "type": "possible_memory_leak",
                        "process": proc,
                        "previous_memory": previous_memory,
                        "current_memory": current_memory
                    })
            
            process_memory_history[pid] = current_memory
                
        return suspicious

class NetworkMonitor(BaseMonitor):
    """Network monitoring."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize network monitor.
        
        Args:
            config: Monitor configuration
        """
        super().__init__(config)
        self.suspicious_ports = config.get("suspicious_ports", [])
        self.suspicious_ips = config.get("suspicious_ips", [])
        self.traffic_threshold = config.get("traffic_threshold", 1000000)  # 1MB/s
        self.connection_history = {}
        
    def get_connections(self) -> List[Dict[str, Any]]:
        """Get network connections.
        
        Returns:
            List of connection information
        """
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status == 'ESTABLISHED':
                    process = psutil.Process(conn.pid)
                    connections.append({
                        "local_address": conn.laddr,
                        "remote_address": conn.raddr,
                        "status": conn.status,
                        "pid": conn.pid,
                        "process_name": process.name(),
                        "bytes_sent": process.io_counters().write_bytes,
                        "bytes_recv": process.io_counters().read_bytes
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        return connections
        
    def analyze_traffic(self, connection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze network traffic for suspicious patterns.
        
        Args:
            connection: Connection information
            
        Returns:
            Traffic analysis results if suspicious, None otherwise
        """
        pid = connection["pid"]
        current_time = datetime.now()
        
        if pid in self.connection_history:
            last_check = self.connection_history[pid]["timestamp"]
            last_bytes = self.connection_history[pid]["bytes_total"]
            
            time_diff = (current_time - last_check).total_seconds()
            if time_diff <= 0:  # Avoid division by zero
                return None
            
            current_bytes = connection["bytes_sent"] + connection["bytes_recv"]
            bytes_diff = current_bytes - last_bytes
            
            bytes_per_second = bytes_diff / time_diff
            
            if bytes_per_second > self.traffic_threshold:
                return {
                    "type": "high_traffic",
                    "bytes_per_second": bytes_per_second,
                    "process": connection
                }
        
        self.connection_history[pid] = {
            "timestamp": current_time,
            "bytes_total": connection["bytes_sent"] + connection["bytes_recv"]
        }
        
        return None
        
    def check_suspicious(self) -> List[Dict[str, Any]]:
        """Check for suspicious connections.
        
        Returns:
            List of suspicious connection information
        """
        suspicious = []
        connections = self.get_connections()
        
        for conn in connections:
            # Check suspicious ports
            if conn["remote_address"].port in self.suspicious_ports:
                suspicious.append({
                    "type": "suspicious_port",
                    "connection": conn
                })
                
            # Check suspicious IPs
            if conn["remote_address"].ip in self.suspicious_ips:
                suspicious.append({
                    "type": "suspicious_ip",
                    "connection": conn
                })
            
            # Analyze traffic patterns
            traffic_analysis = self.analyze_traffic(conn)
            if traffic_analysis:
                suspicious.append(traffic_analysis)
                
        return suspicious

class FileMonitor(BaseMonitor):
    """File system monitoring."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize file monitor.
        
        Args:
            config: Monitor configuration
        """
        super().__init__(config)
        self.monitored_paths = config.get("monitored_paths", [])
        self.file_types = config.get("file_types", [])
        self.file_hashes = {}
        
    def calculate_file_hash(self, filepath: str) -> Optional[str]:
        """Calculate SHA-256 hash of a file.
        
        Args:
            filepath: Path to file
            
        Returns:
            File hash if successful, None otherwise
        """
        import hashlib
        
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, OSError):
            return None
            
    def check_file_integrity(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Check file integrity.
        
        Args:
            filepath: Path to file
            
        Returns:
            Integrity check results if modified, None otherwise
        """
        current_hash = self.calculate_file_hash(filepath)
        
        if not current_hash:
            return None
            
        if filepath in self.file_hashes:
            if current_hash != self.file_hashes[filepath]:
                return {
                    "type": "file_modified",
                    "path": filepath,
                    "old_hash": self.file_hashes[filepath],
                    "new_hash": current_hash
                }
        else:
            self.file_hashes[filepath] = current_hash
            
        return None
        
    def get_file_changes(self, path: str) -> Generator[Dict[str, Any], None, None]:
        """Monitor file changes in a directory.
        
        Args:
            path: Directory path to monitor
            
        Yields:
            File change information
        """
        try:
            for root, _, files in os.walk(path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Check file type
                    if self.file_types and not any(filename.endswith(ft) for ft in self.file_types):
                        continue
                    
                    # Get file stats
                    try:
                        stats = os.stat(filepath)
                        
                        # Check integrity
                        integrity_check = self.check_file_integrity(filepath)
                        if integrity_check:
                            yield integrity_check
                        
                        yield {
                            "type": "file_stats",
                            "path": filepath,
                            "size": stats.st_size,
                            "modified": datetime.fromtimestamp(stats.st_mtime),
                            "accessed": datetime.fromtimestamp(stats.st_atime),
                            "created": datetime.fromtimestamp(stats.st_ctime)
                        }
                    except (OSError, IOError):
                        continue
        except (OSError, IOError):
            pass

class RegistryMonitor(BaseMonitor):
    """Windows registry monitoring."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize registry monitor.
        
        Args:
            config: Monitor configuration
        """
        super().__init__(config)
        self.monitored_keys = config.get("monitored_keys", [])
        self.restore_points = self.get_system_restore_points()
        
    def get_system_restore_points(self) -> List[Dict[str, Any]]:
        """Get system restore points.
        
        Returns:
            List of restore point information
        """
        restore_points = []
        
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore",
                               0, winreg.KEY_READ)
                               
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    
                    try:
                        description = winreg.QueryValueEx(subkey, "Description")[0]
                        type_value = winreg.QueryValueEx(subkey, "RestorePointType")[0]
                        creation_time = winreg.QueryValueEx(subkey, "CreationTime")[0]
                        
                        restore_points.append({
                            "sequence_number": subkey_name,
                            "description": description,
                            "type": type_value,
                            "creation_time": datetime.fromtimestamp(creation_time)
                        })
                    except WindowsError:
                        pass
                        
                    winreg.CloseKey(subkey)
                    i += 1
                except WindowsError:
                    break
                    
            winreg.CloseKey(key)
        except WindowsError:
            pass
            
        return restore_points
        
    def check_restore_point_changes(self) -> List[Dict[str, Any]]:
        """Check for system restore point changes.
        
        Returns:
            List of restore point changes
        """
        changes = []
        current_points = self.get_system_restore_points()
        
        # Check for new restore points
        for point in current_points:
            if point not in self.restore_points:
                changes.append({
                    "type": "restore_point_created",
                    "restore_point": point
                })
                
        # Check for removed restore points
        for point in self.restore_points:
            if point not in current_points:
                changes.append({
                    "type": "restore_point_removed",
                    "restore_point": point
                })
                
        self.restore_points = current_points
        return changes
