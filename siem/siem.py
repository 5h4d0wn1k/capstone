"""Main SIEM system implementation."""

from .monitors import ProcessMonitor, NetworkMonitor, FileMonitor, RegistryMonitor
from loguru import logger
from typing import Dict, Any, List
import threading
import time
from web.app import start_web_interface, event_queue
from datetime import datetime

class SIEM:
    """Main SIEM system class."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize SIEM system.
        
        Args:
            config: System configuration
        """
        self.config = config
        self.monitors = []
        self.running = False
        self._init_monitors()
        
    def _init_monitors(self) -> None:
        """Initialize monitoring components."""
        try:
            # Initialize process monitor
            if self.config.get("process_monitoring", {}).get("enabled", True):
                self.monitors.append(
                    ProcessMonitor(self.config.get("process_monitoring", {}))
                )
                
            # Initialize network monitor    
            if self.config.get("network_monitoring", {}).get("enabled", True):
                self.monitors.append(
                    NetworkMonitor(self.config.get("network_monitoring", {}))
                )
                
            # Initialize file monitor
            if self.config.get("file_monitoring", {}).get("enabled", True):
                self.monitors.append(
                    FileMonitor(self.config.get("file_monitoring", {}))
                )
                
            # Initialize registry monitor
            if self.config.get("registry_monitoring", {}).get("enabled", True):
                self.monitors.append(
                    RegistryMonitor(self.config.get("registry_monitoring", {}))
                )
                
            logger.info(f"Initialized {len(self.monitors)} monitors")
            
        except Exception as e:
            logger.error(f"Failed to initialize monitors: {e}")
            raise
            
    def _broadcast_event(self, event_type: str, source: str, description: str, severity: str = "low") -> None:
        """Broadcast event to web interface.
        
        Args:
            event_type: Type of event
            source: Event source
            description: Event description
            severity: Event severity (low, medium, high)
        """
        event = {
            "type": event_type,
            "source": source,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        event_queue.put(event)
            
    def run(self, debug: bool = False) -> None:
        """Run SIEM system.
        
        Args:
            debug: Enable debug mode
        """
        self.running = True
        
        # Start web interface
        web_thread = threading.Thread(
            target=start_web_interface,
            args=(self,),
            kwargs={"debug": debug}
        )
        web_thread.daemon = True
        web_thread.start()
        logger.info("Started web interface")
        
        # Start all monitors
        for monitor in self.monitors:
            try:
                monitor.start()
                logger.info(f"Started {monitor.__class__.__name__}")
                self._broadcast_event(
                    "monitor_started",
                    monitor.__class__.__name__,
                    f"Started {monitor.__class__.__name__} monitor",
                    "low"
                )
            except Exception as e:
                logger.error(f"Failed to start {monitor.__class__.__name__}: {e}")
                self._broadcast_event(
                    "monitor_error",
                    monitor.__class__.__name__,
                    f"Failed to start {monitor.__class__.__name__}: {e}",
                    "high"
                )
                
        try:
            while self.running:
                for monitor in self.monitors:
                    try:
                        # Check for suspicious activity
                        if hasattr(monitor, "check_suspicious"):
                            results = monitor.check_suspicious()
                            if results:
                                for result in results:
                                    logger.warning(
                                        f"Suspicious activity detected by {monitor.__class__.__name__}: {result}"
                                    )
                                    self._broadcast_event(
                                        "suspicious_activity",
                                        monitor.__class__.__name__,
                                        str(result),
                                        "high"
                                    )
                                    
                        # Check for file changes
                        if isinstance(monitor, FileMonitor):
                            for path in monitor.monitored_paths:
                                for change in monitor.get_file_changes(path):
                                    logger.info(f"File change detected: {change}")
                                    self._broadcast_event(
                                        "file_change",
                                        "FileMonitor",
                                        f"Change detected in {change['path']}: {change['type']}",
                                        "medium"
                                    )
                                    
                        # Check for registry changes
                        if isinstance(monitor, RegistryMonitor):
                            changes = monitor.check_restore_point_changes()
                            for change in changes:
                                logger.info(f"Registry change detected: {change}")
                                self._broadcast_event(
                                    "registry_change",
                                    "RegistryMonitor",
                                    f"Restore point {change['type']}: {change['restore_point']['description']}",
                                    "medium"
                                )
                                
                    except Exception as e:
                        logger.error(f"Error in {monitor.__class__.__name__}: {e}")
                        self._broadcast_event(
                            "monitor_error",
                            monitor.__class__.__name__,
                            f"Error in {monitor.__class__.__name__}: {e}",
                            "high"
                        )
                        
                # Sleep to prevent high CPU usage
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown()
            
    def shutdown(self) -> None:
        """Shutdown SIEM system."""
        self.running = False
        
        # Stop all monitors
        for monitor in self.monitors:
            try:
                monitor.stop()
                logger.info(f"Stopped {monitor.__class__.__name__}")
                self._broadcast_event(
                    "monitor_stopped",
                    monitor.__class__.__name__,
                    f"Stopped {monitor.__class__.__name__} monitor",
                    "low"
                )
            except Exception as e:
                logger.error(f"Failed to stop {monitor.__class__.__name__}: {e}")
                self._broadcast_event(
                    "monitor_error",
                    monitor.__class__.__name__,
                    f"Failed to stop {monitor.__class__.__name__}: {e}",
                    "high"
                )
