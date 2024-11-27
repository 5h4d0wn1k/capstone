#!/usr/bin/env python3

import os
import sys
import time
import threading
import psutil
from datetime import datetime
from typing import Dict, Any, Optional
from loguru import logger

class SystemMonitor:
    """Windows system monitoring component."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize system monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config.get('monitor', {})
        self.enabled = self.config.get('enabled', True)
        self.interval = self.config.get('interval', 5)
        self.thresholds = self.config.get('thresholds', {
            'cpu': 90,
            'memory': 85,
            'disk': 95
        })
        self._stop_event = threading.Event()
        self._monitor_thread = None
        
    def start_monitoring(self) -> None:
        """Start system monitoring thread."""
        if not self.enabled:
            logger.warning("System monitoring is disabled")
            return
            
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.warning("Monitoring thread already running")
            return
            
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("System monitoring started")
        
    def stop_monitoring(self) -> None:
        """Stop system monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._stop_event.set()
            self._monitor_thread.join()
            logger.info("System monitoring stopped")
            
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage.
        
        Returns:
            CPU usage percentage
        """
        return psutil.cpu_percent(interval=1)
        
    def get_memory_usage(self) -> float:
        """Get current memory usage percentage.
        
        Returns:
            Memory usage percentage
        """
        return psutil.virtual_memory().percent
        
    def get_disk_usage(self, path: str = '/') -> float:
        """Get disk usage percentage for given path.
        
        Args:
            path: Path to check disk usage for
            
        Returns:
            Disk usage percentage
        """
        return psutil.disk_usage(path).percent
        
    def check_cpu_alert(self) -> Optional[str]:
        """Check if CPU usage exceeds threshold.
        
        Returns:
            Alert message if threshold exceeded, None otherwise
        """
        usage = self.get_cpu_usage()
        if usage > self.thresholds['cpu']:
            return f"CPU usage exceeded threshold: {usage}% > {self.thresholds['cpu']}%"
        return None
        
    def check_memory_alert(self) -> Optional[str]:
        """Check if memory usage exceeds threshold.
        
        Returns:
            Alert message if threshold exceeded, None otherwise
        """
        usage = self.get_memory_usage()
        if usage > self.thresholds['memory']:
            return f"Memory usage exceeded threshold: {usage}% > {self.thresholds['memory']}%"
        return None
        
    def check_disk_alert(self, path: str = '/') -> Optional[str]:
        """Check if disk usage exceeds threshold.
        
        Args:
            path: Path to check disk usage for
            
        Returns:
            Alert message if threshold exceeded, None otherwise
        """
        usage = self.get_disk_usage(path)
        if usage > self.thresholds['disk']:
            return f"Disk usage exceeded threshold: {usage}% > {self.thresholds['disk']}%"
        return None
        
    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Check CPU
                if alert := self.check_cpu_alert():
                    logger.warning(alert)
                    
                # Check memory
                if alert := self.check_memory_alert():
                    logger.warning(alert)
                    
                # Check disk
                if alert := self.check_disk_alert():
                    logger.warning(alert)
                    
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                
            time.sleep(self.interval)
