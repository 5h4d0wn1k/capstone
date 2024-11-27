"""Process monitoring implementation."""

import psutil
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from loguru import logger

class ProcessMonitor:
    """Process monitoring and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config.get('process_monitor', {})
        self.enabled = self.config.get('enabled', True)
        self.monitor_interval = self.config.get('monitor_interval', 60)  # 1 minute
        self.cpu_threshold = self.config.get('cpu_threshold', 80)  # 80% CPU
        self.memory_threshold = self.config.get('memory_threshold', 80)  # 80% memory
        self.events = []
        self._stop_event = threading.Event()
        self._thread = None
        
    def start(self) -> None:
        """Start process monitoring."""
        if not self.enabled:
            logger.warning("Process monitor is disabled")
            return
            
        try:
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._monitor_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info("Process monitor started")
            
        except Exception as e:
            logger.error(f"Failed to start process monitor: {e}")
            
    def stop(self) -> None:
        """Stop process monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        logger.info("Process monitor stopped")
        
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Get process metrics
                metrics = self._collect_metrics()
                self._analyze_metrics(metrics)
                
                # Wait for next interval
                self._stop_event.wait(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Error in process monitoring loop: {e}")
                
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect process metrics.
        
        Returns:
            Process metrics
        """
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'processes': {}
            }
            
            # Collect metrics for each process
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    # Get process info
                    info = proc.info
                    pid = info['pid']
                    
                    metrics['processes'][pid] = {
                        'name': info['name'],
                        'cpu_percent': info['cpu_percent'] or 0,
                        'memory_percent': info['memory_percent'] or 0
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting process metrics: {e}")
            return {}
            
    def _analyze_metrics(self, metrics: Dict[str, Any]) -> None:
        """Analyze process metrics.
        
        Args:
            metrics: Process metrics
        """
        try:
            for pid, info in metrics['processes'].items():
                # Check CPU usage
                if info['cpu_percent'] > self.cpu_threshold:
                    self._add_event('HIGH_CPU_USAGE', 'warning', {
                        'pid': pid,
                        'name': info['name'],
                        'cpu_percent': info['cpu_percent'],
                        'threshold': self.cpu_threshold
                    })
                    
                # Check memory usage
                if info['memory_percent'] > self.memory_threshold:
                    self._add_event('HIGH_MEMORY_USAGE', 'warning', {
                        'pid': pid,
                        'name': info['name'],
                        'memory_percent': info['memory_percent'],
                        'threshold': self.memory_threshold
                    })
                    
        except Exception as e:
            logger.error(f"Error analyzing process metrics: {e}")
            
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
                f"Process monitoring event: {event_type} - Process {data['name']} ({data['pid']})"
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
