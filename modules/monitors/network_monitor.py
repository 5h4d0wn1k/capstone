"""Network monitoring module."""

import psutil
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from loguru import logger
import threading

class NetworkMonitor:
    """Network monitoring class."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config.get('network_monitor', {})
        self.enabled = self.config.get('enabled', True)
        self.interval = self.config.get('interval', 5)
        self.thresholds = self.config.get('thresholds', {
            'bytes_sent': 1000000,  # 1MB/s
            'bytes_recv': 1000000,  # 1MB/s
            'packets_sent': 1000,   # 1K packets/s
            'packets_recv': 1000    # 1K packets/s
        })
        self._stop_event = threading.Event()
        self._thread = None
        self.stats = []
        
    def start(self) -> None:
        """Start monitoring."""
        if not self.enabled:
            logger.warning("Network monitoring is disabled")
            return
            
        try:
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._monitor_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info("Network monitoring started")
            
        except Exception as e:
            logger.error(f"Failed to start network monitoring: {e}")
            
    def stop(self) -> None:
        """Stop monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        logger.info("Network monitoring stopped")
        
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        last_counters = psutil.net_io_counters()
        last_time = time.time()
        
        while not self._stop_event.is_set():
            try:
                time.sleep(self.interval)
                
                # Get current counters
                current_counters = psutil.net_io_counters()
                current_time = time.time()
                time_delta = current_time - last_time
                
                # Calculate rates
                stats = {
                    'timestamp': datetime.now(),
                    'bytes_sent_per_sec': (current_counters.bytes_sent - last_counters.bytes_sent) / time_delta,
                    'bytes_recv_per_sec': (current_counters.bytes_recv - last_counters.bytes_recv) / time_delta,
                    'packets_sent_per_sec': (current_counters.packets_sent - last_counters.packets_sent) / time_delta,
                    'packets_recv_per_sec': (current_counters.packets_recv - last_counters.packets_recv) / time_delta
                }
                
                # Check thresholds
                alerts = []
                for metric, value in stats.items():
                    if metric in self.thresholds and value > self.thresholds[metric]:
                        alerts.append({
                            'metric': metric,
                            'value': value,
                            'threshold': self.thresholds[metric],
                            'timestamp': datetime.now()
                        })
                
                if alerts:
                    logger.warning(f"Network thresholds exceeded: {alerts}")
                
                # Store stats
                self.stats.append(stats)
                if len(self.stats) > 1000:  # Keep last 1000 readings
                    self.stats.pop(0)
                
                # Update last values
                last_counters = current_counters
                last_time = current_time
                
            except Exception as e:
                logger.error(f"Error in network monitoring loop: {e}")
                time.sleep(1)  # Avoid rapid retries on persistent errors
                
    def get_stats(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get collected statistics.
        
        Args:
            limit: Optional limit on number of stats to return
            
        Returns:
            List of network statistics
        """
        if limit:
            return self.stats[-limit:]
        return self.stats
