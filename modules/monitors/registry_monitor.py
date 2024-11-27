"""Windows Registry monitoring implementation."""

import winreg
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from loguru import logger

class RegistryMonitor:
    """Windows Registry monitoring and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config.get('registry_monitor', {})
        self.enabled = self.config.get('enabled', True)
        self.monitor_interval = self.config.get('monitor_interval', 300)  # 5 minutes
        self.watch_keys = self.config.get('watch_keys', [
            r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        ])
        self.events = []
        self._stop_event = threading.Event()
        self._thread = None
        self._baseline = {}
        
    def start(self) -> None:
        """Start registry monitoring."""
        if not self.enabled:
            logger.warning("Registry monitor is disabled")
            return
            
        try:
            # Create baseline
            self._baseline = self._create_baseline()
            
            # Start monitoring thread
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._monitor_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info("Registry monitor started")
            
        except Exception as e:
            logger.error(f"Failed to start registry monitor: {e}")
            
    def stop(self) -> None:
        """Stop registry monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        logger.info("Registry monitor stopped")
        
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Check registry keys
                current_state = self._scan_registry()
                self._compare_state(current_state)
                
                # Update baseline
                self._baseline = current_state
                
                # Wait for next interval
                self._stop_event.wait(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Error in registry monitoring loop: {e}")
                
    def _create_baseline(self) -> Dict[str, Any]:
        """Create registry baseline.
        
        Returns:
            Registry baseline data
        """
        try:
            return self._scan_registry()
            
        except Exception as e:
            logger.error(f"Error creating registry baseline: {e}")
            return {}
            
    def _scan_registry(self) -> Dict[str, Any]:
        """Scan registry keys.
        
        Returns:
            Registry scan data
        """
        try:
            data = {}
            
            for key_path in self.watch_keys:
                # Parse registry path
                if key_path.startswith('HKEY_LOCAL_MACHINE'):
                    hkey = winreg.HKEY_LOCAL_MACHINE
                    subkey = key_path[len('HKEY_LOCAL_MACHINE\\'):]
                elif key_path.startswith('HKEY_CURRENT_USER'):
                    hkey = winreg.HKEY_CURRENT_USER
                    subkey = key_path[len('HKEY_CURRENT_USER\\'):]
                else:
                    continue
                    
                try:
                    # Open key
                    key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                    
                    # Read values
                    values = {}
                    try:
                        i = 0
                        while True:
                            name, value, type = winreg.EnumValue(key, i)
                            values[name] = {
                                'value': value,
                                'type': type
                            }
                            i += 1
                    except WindowsError:
                        pass
                        
                    data[key_path] = values
                    winreg.CloseKey(key)
                    
                except WindowsError:
                    continue
                    
            return data
            
        except Exception as e:
            logger.error(f"Error scanning registry: {e}")
            return {}
            
    def _compare_state(self, current: Dict[str, Any]) -> None:
        """Compare current state with baseline.
        
        Args:
            current: Current registry state
        """
        try:
            for key_path in self.watch_keys:
                baseline_values = self._baseline.get(key_path, {})
                current_values = current.get(key_path, {})
                
                # Check for new values
                for name, info in current_values.items():
                    if name not in baseline_values:
                        self._add_event('REGISTRY_VALUE_ADDED', 'warning', {
                            'key': key_path,
                            'name': name,
                            'value': info['value'],
                            'type': info['type']
                        })
                    elif info != baseline_values[name]:
                        self._add_event('REGISTRY_VALUE_MODIFIED', 'warning', {
                            'key': key_path,
                            'name': name,
                            'old_value': baseline_values[name]['value'],
                            'new_value': info['value'],
                            'type': info['type']
                        })
                        
                # Check for deleted values
                for name in baseline_values:
                    if name not in current_values:
                        self._add_event('REGISTRY_VALUE_DELETED', 'warning', {
                            'key': key_path,
                            'name': name,
                            'value': baseline_values[name]['value'],
                            'type': baseline_values[name]['type']
                        })
                        
        except Exception as e:
            logger.error(f"Error comparing registry state: {e}")
            
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
                f"Registry monitoring event: {event_type} - {data['key']}\\{data['name']}"
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
