from typing import Dict, List, Optional
import threading
import queue
import json
import time
from loguru import logger
from .base import BaseEventCollector

class WindowsEventCollector(BaseEventCollector):
    """Windows event collector for Windows Event Log"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "windows_event"
        self.event_sources = config.get('event_sources', [
            'System', 'Security', 'Application'
        ])
        self.event_types = config.get('event_types', [
            'Error', 'Warning', 'Information'
        ])
        self.initialize_collector()

    def initialize_collector(self):
        """Initialize Windows event collector"""
        try:
            # Only import Windows-specific modules if we're on Windows
            import platform
            if platform.system() == 'Windows':
                import wmi
                import win32com.client
                import win32security
                import win32api
                import win32con
                
                # Initialize COM in this thread
                import pythoncom
                pythoncom.CoInitialize()
                
                # Get current process token and enable required privileges
                priv_flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
                h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), priv_flags)
                
                # Enable required privileges
                privileges = [
                    'SeSecurityPrivilege',
                    'SeBackupPrivilege',
                    'SeSystemtimePrivilege',
                    'SeTakeOwnershipPrivilege'
                ]
                
                for privilege in privileges:
                    try:
                        win32security.LookupPrivilegeValue(None, privilege)
                        # Enable the privilege
                        privs = [(win32security.LookupPrivilegeValue(None, privilege),
                                win32con.SE_PRIVILEGE_ENABLED)]
                        win32security.AdjustTokenPrivileges(h_token, 0, privs)
                    except Exception as e:
                        logger.warning(f"Could not enable privilege {privilege}: {e}")
                
                # Initialize WMI with security privileges
                self.wmi = wmi.WMI(privileges=["Security"])
                logger.info("Windows Event Collector initialized with elevated privileges")
            else:
                raise RuntimeError("Windows Event Collector can only run on Windows")
        except ImportError as e:
            logger.error(f"Required Windows modules not available: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Windows Event Collector: {e}")
            raise

    def _collect_events(self) -> Optional[List]:
        """Collect Windows events"""
        if not hasattr(self, 'wmi'):
            return None

        try:
            import pythoncom
            pythoncom.CoInitialize()
            
            events = []
            for source in self.event_sources:
                try:
                    query = f"SELECT * FROM Win32_NTLogEvent WHERE Logfile = '{source}'"
                    if self.event_types:
                        types_str = "', '".join(self.event_types)
                        query += f" AND EventType IN ('{types_str}')"
                    query += f" AND TimeGenerated > '{self._get_last_query_time()}'"
                    
                    source_events = self.wmi.query(query)
                    if source_events:
                        events.extend(source_events)
                        
                except Exception as e:
                    logger.error(f"Error querying events from {source}: {e}")
                    continue
                    
            return events
            
        except Exception as e:
            logger.error(f"Error collecting Windows events: {e}")
            self.error_count += 1
            return None
            
        finally:
            pythoncom.CoUninitialize()

    def _normalize_event(self, event) -> Dict:
        """Normalize Windows event to common format"""
        try:
            return {
                'timestamp': self._convert_windows_time(event.TimeGenerated),
                'source': f"windows_{event.Logfile}",
                'event_type': event.Type,
                'event_id': event.EventCode,
                'severity': self._map_event_type(event.EventType),
                'message': event.Message,
                'computer': event.ComputerName,
                'raw_data': {
                    'record_number': event.RecordNumber,
                    'source_name': event.SourceName,
                    'time_written': event.TimeWritten,
                    'event_identifier': event.EventIdentifier,
                    'category': event.Category,
                    'user': event.User
                }
            }
        except Exception as e:
            logger.error(f"Error normalizing Windows event: {e}")
            return {
                'timestamp': time.time(),
                'source': 'windows_unknown',
                'event_type': 'unknown',
                'severity': 'unknown',
                'message': str(event),
                'raw_data': event
            }

    def _map_event_type(self, event_type: int) -> str:
        """Map Windows event type to standard severity"""
        mapping = {
            1: 'error',
            2: 'warning',
            3: 'info',
            4: 'info',
            5: 'info'
        }
        return mapping.get(event_type, 'unknown')

    def _convert_windows_time(self, time_str: str) -> float:
        """Convert Windows time string to Unix timestamp"""
        try:
            from datetime import datetime
            dt = datetime.strptime(str(time_str), '%Y%m%d%H%M%S.%f')
            return dt.timestamp()
        except Exception:
            return time.time()

    def _get_last_query_time(self) -> str:
        """Get formatted time for WMI query"""
        from datetime import datetime, timedelta
        last_time = datetime.fromtimestamp(self.last_event_time)
        return last_time.strftime('%Y%m%d%H%M%S.000000-000')

    def is_healthy(self) -> bool:
        """Check if collector is healthy"""
        try:
            # Check if running
            if not self.running:
                return False
                
            # Check if events are being collected
            current_time = time.time()
            if current_time - self.last_event_time > self.event_check_interval:
                return False
                
            # Check error count
            if self.error_count >= self.max_errors:
                return False
                
            # Try to query events
            events = self._collect_events()
            if events is None:
                return False
                
            self.error_count = 0
            return True
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.error_count += 1
            return False
            
    def start(self):
        """Start collecting Windows events"""
        try:
            logger.info("Starting Windows Event Collector")
            self.running = True
            self.error_count = 0
            
            # Start collection thread
            self.collection_thread = threading.Thread(
                target=self._run,
                daemon=True,
                name="WindowsEventCollector"
            )
            self.collection_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start Windows Event Collector: {e}")
            self.running = False
            raise
            
    def stop(self):
        """Stop collecting Windows events"""
        logger.info("Stopping Windows Event Collector")
        self.running = False
        if hasattr(self, 'collection_thread'):
            self.collection_thread.join(timeout=5)
            
    def _run(self):
        """Run the collector"""
        while self.running:
            try:
                events = self._collect_events()
                if events:
                    for event in events:
                        normalized_event = self._normalize_event(event)
                        self.event_queue.put(normalized_event)
                    self.last_event_time = time.time()
                    
            except Exception as e:
                logger.error(f"Error running Windows Event Collector: {e}")
                self.error_count += 1
                if self.error_count >= self.max_errors:
                    logger.error("Max errors reached, stopping collector")
                    self.running = False
                    break
                    
            time.sleep(10)  # Wait before next collection
