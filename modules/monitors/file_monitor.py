"""File system monitoring implementation."""

import os
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from loguru import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

class FileEventHandler(FileSystemEventHandler):
    """File system event handler."""
    
    def __init__(self, callback):
        """Initialize handler.
        
        Args:
            callback: Function to call on file system events
        """
        self.callback = callback
        
    def on_any_event(self, event: FileSystemEvent):
        """Handle any file system event.
        
        Args:
            event: File system event
        """
        self.callback(event)

class FileMonitor:
    """File system monitoring and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config.get('file_monitor', {})
        self.enabled = self.config.get('enabled', True)
        self.watch_paths = self.config.get('watch_paths', [])
        self.recursive = self.config.get('recursive', True)
        self.events = []
        self._stop_event = threading.Event()
        self._thread = None
        self._observer = None
        
    def start(self) -> None:
        """Start file system monitoring."""
        if not self.enabled:
            logger.warning("File monitor is disabled")
            return
            
        try:
            # Start file system observer
            self._observer = Observer()
            handler = FileEventHandler(self._handle_event)
            
            for path in self.watch_paths:
                if os.path.exists(path):
                    self._observer.schedule(handler, path, recursive=self.recursive)
                    
            self._observer.start()
            
            # Start monitoring thread
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._monitor_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info("File monitor started")
            
        except Exception as e:
            logger.error(f"Failed to start file monitor: {e}")
            
    def stop(self) -> None:
        """Stop file system monitoring."""
        self._stop_event.set()
        if self._observer:
            self._observer.stop()
            self._observer.join()
        if self._thread:
            self._thread.join()
        logger.info("File monitor stopped")
        
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Periodic tasks
                self._check_watch_paths()
                
                # Wait for next interval
                self._stop_event.wait(60)  # Check paths every minute
                
            except Exception as e:
                logger.error(f"Error in file monitoring loop: {e}")
                
    def _check_watch_paths(self) -> None:
        """Check if watched paths still exist."""
        try:
            for path in self.watch_paths:
                if not os.path.exists(path):
                    self._add_event('WATCH_PATH_MISSING', 'warning', {
                        'path': path
                    })
                    
        except Exception as e:
            logger.error(f"Error checking watch paths: {e}")
            
    def _handle_event(self, event: FileSystemEvent) -> None:
        """Handle file system event.
        
        Args:
            event: File system event
        """
        try:
            # Get event type
            if event.event_type == 'created':
                event_type = 'FILE_CREATED'
            elif event.event_type == 'modified':
                event_type = 'FILE_MODIFIED'
            elif event.event_type == 'deleted':
                event_type = 'FILE_DELETED'
            elif event.event_type == 'moved':
                event_type = 'FILE_MOVED'
            else:
                event_type = 'FILE_UNKNOWN'
                
            # Add event
            self._add_event(event_type, 'info', {
                'path': event.src_path,
                'is_directory': event.is_directory,
                'event_type': event.event_type
            })
            
            # Check for suspicious patterns
            self._check_suspicious_patterns(event)
            
        except Exception as e:
            logger.error(f"Error handling file event: {e}")
            
    def _check_suspicious_patterns(self, event: FileSystemEvent) -> None:
        """Check for suspicious file patterns.
        
        Args:
            event: File system event
        """
        try:
            # Check for suspicious extensions
            suspicious_exts = ['.exe', '.dll', '.sys', '.bat', '.ps1']
            if any(event.src_path.lower().endswith(ext) for ext in suspicious_exts):
                self._add_event('SUSPICIOUS_FILE_CREATED', 'warning', {
                    'path': event.src_path,
                    'event_type': event.event_type
                })
                
            # Check for hidden files
            if os.path.basename(event.src_path).startswith('.'):
                self._add_event('HIDDEN_FILE_ACTIVITY', 'warning', {
                    'path': event.src_path,
                    'event_type': event.event_type
                })
                
            # Check for system directories
            system_dirs = ['windows', 'system32', 'syswow64']
            if any(dir.lower() in event.src_path.lower() for dir in system_dirs):
                self._add_event('SYSTEM_DIRECTORY_ACTIVITY', 'warning', {
                    'path': event.src_path,
                    'event_type': event.event_type
                })
                
        except Exception as e:
            logger.error(f"Error checking suspicious patterns: {e}")
            
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
                f"File monitoring event: {event_type} - {data.get('path', 'unknown')}"
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
