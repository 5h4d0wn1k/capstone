"""Custom log collector implementation."""

import os
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from loguru import logger
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

class LogFileHandler(FileSystemEventHandler):
    """File system event handler for log files."""
    
    def __init__(self, callback):
        """Initialize handler.
        
        Args:
            callback: Function to call when file is modified
        """
        self.callback = callback
        
    def on_modified(self, event):
        """Handle file modification event.
        
        Args:
            event: File system event
        """
        if isinstance(event, FileModifiedEvent):
            self.callback(event.src_path)

class CustomLogCollector:
    """Custom log file collector."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize collector.
        
        Args:
            config: Collector configuration
        """
        self.config = config.get('custom_collector', {})
        self.enabled = self.config.get('enabled', True)
        self.log_paths = self.config.get('log_paths', [])
        self.events = []
        self._stop_event = threading.Event()
        self._thread = None
        self._observer = None
        self._file_positions = {}
        
    def start(self) -> None:
        """Start collecting log events."""
        if not self.enabled:
            logger.warning("Custom log collector is disabled")
            return
            
        try:
            # Initialize file positions
            for path in self.log_paths:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        f.seek(0, os.SEEK_END)
                        self._file_positions[path] = f.tell()
                        
            # Start file system observer
            self._observer = Observer()
            handler = LogFileHandler(self._handle_file_change)
            
            for path in self.log_paths:
                if os.path.exists(path):
                    directory = os.path.dirname(path)
                    self._observer.schedule(handler, directory, recursive=False)
                    
            self._observer.start()
            
            # Start collection thread
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._collect_loop)
            self._thread.daemon = True
            self._thread.start()
            logger.info("Custom log collector started")
            
        except Exception as e:
            logger.error(f"Failed to start custom log collector: {e}")
            
    def stop(self) -> None:
        """Stop collecting log events."""
        self._stop_event.set()
        if self._observer:
            self._observer.stop()
            self._observer.join()
        if self._thread:
            self._thread.join()
        logger.info("Custom log collector stopped")
        
    def _collect_loop(self) -> None:
        """Main collection loop."""
        while not self._stop_event.is_set():
            try:
                # Check each log file
                for path in self.log_paths:
                    if os.path.exists(path):
                        self._read_log_file(path)
                        
                time.sleep(1)  # Avoid high CPU usage
                
            except Exception as e:
                logger.error(f"Error in custom log collection loop: {e}")
                
    def _handle_file_change(self, path: str) -> None:
        """Handle file change event.
        
        Args:
            path: Path to changed file
        """
        try:
            if path in self.log_paths:
                self._read_log_file(path)
                
        except Exception as e:
            logger.error(f"Error handling file change: {e}")
            
    def _read_log_file(self, path: str) -> None:
        """Read log file from last position.
        
        Args:
            path: Path to log file
        """
        try:
            with open(path, 'r') as f:
                # Get file size
                f.seek(0, os.SEEK_END)
                size = f.tell()
                
                # Check if file was truncated
                if size < self._file_positions.get(path, 0):
                    self._file_positions[path] = 0
                    
                # Read new content
                f.seek(self._file_positions.get(path, 0))
                new_content = f.read()
                
                # Update position
                self._file_positions[path] = f.tell()
                
                # Process new content
                if new_content:
                    self._process_content(path, new_content)
                    
        except Exception as e:
            logger.error(f"Error reading log file {path}: {e}")
            
    def _process_content(self, path: str, content: str) -> None:
        """Process log file content.
        
        Args:
            path: Source file path
            content: File content
        """
        try:
            # Process each line
            for line in content.splitlines():
                if line.strip():
                    event = self._parse_line(path, line)
                    if event:
                        self.events.append(event)
                        
        except Exception as e:
            logger.error(f"Error processing log content from {path}: {e}")
            
    def _parse_line(self, path: str, line: str) -> Optional[Dict[str, Any]]:
        """Parse log line.
        
        Args:
            path: Source file path
            line: Log line
            
        Returns:
            Parsed event data or None if parsing fails
        """
        try:
            # Basic event data
            data = {
                'timestamp': datetime.now().isoformat(),
                'source': path,
                'message': line.strip()
            }
            
            # Try to parse severity
            lower_line = line.lower()
            if 'error' in lower_line:
                data['severity'] = 'error'
            elif 'warn' in lower_line:
                data['severity'] = 'warning'
            elif 'info' in lower_line:
                data['severity'] = 'info'
            elif 'debug' in lower_line:
                data['severity'] = 'debug'
            else:
                data['severity'] = 'unknown'
                
            return data
            
        except Exception as e:
            logger.error(f"Error parsing log line: {e}")
            return None
            
    def get_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get collected events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of events
        """
        if limit:
            return self.events[-limit:]
        return self.events.copy()
        
    def clear_events(self) -> None:
        """Clear collected events."""
        self.events.clear()
