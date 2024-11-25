#!/usr/bin/env python3

import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from loguru import logger

class FileEventHandler(FileSystemEventHandler):
    """Handle file system events."""
    
    def __init__(self, monitor):
        """Initialize event handler."""
        self.monitor = monitor
        
    def on_created(self, event):
        """Handle file creation event."""
        self.monitor.handle_event(event)
            
    def on_modified(self, event):
        """Handle file modification event."""
        self.monitor.handle_event(event)
            
    def on_deleted(self, event):
        """Handle file deletion event."""
        self.monitor.handle_event(event)
            
    def on_moved(self, event):
        """Handle file move event."""
        self.monitor.handle_event(event)

class FileMonitor:
    """Monitor file system changes."""
    
    def __init__(self):
        """Initialize file monitor."""
        self.running = False
        self.observer = None
        self.watch_paths = [
            os.environ.get('SYSTEMWINDOW', 'C:\\Windows'),
            os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
            os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')
        ]
        self.events = []
        self.config = {
            'suspicious_extensions': ['.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs'],
            'watch_paths': ['\\windows\\system32', '\\windows\\syswow64', '\\windows\\tasks'],
            'max_events': 10000
        }
        
    def start(self):
        """Start file monitoring."""
        if not self.running:
            self.running = True
            self.observer = Observer()
            event_handler = FileEventHandler(self)
            
            for path in self.watch_paths:
                try:
                    if os.path.exists(path):
                        self.observer.schedule(event_handler, path, recursive=True)
                except Exception as e:
                    logger.error(f"Error watching path {path}: {e}")
                    
            self.observer.start()
            logger.info("File monitor started")
            
    def stop(self):
        """Stop file monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.running = False
        logger.info("File monitor stopped")
        
    def handle_event(self, event):
        """Handle a file system event.
        
        Args:
            event: watchdog.events.FileSystemEvent
        """
        try:
            if event.is_directory:
                return
            
            event_type = event.event_type
            file_path = event.src_path
            
            # Check if file extension is suspicious
            _, ext = os.path.splitext(file_path)
            is_suspicious = (
                ext.lower() in self.config['suspicious_extensions'] or
                any(path.lower() in file_path.lower() for path in self.config['watch_paths'])
            )
            
            if is_suspicious:
                logger.warning(f"Suspicious file activity: {event_type} {file_path}")
                self.events.append({
                    'type': 'suspicious_file',
                    'event': event_type,
                    'path': file_path,
                    'timestamp': datetime.now().isoformat()
                })
            else:
                logger.info(f"File activity: {event_type} {file_path}")
                self.events.append({
                    'type': 'file',
                    'event': event_type,
                    'path': file_path,
                    'timestamp': datetime.now().isoformat()
                })
                
            # Trim events if needed
            if len(self.events) > self.config['max_events']:
                self.events = self.events[-self.config['max_events']:]
                
        except Exception as e:
            logger.error(f"Error handling file event: {e}")

    def get_events(self):
        """Get list of file events."""
        return self.events
        
    def get_alerts(self):
        """Get list of file alerts."""
        return [event for event in self.events if event['type'] == 'suspicious_file']
