#!/usr/bin/env python3

import os
import glob
import threading
import queue
from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, collector):
        self.collector = collector
        
    def on_modified(self, event):
        if not event.is_directory:
            self.collector.process_file(event.src_path)

class CustomLogCollector:
    """Custom log file collector"""
    
    def __init__(self, config: Dict):
        """Initialize Custom Log Collector"""
        self.config = config
        self.name = "custom_log"
        self.paths = config.get('paths', [])
        self.patterns = [re.compile(p) for p in config.get('patterns', [])]
        self.event_queue = queue.Queue()
        self.running = False
        self.file_positions = {}  # Track file read positions
        
        # Initialize watchdog observer
        self.observer = Observer()
        self.handler = LogFileHandler(self)
        
    def start(self):
        """Start collecting custom logs"""
        logger.info("Starting Custom Log Collector")
        self.running = True
        
        # Start initial file processing
        self._process_existing_files()
        
        # Start file watchers
        self._start_watchers()
        
        # Start processing thread
        self.process_thread = threading.Thread(
            target=self._process_events,
            daemon=True,
            name="CustomLogProcessor"
        )
        self.process_thread.start()
        
    def stop(self):
        """Stop collecting custom logs"""
        logger.info("Stopping Custom Log Collector")
        self.running = False
        if hasattr(self, 'observer') and self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        if hasattr(self, 'process_thread') and self.process_thread and self.process_thread.is_alive():
            self.process_thread.join()
            
    def _process_existing_files(self):
        """Process existing log files"""
        for path_pattern in self.paths:
            try:
                for filepath in glob.glob(path_pattern):
                    if os.path.isfile(filepath):
                        self.process_file(filepath)
            except Exception as e:
                logger.error(f"Error processing existing files for pattern {path_pattern}: {e}")
                
    def _start_watchers(self):
        """Start file system watchers"""
        for path_pattern in self.paths:
            try:
                # Get directory path from pattern
                directory = os.path.dirname(path_pattern)
                if os.path.exists(directory):
                    self.observer.schedule(self.handler, directory, recursive=False)
                    logger.info(f"Started watching directory: {directory}")
            except Exception as e:
                logger.error(f"Error setting up watcher for {path_pattern}: {e}")
                
        self.observer.start()
        
    def process_file(self, filepath: str):
        """Process a log file"""
        try:
            # Get current file size
            file_size = os.path.getsize(filepath)
            
            # Get last position
            last_position = self.file_positions.get(filepath, 0)
            
            # Check if file was truncated
            if file_size < last_position:
                last_position = 0
                
            # Read new content
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                
                # Update position
                self.file_positions[filepath] = f.tell()
                
            # Process new lines
            for line in new_lines:
                self._process_line(line.strip(), filepath)
                
        except Exception as e:
            logger.error(f"Error processing file {filepath}: {e}")
            
    def _process_line(self, line: str, source: str):
        """Process a single log line"""
        try:
            # Skip empty lines
            if not line:
                return
                
            # Check if line matches any patterns
            matches = []
            if self.patterns:
                for pattern in self.patterns:
                    if pattern.search(line):
                        matches.append(pattern.pattern)
                        
            # Create event
            event = {
                'timestamp': datetime.now().isoformat(),
                'source': source,
                'message': line,
                'matches': matches,
                'raw_message': line
            }
            
            # Parse common log formats
            parsed = self._parse_common_formats(line)
            if parsed:
                event.update(parsed)
                
            # Add to queue if matches patterns or no patterns specified
            if not self.patterns or matches:
                self.event_queue.put(event)
                
        except Exception as e:
            logger.error(f"Error processing line from {source}: {e}")
            
    def _parse_common_formats(self, line: str) -> Optional[Dict]:
        """Parse common log formats"""
        try:
            # Apache/Nginx access log format
            apache_pattern = re.compile(
                r'(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(.*?)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]+)"\s+"([^"]+)"'
            )
            match = apache_pattern.match(line)
            if match:
                ip, timestamp, request, status, size, referrer, useragent = match.groups()
                return {
                    'format': 'APACHE',
                    'client_ip': ip,
                    'timestamp': timestamp,
                    'request': request,
                    'status_code': int(status),
                    'bytes_sent': int(size),
                    'referrer': referrer,
                    'user_agent': useragent
                }
                
            # Common Log Format (CLF)
            clf_pattern = re.compile(
                r'(\S+)\s+(\S+)\s+(\S+)\s+\[(.*?)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)'
            )
            match = clf_pattern.match(line)
            if match:
                host, ident, authuser, timestamp, request, status, size = match.groups()
                return {
                    'format': 'CLF',
                    'host': host,
                    'ident': ident,
                    'authuser': authuser,
                    'timestamp': timestamp,
                    'request': request,
                    'status_code': int(status),
                    'bytes_sent': int(size)
                }
                
            # Syslog-style format
            syslog_pattern = re.compile(
                r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.*)'
            )
            match = syslog_pattern.match(line)
            if match:
                timestamp, host, program, message = match.groups()
                return {
                    'format': 'SYSLOG',
                    'timestamp': timestamp,
                    'host': host,
                    'program': program,
                    'message': message
                }
                
        except Exception as e:
            logger.error(f"Error parsing log format: {e}")
            
        return None
        
    def _process_events(self):
        """Process events from queue"""
        while self.running:
            try:
                # Get event with timeout to allow checking running flag
                try:
                    event = self.event_queue.get(timeout=1)
                except queue.Empty:
                    continue
                    
                # Process event (add custom processing here)
                logger.debug(f"Processed log event: {event}")
                
                self.event_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error processing events: {e}")
                
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        return {
            'files_monitored': len(self.file_positions),
            'patterns': len(self.patterns),
            'queue_size': self.event_queue.qsize()
        }
