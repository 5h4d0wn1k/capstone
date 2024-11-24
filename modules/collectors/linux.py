import os
from typing import Dict, List, Optional
from .base import BaseEventCollector
from loguru import logger
import subprocess
import json
import time

class LinuxEventCollector(BaseEventCollector):
    """Linux event collector for system logs and audit events"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.log_sources = config.get('log_sources', [
            '/var/log/syslog',
            '/var/log/auth.log',
            '/var/log/audit/audit.log'
        ])
        self.last_positions = {}
        self.initialize_collector()

    def initialize_collector(self):
        """Initialize the collector"""
        try:
            # Initialize last read positions for each log file
            for log_file in self.log_sources:
                if os.path.exists(log_file):
                    self.last_positions[log_file] = os.path.getsize(log_file)
            logger.info("Linux Event Collector initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Linux Event Collector: {e}")
            raise

    def _collect_events(self) -> Optional[List]:
        """Collect events from Linux logs"""
        events = []
        
        # Collect from log files
        for log_file in self.log_sources:
            try:
                if os.path.exists(log_file):
                    events.extend(self._read_log_file(log_file))
            except Exception as e:
                logger.error(f"Error reading {log_file}: {e}")
                continue

        # Collect from journalctl if available
        try:
            journal_events = self._collect_journal_events()
            if journal_events:
                events.extend(journal_events)
        except Exception as e:
            logger.error(f"Error collecting journal events: {e}")

        # Collect audit events if available
        try:
            audit_events = self._collect_audit_events()
            if audit_events:
                events.extend(audit_events)
        except Exception as e:
            logger.error(f"Error collecting audit events: {e}")

        return events if events else None

    def _read_log_file(self, log_file: str) -> List:
        """Read new entries from a log file"""
        events = []
        current_size = os.path.getsize(log_file)
        last_position = self.last_positions.get(log_file, 0)

        if current_size < last_position:
            # Log file has been rotated
            last_position = 0

        if current_size > last_position:
            with open(log_file, 'r') as f:
                f.seek(last_position)
                for line in f:
                    events.append({
                        'source': log_file,
                        'message': line.strip(),
                        'timestamp': time.time()
                    })
            self.last_positions[log_file] = current_size

        return events

    def _collect_journal_events(self) -> List:
        """Collect events from systemd journal"""
        events = []
        try:
            cmd = ['journalctl', '-n', '100', '--no-pager', '--output=json']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    try:
                        event = json.loads(line)
                        events.append({
                            'source': 'systemd-journal',
                            'message': event.get('MESSAGE', ''),
                            'timestamp': event.get('__REALTIME_TIMESTAMP', ''),
                            'unit': event.get('_SYSTEMD_UNIT', ''),
                            'priority': event.get('PRIORITY', '')
                        })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error collecting journal events: {e}")
        return events

    def _collect_audit_events(self) -> List:
        """Collect events from audit system"""
        events = []
        try:
            cmd = ['ausearch', '-ts', 'recent', '--format', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                try:
                    audit_data = json.loads(result.stdout)
                    for record in audit_data.get('records', []):
                        events.append({
                            'source': 'audit',
                            'message': record.get('message', ''),
                            'timestamp': record.get('time', ''),
                            'type': record.get('type', ''),
                            'serial': record.get('serial', '')
                        })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.error(f"Error collecting audit events: {e}")
        return events

    def _normalize_event(self, event: Dict) -> Dict:
        """Normalize Linux event to common format"""
        return {
            'timestamp': event.get('timestamp', time.time()),
            'source': event.get('source', 'linux'),
            'event_type': event.get('type', 'system'),
            'severity': event.get('priority', 'info'),
            'message': event.get('message', ''),
            'raw_data': event
        }
