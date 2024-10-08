import os
import re
import json
import time
import sqlite3
import logging
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import queue
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EnterpriseSTEM')

class LogSource(ABC):
    @abstractmethod
    def collect_logs(self):
        pass

    @abstractmethod
    def parse_log(self, log_data):
        pass

class FileLogSource(LogSource):
    def __init__(self, directory, file_pattern):
        self.directory = directory
        self.file_pattern = file_pattern
        self.processed_files = set()

    def collect_logs(self):
        logs = []
        for filename in os.listdir(self.directory):
            if re.match(self.file_pattern, filename):
                filepath = os.path.join(self.directory, filename)
                if filepath not in self.processed_files:
                    with open(filepath, 'r') as file:
                        for line in file:
                            logs.append(line.strip())
                    self.processed_files.add(filepath)
        return logs

    def parse_log(self, log_data):
        # Implement based on specific log format
        pass

class WindowsEventLogSource(LogSource):
    def __init__(self, event_types=['System', 'Security', 'Application']):
        self.event_types = event_types
        # In a real implementation, you'd use the Windows API
        # This is a placeholder for demonstration
        
    def collect_logs(self):
        # Placeholder - in reality, you'd use win32evtlog or similar
        return []

    def parse_log(self, log_data):
        # Parse Windows Event Log XML format
        try:
            root = ET.fromstring(log_data)
            return {
                'EventID': root.find('./System/EventID').text,
                'TimeCreated': root.find('./System/TimeCreated').get('SystemTime'),
                'Level': root.find('./System/Level').text,
                'Task': root.find('./System/Task').text,
                'Description': root.find('./EventData').text
            }
        except Exception as e:
            logger.error(f"Error parsing Windows Event Log: {e}")
            return None

class SyslogSource(LogSource):
    def __init__(self, host='0.0.0.0', port=514):
        self.host = host
        self.port = port
        # In a real implementation, you'd set up a syslog server

    def collect_logs(self):
        # Placeholder - in reality, you'd implement a syslog server
        return []

    def parse_log(self, log_data):
        # Parse syslog format
        syslog_pattern = r'<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)'
        match = re.match(syslog_pattern, log_data)
        if match:
            priority, timestamp, hostname, message = match.groups()
            facility = int(priority) // 8
            severity = int(priority) % 8
            return {
                'facility': facility,
                'severity': severity,
                'timestamp': timestamp,
                'hostname': hostname,
                'message': message
            }
        return None

class Event:
    def __init__(self, source, event_type, timestamp, data, severity):
        self.source = source
        self.event_type = event_type
        self.timestamp = timestamp
        self.data = data
        self.severity = severity
        self.correlated_events = []

    def to_dict(self):
        return {
            'source': self.source,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'severity': self.severity
        }

class Rule(ABC):
    def __init__(self, name, severity='MEDIUM'):
        self.name = name
        self.severity = severity

    @abstractmethod
    def matches(self, event):
        pass

class SimpleRule(Rule):
    def __init__(self, name, pattern, severity='MEDIUM'):
        super().__init__(name, severity)
        self.pattern = pattern

    def matches(self, event):
        return self.pattern.lower() in str(event.data).lower()

class ComplexRule(Rule):
    def __init__(self, name, conditions, timeframe=60, threshold=5, severity='HIGH'):
        super().__init__(name, severity)
        self.conditions = conditions
        self.timeframe = timeframe
        self.threshold = threshold
        self.event_history = []

    def matches(self, event ):
        # Add the current event to history
        self.event_history.append(event)
        
        # Remove events outside the timeframe
        cutoff_time = datetime.now() - timedelta(seconds=self.timeframe)
        self.event_history = [e for e in self.event_history 
                             if e.timestamp > cutoff_time]

        # Check if all conditions are met and threshold is reached
        matching_events = [e for e in self.event_history 
                          if all(self._check_condition(e, c) 
                                for c in self.conditions)]
        
        return len(matching_events) >= self.threshold

    def _check_condition(self, event, condition):
        field, operator, value = condition
        event_value = getattr(event, field, None)
        if event_value is None and isinstance(event.data, dict):
            event_value = event.data.get(field)

        if operator == 'equals':
            return event_value == value
        elif operator == 'contains':
            return value in str(event_value)
        elif operator == 'regex':
            return re.search(value, str(event_value)) is not None
        return False

class Alert:
    def __init__(self, rule, event, timestamp=None):
        self.rule = rule
        self.event = event
        self.timestamp = timestamp or datetime.now()

    def to_dict(self):
        return {
            'rule_name': self.rule.name,
            'severity': self.rule.severity,
            'timestamp': self.timestamp.isoformat(),
            'event': self.event.to_dict()
        }

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self._create_tables()

    def _create_tables(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS events
                (id INTEGER PRIMARY KEY,
                 source TEXT,
                 event_type TEXT,
                 timestamp TEXT,
                 data TEXT,
                 severity TEXT)
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts
                (id INTEGER PRIMARY KEY,
                 rule_name TEXT,
                 severity TEXT,
                 timestamp TEXT,
                 event_id INTEGER,
                 FOREIGN KEY (event_id) REFERENCES events(id))
            ''')
            conn.commit()

    def store_event(self, event):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events (source, event_type, timestamp, data, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (event.source, event.event_type, event.timestamp.isoformat(),
                  json.dumps(event.data), event.severity))
            return cursor.lastrowid

    def store_alert(self, alert, event_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO alerts (rule_name, severity, timestamp, event_id)
                VALUES (?, ?, ?, ?)
            ''', (alert.rule.name, alert.rule.severity,
                  alert.timestamp.isoformat(), event_id))

    def get_recent_events(self, limit=100):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT * FROM events
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()

class EnterpriseSTEM:
    def __init__(self, db_path='siem.db'):
        self.log_sources = []
        self.rules = []
        self.event_queue = queue.Queue()
        self.db = Database(db_path)
        self.running = False

    def add_log_source(self, log_source):
        self.log_sources.append(log_source)

    def add_rule(self, rule):
        self.rules.append(rule)

    def start(self):
        self.running = True
        collection_thread = threading.Thread(target=self._collect_logs)
        analysis_thread = threading.Thread(target=self._analyze_events)
        
        collection_thread.start()
        analysis_thread.start()

    def stop(self):
        self.running = False

    def _collect_logs(self):
        while self.running:
            for source in self.log_sources:
                try:
                    logs = source.collect_logs()
                    for log in logs:
                        parsed_log = source.parse_log(log)
                        if parsed_log:
                            event = Event(
                                source=source.__class__.__name__,
                                event_type=parsed_log.get('event_type', 'unknown'),
                                timestamp=datetime.now(),
                                data=parsed_log,
                                severity=parsed_log.get('severity', 'MEDIUM')
                            )
                            self.event_queue.put(event)
                except Exception as e:
                    logger.error(f"Error collecting logs from {source.__class__.__name__}: {e}")
            time.sleep(1)

    def _analyze_events(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                self._process_event(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error analyzing event: {e}")

    def _process_event(self, event):
        event_id = self.db.store_event(event)
        
        for rule in self.rules:
            try:
                if rule.matches(event):
                    alert = Alert(rule, event)
                    self.db.store_alert(alert, event_id)
                    self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Error processing rule {rule.name}: {e}")

    def _handle_alert(self, alert):
        logger.warning(f"Alert generated: {alert.rule.name} - {alert.event.data}")
        # Here you could add additional alert handlers:
        # - Send email
        # - Send to SIEM dashboard
        # - Trigger automated response

# Example usage
def main():
    siem = EnterpriseSTEM()

    # Add log sources
    siem.add_log_source(FileLogSource('/var/log', r'.*\.log$'))
    siem.add_log_source(WindowsEventLogSource())
    siem.add_log_source(SyslogSource())

    # Add rules
    siem.add_rule(SimpleRule('Failed Login', 'failed login attempt'))
    siem.add_rule(SimpleRule('Firewall Block', 'blocked incoming connection'))
    
    # Complex rule example: Multiple failed logins from same IP
    failed_login_conditions = [
        ('event_type', 'equals', 'login_failure'),
        ('data', 'contains', 'Failed login')
    ]
    siem.add_rule(ComplexRule('Brute Force Attempt', failed_login_conditions,timeframe=300, threshold=5))

    try:
        siem.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        siem.stop()
        logger.info("SIEM shutdown complete.")

if __name__ == "__main__":
    main()