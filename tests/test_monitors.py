#!/usr/bin/env python3

import os
import sys
import time
import unittest
import threading
import psutil
import win32evtlog
import win32con
from unittest.mock import MagicMock, patch
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.monitors.process_monitor import ProcessMonitor
from modules.monitors.network_monitor import NetworkMonitor
from modules.monitors.file_monitor import FileMonitor
from modules.monitors.registry_monitor import RegistryMonitor

class TestProcessMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        logger.remove()
        logger.add(sys.stderr, level="INFO")
        
    def setUp(self):
        """Initialize monitor for each test"""
        self.monitor = ProcessMonitor()
        
    def test_1_initialization(self):
        """Test process monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertFalse(self.monitor.running)
        self.assertIsNotNone(self.monitor.process_list)
        logger.info("✓ Process monitor initialization test passed")
        
    def test_2_process_tracking(self):
        """Test process tracking"""
        # Start monitor
        self.monitor.start()
        time.sleep(2)
        
        # Check if monitor is tracking processes
        processes = self.monitor.get_processes()
        self.assertIsNotNone(processes)
        self.assertGreater(len(processes), 0)
        
        # Verify process information
        for proc in processes:
            self.assertIn('pid', proc)
            self.assertIn('name', proc)
            self.assertIn('cpu_percent', proc)
            self.assertIn('memory_percent', proc)
            
        # Stop monitor
        self.monitor.stop()
        logger.info("✓ Process tracking test passed")
        
    def test_3_suspicious_process_detection(self):
        """Test suspicious process detection"""
        # Mock a suspicious process
        suspicious_proc = {
            'name': 'suspicious.exe',
            'cpu_percent': 90.0,
            'memory_percent': 80.0,
            'connections': [{'remote_ip': '1.2.3.4'}]
        }
        
        # Test detection
        is_suspicious = self.monitor.is_suspicious_process(suspicious_proc)
        self.assertTrue(is_suspicious)
        logger.info("✓ Suspicious process detection test passed")

class TestNetworkMonitor(unittest.TestCase):
    def setUp(self):
        """Initialize monitor for each test"""
        self.monitor = NetworkMonitor()
        
    def test_1_initialization(self):
        """Test network monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertFalse(self.monitor.running)
        logger.info("✓ Network monitor initialization test passed")
        
    def test_2_connection_tracking(self):
        """Test connection tracking"""
        # Start monitor
        self.monitor.start()
        time.sleep(2)
        
        # Check connections
        connections = self.monitor.get_connections()
        self.assertIsNotNone(connections)
        
        for conn in connections:
            self.assertIn('local_address', conn)
            self.assertIn('remote_address', conn)
            self.assertIn('status', conn)
            
        # Stop monitor
        self.monitor.stop()
        logger.info("✓ Connection tracking test passed")
        
    def test_3_traffic_analysis(self):
        """Test network traffic analysis"""
        # Start monitor
        self.monitor.start()
        time.sleep(2)
        
        # Get traffic stats
        stats = self.monitor.get_traffic_stats()
        self.assertIn('bytes_sent', stats)
        self.assertIn('bytes_recv', stats)
        self.assertIn('packets_sent', stats)
        self.assertIn('packets_recv', stats)
        
        # Stop monitor
        self.monitor.stop()
        logger.info("✓ Traffic analysis test passed")

class TestFileMonitor(unittest.TestCase):
    def setUp(self):
        """Initialize monitor for each test"""
        self.test_dir = os.path.join(os.path.dirname(__file__), 'test_files')
        os.makedirs(self.test_dir, exist_ok=True)
        self.monitor = FileMonitor()
        
    def tearDown(self):
        """Clean up after each test"""
        if os.path.exists(self.test_dir):
            for file in os.listdir(self.test_dir):
                os.remove(os.path.join(self.test_dir, file))
            os.rmdir(self.test_dir)
            
    def test_1_initialization(self):
        """Test file monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertFalse(self.monitor.running)
        logger.info("✓ File monitor initialization test passed")
        
    def test_2_file_tracking(self):
        """Test file change tracking"""
        # Start monitor
        self.monitor.start()
        time.sleep(1)
        
        # Create test file
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('Test content')
            
        time.sleep(1)
        
        # Modify file
        with open(test_file, 'a') as f:
            f.write('\nMore content')
            
        time.sleep(1)
        
        # Check events
        events = self.monitor.get_events()
        self.assertGreater(len(events), 0)
        
        # Stop monitor
        self.monitor.stop()
        logger.info("✓ File tracking test passed")
        
    def test_3_suspicious_changes(self):
        """Test suspicious file change detection"""
        # Start monitor
        self.monitor.start()
        time.sleep(1)
        
        # Create suspicious file
        susp_file = os.path.join(self.test_dir, 'suspicious.exe')
        with open(susp_file, 'w') as f:
            f.write('Suspicious content')
            
        time.sleep(1)
        
        # Check alerts
        alerts = self.monitor.get_alerts()
        self.assertGreater(len(alerts), 0)
        
        # Stop monitor
        self.monitor.stop()
        logger.info("✓ Suspicious change detection test passed")

class TestRegistryMonitor(unittest.TestCase):
    def setUp(self):
        """Initialize monitor for each test"""
        self.monitor = RegistryMonitor()
        
    def test_1_initialization(self):
        """Test registry monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertFalse(self.monitor.running)
        logger.info("✓ Registry monitor initialization test passed")
        
    @patch('win32evtlog.OpenEventLog')
    def test_2_registry_tracking(self, mock_open_log):
        """Test registry change tracking"""
        # Mock event log
        mock_log = MagicMock()
        mock_open_log.return_value = mock_log
        
        # Start monitor
        self.monitor.start()
        time.sleep(1)
        
        # Simulate registry event
        event = {
            'EventID': 4657,
            'TimeGenerated': datetime.now(),
            'SourceName': 'Microsoft-Windows-Security-Auditing',
            'StringInserts': [
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Test',
                'WriteKey',
                'TestValue'
            ]
        }
        mock_log.ReadEventLog.return_value = [event]
        
        # Check events
        events = self.monitor.get_events()
        self.assertGreater(len(events), 0)
        
        # Stop monitor
        self.monitor.stop()
        logger.info("✓ Registry tracking test passed")
        
    def test_3_suspicious_changes(self):
        """Test suspicious registry change detection"""
        # Create suspicious change event
        event = {
            'key': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'value': 'suspicious.exe',
            'type': 'SetValue'
        }
        
        # Test detection
        is_suspicious = self.monitor.is_suspicious_change(event)
        self.assertTrue(is_suspicious)
        logger.info("✓ Suspicious change detection test passed")

if __name__ == '__main__':
    unittest.main(verbosity=2)
