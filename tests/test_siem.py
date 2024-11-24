#!/usr/bin/env python3

import os
import sys
import time
import threading
import socket
import json
import unittest
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem import SIEM
from modules.collectors.windows import WindowsEventCollector
from modules.collectors.syslog import SyslogCollector
from modules.collectors.custom import CustomLogCollector
from modules.monitor import SystemMonitor
from modules.offensive import OffensiveTools
from modules.defensive import DefensiveTools

class TestSIEM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        # Configure logging
        logger.remove()
        logger.add(sys.stderr, level="INFO")
        
        # Create test files directory
        cls.test_dir = os.path.join(os.path.dirname(__file__), 'test_files')
        os.makedirs(cls.test_dir, exist_ok=True)
        
        # Create test log file
        cls.test_log = os.path.join(cls.test_dir, 'test.log')
        with open(cls.test_log, 'w') as f:
            f.write("192.168.1.1 - - [15/Mar/2024:11:22:33 +0000] \"GET /test HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"\n")
        
    def setUp(self):
        """Initialize SIEM for each test"""
        self.siem = SIEM()
        
    def test_1_initialization(self):
        """Test SIEM initialization"""
        self.assertIsNotNone(self.siem.config)
        self.assertTrue(hasattr(self.siem, 'windows_collector'))
        self.assertTrue(hasattr(self.siem, 'syslog_collector'))
        self.assertTrue(hasattr(self.siem, 'custom_collector'))
        self.assertTrue(hasattr(self.siem, 'system_monitor'))
        logger.info("✓ SIEM initialization test passed")
        
    def test_2_windows_collector(self):
        """Test Windows Event Collector"""
        if self.siem.windows_collector:
            self.siem.windows_collector.start()
            time.sleep(2)  # Give collector time to start
            
            # Check if collector is running
            self.assertTrue(self.siem.windows_collector.running)
            
            # Stop collector
            self.siem.windows_collector.stop()
            logger.info("✓ Windows Event Collector test passed")
        else:
            logger.warning("Windows Event Collector not available")
            
    def test_3_syslog_collector(self):
        """Test Syslog Collector"""
        if self.siem.syslog_collector:
            # Start collector
            collector_thread = threading.Thread(target=self.siem.syslog_collector.start)
            collector_thread.daemon = True
            collector_thread.start()
            time.sleep(2)  # Give collector time to start
            
            # Send test message
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            message = '<13>Mar 15 11:22:33 localhost test: Test syslog message'
            sock.sendto(message.encode(), ('127.0.0.1', 5140))
            sock.close()
            
            time.sleep(1)  # Give collector time to process
            
            # Check if message was received
            self.assertFalse(self.siem.syslog_collector.event_queue.empty())
            
            # Stop collector
            self.siem.syslog_collector.stop()
            logger.info("✓ Syslog Collector test passed")
        else:
            logger.warning("Syslog Collector not available")
            
    def test_4_custom_collector(self):
        """Test Custom Log Collector"""
        if self.siem.custom_collector:
            # Configure test file
            self.siem.custom_collector.paths = [self.test_log]
            
            # Start collector
            collector_thread = threading.Thread(target=self.siem.custom_collector.start)
            collector_thread.daemon = True
            collector_thread.start()
            time.sleep(2)  # Give collector time to start
            
            # Append test log entry
            with open(self.test_log, 'a') as f:
                f.write("192.168.1.2 - - [15/Mar/2024:11:22:34 +0000] \"GET /test HTTP/1.1\" 200 5678 \"-\" \"Mozilla/5.0\"\n")
            
            time.sleep(1)  # Give collector time to process
            
            # Check if file is being monitored
            self.assertIn(self.test_log, self.siem.custom_collector.file_positions)
            
            # Stop collector
            self.siem.custom_collector.stop()
            logger.info("✓ Custom Log Collector test passed")
        else:
            logger.warning("Custom Log Collector not available")
            
    def test_5_system_monitor(self):
        """Test System Monitor"""
        if self.siem.system_monitor:
            self.siem.system_monitor.start()
            time.sleep(2)  # Give monitor time to collect metrics
            
            # Check if metrics are being collected
            metrics = self.siem.system_monitor.get_metrics()
            self.assertIsNotNone(metrics)
            self.assertIn('cpu_percent', metrics)
            self.assertIn('memory_percent', metrics)
            
            # Stop monitor
            self.siem.system_monitor.stop()
            logger.info("✓ System Monitor test passed")
        else:
            logger.warning("System Monitor not available")
            
    def test_6_defensive_tools(self):
        """Test Defensive Tools"""
        if self.siem.defensive:
            self.siem.defensive.start()
            time.sleep(2)  # Give tools time to initialize
            
            # Check if defensive tools are running
            self.assertTrue(self.siem.defensive.running)
            
            # Stop defensive tools
            self.siem.defensive.stop()
            logger.info("✓ Defensive Tools test passed")
        else:
            logger.warning("Defensive Tools not available")
            
    def test_7_offensive_tools(self):
        """Test Offensive Tools"""
        if self.siem.offensive:
            self.siem.offensive.start()
            time.sleep(2)  # Give tools time to initialize
            
            # Check if offensive tools are running
            self.assertTrue(self.siem.offensive.running)
            
            # Stop offensive tools
            self.siem.offensive.stop()
            logger.info("✓ Offensive Tools test passed")
        else:
            logger.warning("Offensive Tools not available")
            
    def test_8_web_interface(self):
        """Test Web Interface"""
        # Start Flask app in a thread
        def run_app():
            self.siem.app.config['TESTING'] = True
            self.siem.app.config['SERVER_NAME'] = 'localhost:5000'
            self.client = self.siem.app.test_client()
            
        thread = threading.Thread(target=run_app)
        thread.daemon = True
        thread.start()
        time.sleep(2)  # Give app time to start
        
        with self.siem.app.app_context():
            # Test home page
            response = self.client.get('/')
            self.assertEqual(response.status_code, 200)
            
            # Test status endpoint
            response = self.client.get('/status')
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertIn('status', data)
            self.assertIn('components', data)
            
        logger.info("✓ Web Interface test passed")
        
    def test_9_full_system(self):
        """Test full SIEM system"""
        # Start SIEM
        self.siem.start()
        time.sleep(5)  # Give system time to initialize
        
        # Check component status
        self.assertTrue(any(self.siem.components_status.values()))
        
        # Stop SIEM
        self.siem.stop()
        logger.info("✓ Full System test passed")
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        # Remove test files
        if os.path.exists(cls.test_log):
            os.remove(cls.test_log)
        if os.path.exists(cls.test_dir):
            os.rmdir(cls.test_dir)

if __name__ == '__main__':
    unittest.main(verbosity=2)
