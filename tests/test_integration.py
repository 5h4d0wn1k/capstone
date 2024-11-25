#!/usr/bin/env python3

import os
import sys
import time
import json
import unittest
import threading
import socket
import requests
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem import SIEM
from web.app import app, socketio
from modules.monitors.process_monitor import ProcessMonitor
from modules.monitors.network_monitor import NetworkMonitor
from modules.monitors.file_monitor import FileMonitor
from modules.monitors.registry_monitor import RegistryMonitor

class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        logger.remove()
        logger.add(sys.stderr, level="INFO")
        
        # Create test files directory
        cls.test_dir = os.path.join(os.path.dirname(__file__), 'test_files')
        os.makedirs(cls.test_dir, exist_ok=True)
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        if os.path.exists(cls.test_dir):
            for file in os.listdir(cls.test_dir):
                os.remove(os.path.join(cls.test_dir, file))
            os.rmdir(cls.test_dir)
            
    def setUp(self):
        """Initialize SIEM for each test"""
        self.siem = SIEM()
        self.web_thread = None
        self.port = self.find_free_port()
        
    def tearDown(self):
        """Clean up after each test"""
        if self.siem:
            self.siem.shutdown()
        if self.web_thread and self.web_thread.is_alive():
            self.web_thread.join(timeout=5)
            
    def find_free_port(self):
        """Find a free port for testing"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
            
    def test_1_full_system_startup(self):
        """Test complete system startup"""
        # Start SIEM in a thread
        def run_siem():
            self.siem.run(port=self.port)
            
        self.web_thread = threading.Thread(target=run_siem)
        self.web_thread.daemon = True
        self.web_thread.start()
        time.sleep(5)  # Give system time to start
        
        # Check if web interface is running
        try:
            response = requests.get(f'http://localhost:{self.port}/')
            self.assertEqual(response.status_code, 200)
        except Exception as e:
            self.fail(f"Web interface not accessible: {e}")
            
        # Check if monitors are running
        self.assertTrue(self.siem.process_monitor.running)
        self.assertTrue(self.siem.network_monitor.running)
        self.assertTrue(self.siem.file_monitor.running)
        self.assertTrue(self.siem.registry_monitor.running)
        logger.info("✓ Full system startup test passed")
        
    def test_2_event_flow(self):
        """Test event flow through system"""
        # Start SIEM
        def run_siem():
            self.siem.run(port=self.port)
            
        self.web_thread = threading.Thread(target=run_siem)
        self.web_thread.daemon = True
        self.web_thread.start()
        time.sleep(5)
        
        # Create test event
        test_event = {
            'timestamp': datetime.now().isoformat(),
            'severity': 'High',
            'source': 'Integration Test',
            'message': 'Test event flow'
        }
        
        # Add event through SIEM
        self.siem.add_event(test_event)
        time.sleep(1)
        
        # Verify event in web interface
        response = requests.get(f'http://localhost:{self.port}/api/events')
        self.assertEqual(response.status_code, 200)
        events = response.json()
        self.assertTrue(any(e['message'] == 'Test event flow' for e in events))
        logger.info("✓ Event flow test passed")
        
    def test_3_monitor_integration(self):
        """Test monitor integration"""
        # Start SIEM
        def run_siem():
            self.siem.run(port=self.port)
            
        self.web_thread = threading.Thread(target=run_siem)
        self.web_thread.daemon = True
        self.web_thread.start()
        time.sleep(5)
        
        # Create test file to trigger file monitor
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('Test content')
            
        time.sleep(2)
        
        # Check if event was captured
        response = requests.get(f'http://localhost:{self.port}/api/events')
        events = response.json()
        self.assertTrue(any('test.txt' in str(e) for e in events))
        logger.info("✓ Monitor integration test passed")
        
    def test_4_real_time_updates(self):
        """Test real-time updates through WebSocket"""
        # Start SIEM
        def run_siem():
            self.siem.run(port=self.port)
            
        self.web_thread = threading.Thread(target=run_siem)
        self.web_thread.daemon = True
        self.web_thread.start()
        time.sleep(5)
        
        # Connect to WebSocket
        ws_client = socketio.test_client(app)
        self.assertTrue(ws_client.is_connected())
        
        # Create test event
        test_event = {
            'timestamp': datetime.now().isoformat(),
            'severity': 'Critical',
            'source': 'WebSocket Test',
            'message': 'Test real-time updates'
        }
        
        # Add event and check if received through WebSocket
        received_events = []
        @ws_client.on('new_event')
        def handle_event(event):
            received_events.append(event)
            
        self.siem.add_event(test_event)
        time.sleep(2)
        
        self.assertTrue(any(e['message'] == 'Test real-time updates' for e in received_events))
        logger.info("✓ Real-time updates test passed")
        
    def test_5_system_metrics(self):
        """Test system metrics collection and reporting"""
        # Start SIEM
        def run_siem():
            self.siem.run(port=self.port)
            
        self.web_thread = threading.Thread(target=run_siem)
        self.web_thread.daemon = True
        self.web_thread.start()
        time.sleep(5)
        
        # Connect to WebSocket
        ws_client = socketio.test_client(app)
        self.assertTrue(ws_client.is_connected())
        
        # Check system stats
        received_stats = []
        @ws_client.on('system_stats')
        def handle_stats(stats):
            received_stats.append(stats)
            
        time.sleep(3)  # Wait for stats update
        
        self.assertTrue(len(received_stats) > 0)
        stats = received_stats[-1]
        self.assertIn('cpu_percent', stats)
        self.assertIn('memory_percent', stats)
        self.assertIn('network_speed', stats)
        logger.info("✓ System metrics test passed")
        
    def test_6_error_handling(self):
        """Test system-wide error handling"""
        # Start SIEM
        def run_siem():
            self.siem.run(port=self.port)
            
        self.web_thread = threading.Thread(target=run_siem)
        self.web_thread.daemon = True
        self.web_thread.start()
        time.sleep(5)
        
        # Test invalid event
        invalid_event = "Not a dictionary"
        self.siem.add_event(invalid_event)
        
        # Test invalid API request
        response = requests.get(f'http://localhost:{self.port}/invalid')
        self.assertEqual(response.status_code, 404)
        
        # Test invalid WebSocket message
        ws_client = socketio.test_client(app)
        ws_client.emit('invalid_event', 'invalid data')
        time.sleep(1)
        
        # System should still be running
        self.assertTrue(self.siem.running)
        logger.info("✓ Error handling test passed")

if __name__ == '__main__':
    unittest.main(verbosity=2)
