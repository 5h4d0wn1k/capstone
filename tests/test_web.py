#!/usr/bin/env python3

import os
import sys
import time
import json
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import app, socketio, Dashboard, add_event, start_web_interface

class TestWebInterface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        logger.remove()
        logger.add(sys.stderr, level="INFO")
        
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['SERVER_NAME'] = 'localhost:5000'
        cls.client = app.test_client()
        
        # Create test dashboard
        cls.dashboard = Dashboard()
        
    def setUp(self):
        """Set up each test"""
        self.ctx = app.app_context()
        self.ctx.push()
        
    def tearDown(self):
        """Clean up after each test"""
        self.ctx.pop()
        
    def test_1_dashboard_initialization(self):
        """Test dashboard initialization"""
        self.assertIsNotNone(self.dashboard.monitors)
        self.assertEqual(len(self.dashboard.monitors), 4)
        for monitor in ['ProcessMonitor', 'NetworkMonitor', 'FileMonitor', 'RegistryMonitor']:
            self.assertIn(monitor, self.dashboard.monitors)
            self.assertTrue(self.dashboard.monitors[monitor]['active'])
        logger.info("✓ Dashboard initialization test passed")
        
    def test_2_dashboard_start_stop(self):
        """Test dashboard start/stop functionality"""
        # Start dashboard
        self.dashboard.start()
        time.sleep(1)
        
        # Check if threads are running
        self.assertIsNotNone(self.dashboard.stats_thread)
        self.assertIsNotNone(self.dashboard.events_thread)
        self.assertTrue(self.dashboard.stats_thread.is_alive())
        self.assertTrue(self.dashboard.events_thread.is_alive())
        
        # Stop dashboard
        self.dashboard.stop()
        time.sleep(1)
        
        # Check if threads are stopped
        self.assertFalse(self.dashboard.running)
        self.assertFalse(self.dashboard.stats_thread.is_alive())
        self.assertFalse(self.dashboard.events_thread.is_alive())
        logger.info("✓ Dashboard start/stop test passed")
        
    def test_3_event_handling(self):
        """Test event handling"""
        test_event = {
            'timestamp': datetime.now().isoformat(),
            'severity': 'Critical',
            'source': 'Test',
            'message': 'Test event'
        }
        
        # Add event
        success = add_event(test_event)
        self.assertTrue(success)
        
        # Invalid event
        invalid_event = "Not a dictionary"
        success = add_event(invalid_event)
        self.assertFalse(success)
        logger.info("✓ Event handling test passed")
        
    @patch('web.app.socketio.emit')
    def test_4_websocket_events(self, mock_emit):
        """Test WebSocket event handling"""
        with app.test_client() as client:
            # Test connect event
            client.get('/socket.io/')
            mock_emit.assert_called()
            
            # Test system stats event
            self.dashboard.update_system_stats()
            mock_emit.assert_called_with('system_stats', unittest.mock.ANY)
            
            # Test event broadcasting
            test_event = {
                'timestamp': datetime.now().isoformat(),
                'severity': 'High',
                'source': 'Test',
                'message': 'Test broadcast'
            }
            add_event(test_event)
            mock_emit.assert_called_with('new_event', unittest.mock.ANY)
        logger.info("✓ WebSocket events test passed")
        
    def test_5_metrics_validation(self):
        """Test metrics validation"""
        from web.app import validateMetric
        
        # Test normal cases
        self.assertEqual(validateMetric(50, 0, 100), 50)
        self.assertEqual(validateMetric(-10, 0, 100), 0)
        self.assertEqual(validateMetric(150, 0, 100), 100)
        
        # Test edge cases
        self.assertEqual(validateMetric(None, 0, 100), 0)
        self.assertEqual(validateMetric("invalid", 0, 100), 0)
        self.assertEqual(validateMetric(float('inf'), 0, 100), 100)
        logger.info("✓ Metrics validation test passed")
        
    def test_6_error_handling(self):
        """Test error handling"""
        # Test invalid route
        response = self.client.get('/invalid_route')
        self.assertEqual(response.status_code, 404)
        
        # Test invalid event
        with patch('web.app.logger.error') as mock_logger:
            add_event(None)
            mock_logger.assert_called()
        logger.info("✓ Error handling test passed")
        
    def test_7_dashboard_data(self):
        """Test dashboard data endpoints"""
        # Test monitor status
        self.assertEqual(len(self.dashboard.monitors), 4)
        for monitor in self.dashboard.monitors.values():
            self.assertIn('active', monitor)
            self.assertIn('description', monitor)
            
        # Test system stats
        from web.app import system_stats
        self.assertIn('cpu_percent', system_stats)
        self.assertIn('memory_percent', system_stats)
        self.assertIn('network_speed', system_stats)
        self.assertIn('active_alerts', system_stats)
        logger.info("✓ Dashboard data test passed")

if __name__ == '__main__':
    unittest.main(verbosity=2)
