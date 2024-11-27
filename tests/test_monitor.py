#!/usr/bin/env python3

import os
import sys
import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.monitor import SystemMonitor

class TestSystemMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        logger.remove()
        logger.add(sys.stderr, level="INFO")
        cls.config = {
            'monitor': {
                'enabled': True,
                'interval': 5,
                'thresholds': {
                    'cpu': 90,
                    'memory': 85,
                    'disk': 95
                }
            }
        }
        
    def setUp(self):
        """Initialize monitor for each test"""
        self.monitor = SystemMonitor(self.config)
        
    def test_monitor_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertTrue(hasattr(self.monitor, 'start_monitoring'))
        self.assertTrue(hasattr(self.monitor, 'stop_monitoring'))
        
    @patch('psutil.cpu_percent')
    def test_cpu_monitoring(self, mock_cpu):
        """Test CPU monitoring functionality"""
        mock_cpu.return_value = 50.0
        cpu_usage = self.monitor.get_cpu_usage()
        self.assertEqual(cpu_usage, 50.0)
        mock_cpu.assert_called_once()
        
    @patch('psutil.virtual_memory')
    def test_memory_monitoring(self, mock_memory):
        """Test memory monitoring functionality"""
        mock_memory.return_value = Mock(percent=75.0)
        memory_usage = self.monitor.get_memory_usage()
        self.assertEqual(memory_usage, 75.0)
        mock_memory.assert_called_once()
        
    @patch('psutil.disk_usage')
    def test_disk_monitoring(self, mock_disk):
        """Test disk monitoring functionality"""
        mock_disk.return_value = Mock(percent=60.0)
        disk_usage = self.monitor.get_disk_usage('/')
        self.assertEqual(disk_usage, 60.0)
        mock_disk.assert_called_once_with('/')
        
    def test_alert_thresholds(self):
        """Test alert threshold functionality"""
        self.assertEqual(self.monitor.thresholds['cpu'], 90)
        self.assertEqual(self.monitor.thresholds['memory'], 85)
        self.assertEqual(self.monitor.thresholds['disk'], 95)
        
    @patch('modules.monitor.SystemMonitor.get_cpu_usage')
    def test_alert_generation(self, mock_cpu):
        """Test alert generation when thresholds are exceeded"""
        mock_cpu.return_value = 95.0
        alert = self.monitor.check_cpu_alert()
        self.assertTrue(alert)
        self.assertIn('CPU usage exceeded threshold', str(alert))

if __name__ == '__main__':
    unittest.main(verbosity=2)
