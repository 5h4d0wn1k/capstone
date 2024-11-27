#!/usr/bin/env python3

import os
import sys
import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.detectors.anomaly_detector import AnomalyDetector
from modules.detectors.threat_detector import ThreatDetector

class TestDetectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        logger.remove()
        logger.add(sys.stderr, level="INFO")
        
    def setUp(self):
        """Initialize detectors for each test"""
        self.anomaly_detector = AnomalyDetector()
        self.threat_detector = ThreatDetector()
        
    def test_anomaly_detector_initialization(self):
        """Test anomaly detector initialization"""
        self.assertIsNotNone(self.anomaly_detector)
        self.assertTrue(hasattr(self.anomaly_detector, 'detect'))
        
    def test_threat_detector_initialization(self):
        """Test threat detector initialization"""
        self.assertIsNotNone(self.threat_detector)
        self.assertTrue(hasattr(self.threat_detector, 'detect'))
        
    def test_anomaly_detection(self):
        """Test anomaly detection functionality"""
        test_data = {
            'cpu_usage': 95.0,
            'memory_usage': 90.0,
            'network_traffic': 1000000
        }
        anomalies = self.anomaly_detector.detect(test_data)
        self.assertIsInstance(anomalies, list)
        self.assertTrue(len(anomalies) > 0)
        
    def test_threat_detection(self):
        """Test threat detection functionality"""
        test_event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.200',
            'port': 445,
            'protocol': 'SMB'
        }
        threats = self.threat_detector.detect(test_event)
        self.assertIsInstance(threats, list)
        
    @patch('modules.detectors.anomaly_detector.AnomalyDetector.get_baseline')
    def test_baseline_comparison(self, mock_baseline):
        """Test baseline comparison functionality"""
        mock_baseline.return_value = {
            'cpu_usage': 50.0,
            'memory_usage': 60.0,
            'network_traffic': 500000
        }
        current_data = {
            'cpu_usage': 90.0,
            'memory_usage': 85.0,
            'network_traffic': 1000000
        }
        deviations = self.anomaly_detector.compare_to_baseline(current_data)
        self.assertTrue(len(deviations) > 0)
        mock_baseline.assert_called_once()
        
    def test_threat_patterns(self):
        """Test threat pattern recognition"""
        test_patterns = [
            {'pattern': 'bruteforce', 'threshold': 5},
            {'pattern': 'port_scan', 'threshold': 100}
        ]
        self.threat_detector.load_patterns(test_patterns)
        self.assertEqual(len(self.threat_detector.patterns), 2)
        
    def test_false_positives(self):
        """Test false positive handling"""
        known_safe = {
            'source_ip': '192.168.1.10',
            'activity': 'backup_process'
        }
        self.anomaly_detector.add_whitelist(known_safe)
        result = self.anomaly_detector.check_whitelist(known_safe)
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main(verbosity=2)
