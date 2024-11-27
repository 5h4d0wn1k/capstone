#!/usr/bin/env python3

import os
import sys
import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.defensive import DefensiveTools

class TestDefensiveTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        logger.remove()
        logger.add(sys.stderr, level="INFO")
        cls.config = {
            'defensive': {
                'enabled': True,
                'log_dir': './logs',
                'rules_dir': './rules',
                'alert_threshold': 80
            }
        }
        
    def setUp(self):
        """Initialize defensive tools for each test"""
        self.defensive = DefensiveTools(self.config)
        
    def test_initialization(self):
        """Test defensive tools initialization"""
        self.assertIsNotNone(self.defensive)
        self.assertTrue(hasattr(self.defensive, 'analyze_traffic'))
        self.assertTrue(hasattr(self.defensive, 'detect_threats'))
        
    @patch('modules.defensive.DefensiveTools.get_network_traffic')
    def test_traffic_analysis(self, mock_traffic):
        """Test traffic analysis functionality"""
        mock_traffic.return_value = [
            {'src': '192.168.1.1', 'dst': '192.168.1.2', 'port': 80},
            {'src': '192.168.1.3', 'dst': '192.168.1.4', 'port': 443}
        ]
        analysis = self.defensive.analyze_traffic()
        self.assertIsNotNone(analysis)
        self.assertEqual(len(analysis), 2)
        mock_traffic.assert_called_once()
        
    def test_threat_detection(self):
        """Test threat detection capabilities"""
        sample_log = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.100',
            'event_type': 'login_attempt',
            'status': 'failed',
            'attempts': 5
        }
        threat_level = self.defensive.detect_threats(sample_log)
        self.assertIsInstance(threat_level, (int, float))
        self.assertTrue(0 <= threat_level <= 100)
        
    @patch('modules.defensive.DefensiveTools.get_system_logs')
    def test_log_analysis(self, mock_logs):
        """Test log analysis functionality"""
        mock_logs.return_value = [
            {'type': 'warning', 'message': 'Failed login attempt'},
            {'type': 'error', 'message': 'Unauthorized access attempt'}
        ]
        analysis = self.defensive.analyze_logs()
        self.assertTrue(isinstance(analysis, list))
        mock_logs.assert_called_once()
        
    def test_firewall_rules(self):
        """Test firewall rules management"""
        test_rule = {
            'action': 'block',
            'source_ip': '192.168.1.100',
            'destination_port': 22
        }
        result = self.defensive.add_firewall_rule(test_rule)
        self.assertTrue(result)
        rules = self.defensive.get_firewall_rules()
        self.assertIn(test_rule, rules)
        
    def test_incident_response(self):
        """Test incident response procedures"""
        incident = {
            'type': 'brute_force',
            'source': '192.168.1.100',
            'timestamp': datetime.now().isoformat()
        }
        response = self.defensive.handle_incident(incident)
        self.assertIsNotNone(response)
        self.assertIn('action_taken', response)

if __name__ == '__main__':
    unittest.main(verbosity=2)
