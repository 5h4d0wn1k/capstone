#!/usr/bin/env python3

import os
import sys
import asyncio
import pytest
import json
from datetime import datetime
from loguru import logger

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem import SIEM
from collectors import WindowsEventCollector, SyslogCollector, CustomLogCollector
from modules.monitors.system_monitor import SystemMonitor
from modules.offensive import OffensiveTools
from modules.defensive import DefensiveTools
from database import AsyncDatabase

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_config():
    """Provide test configuration"""
    test_dir = os.path.join(os.path.dirname(__file__), 'test_files')
    os.makedirs(test_dir, exist_ok=True)
    
    test_log = os.path.join(test_dir, 'test.log')
    with open(test_log, 'w') as f:
        f.write("192.168.1.1 - - [15/Mar/2024:11:22:33 +0000] \"GET /test HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"\n")
    
    return {
        'siem': {
            'enabled': True,
            'log_dir': './logs',
            'rules_dir': './rules',
            'db_url': 'sqlite+aiosqlite:///:memory:'
        },
        'collectors': {
            'windows': {
                'enabled': True,
                'channels': ['Security', 'System']
            },
            'syslog': {
                'enabled': True,
                'port': 5140,
                'protocol': 'UDP'
            },
            'custom': {
                'enabled': True,
                'paths': [test_log]
            }
        },
        'monitor': {
            'enabled': True,
            'interval': 5,
            'thresholds': {
                'cpu': 90,
                'memory': 85,
                'disk': 95
            }
        },
        'defensive': {
            'enabled': True,
            'log_dir': './logs',
            'rules_dir': './rules',
            'alert_threshold': 80
        },
        'offensive': {
            'enabled': True,
            'scan_interval': 3600,
            'target_networks': ['192.168.1.0/24']
        }
    }

@pytest.fixture
async def siem_instance(test_config):
    """Initialize async SIEM instance"""
    siem = SIEM(test_config)
    await siem.initialize()
    yield siem
    await siem.shutdown()

@pytest.fixture
async def db(test_config):
    """Initialize test database"""
    db = AsyncDatabase(test_config['siem']['db_url'])
    await db.initialize()
    yield db
    await db.close()

@pytest.mark.asyncio
async def test_siem_initialization(siem_instance):
    """Test async SIEM initialization"""
    assert siem_instance.config is not None
    assert hasattr(siem_instance, 'windows_collector')
    assert hasattr(siem_instance, 'syslog_collector')
    assert hasattr(siem_instance, 'custom_collector')
    assert hasattr(siem_instance, 'system_monitor')

@pytest.mark.asyncio
async def test_defensive_module(siem_instance):
    """Test defensive module async functionality"""
    defensive = siem_instance.defensive_tools
    
    # Test threat detection initialization
    await defensive.initialize_threat_detection()
    assert defensive.threat_patterns is not None
    
    # Test anomaly detection
    anomaly_result = await defensive.check_anomalies({
        'source_ip': '192.168.1.100',
        'timestamp': datetime.now(),
        'event_type': 'login_attempt'
    })
    assert isinstance(anomaly_result, dict)
    
    # Test alert generation
    alert = await defensive.create_alert('test_alert', 'high', 'Suspicious activity detected')
    assert alert['severity'] == 'high'

@pytest.mark.asyncio
async def test_offensive_module(siem_instance):
    """Test offensive module async functionality"""
    offensive = siem_instance.offensive_tools
    
    # Test scanner initialization
    await offensive.initialize_scanners()
    assert offensive.network_scanner is not None
    
    # Test vulnerability scanning
    scan_result = await offensive.scan_target('127.0.0.1')
    assert isinstance(scan_result, dict)
    
    # Test threat intel updates
    await offensive.update_threat_intelligence()
    assert offensive.threat_intel_data is not None

@pytest.mark.asyncio
async def test_event_processing(siem_instance, db):
    """Test async event processing pipeline"""
    test_event = {
        'timestamp': datetime.now(),
        'source': 'test_source',
        'event_type': 'security_alert',
        'severity': 'high',
        'details': {'message': 'Test security event'}
    }
    
    # Process test event
    event_id = await siem_instance.process_event(test_event)
    assert event_id is not None
    
    # Verify event in database
    stored_event = await db.get_event(event_id)
    assert stored_event is not None
    assert stored_event['severity'] == 'high'

if __name__ == '__main__':
    pytest.main(['-v', __file__])
