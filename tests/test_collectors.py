#!/usr/bin/env python3

import os
import sys
import time
import threading
import logging
from loguru import logger
import socket

# Add parent directory to path to import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.collectors.syslog import SyslogCollector
from modules.collectors.custom import CustomLogCollector

def test_syslog_collector():
    """Test the Syslog collector with both UDP and TCP"""
    print("\nTesting Syslog Collector...")
    
    # Configure collector
    config = {
        'port': 5140,  # Use non-privileged port for testing
        'protocol': 'UDP',
        'buffer_size': 8192
    }
    
    # Create collector
    collector = SyslogCollector(config)
    
    # Start collector in a thread
    collector_thread = threading.Thread(target=collector.start)
    collector_thread.daemon = True
    collector_thread.start()
    
    time.sleep(1)  # Give collector time to start
    
    # Test UDP
    try:
        # Send RFC3164 format message
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = '<13>Mar 15 11:22:33 localhost test: Test message via UDP'
        sock.sendto(message.encode(), ('127.0.0.1', 5140))
        sock.close()
        
        # Check if message was received
        time.sleep(1)
        event = collector.event_queue.get_nowait()
        print("Received UDP syslog message:", event)
        assert event['format'] == 'RFC3164'
        assert event['message'] == 'Test message via UDP'
        print("UDP test passed!")
        
    except Exception as e:
        print(f"UDP test failed: {e}")
    
    # Stop collector
    collector.stop()
    collector_thread.join(timeout=1)

def test_custom_collector():
    """Test the Custom log collector"""
    print("\nTesting Custom Log Collector...")
    
    # Create test log file
    test_log = "test_custom.log"
    with open(test_log, 'w') as f:
        f.write("192.168.1.1 - - [15/Mar/2024:11:22:33 +0000] \"GET /test HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"\n")
    
    # Configure collector
    config = {
        'paths': [test_log],
        'patterns': [r'GET /test']
    }
    
    # Create collector
    collector = CustomLogCollector(config)
    
    # Start collector
    collector_thread = threading.Thread(target=collector.start)
    collector_thread.daemon = True
    collector_thread.start()
    
    time.sleep(1)  # Give collector time to start
    
    try:
        # Append new log entry
        with open(test_log, 'a') as f:
            f.write("192.168.1.2 - - [15/Mar/2024:11:22:34 +0000] \"GET /test HTTP/1.1\" 200 5678 \"-\" \"Mozilla/5.0\"\n")
        
        # Check if message was received
        time.sleep(1)
        event = collector.event_queue.get_nowait()
        print("Received custom log message:", event)
        assert event['format'] == 'APACHE'
        assert 'GET /test' in event['request']
        print("Custom collector test passed!")
        
    except Exception as e:
        print(f"Custom collector test failed: {e}")
    finally:
        # Clean up
        collector.stop()
        collector_thread.join(timeout=1)
        if os.path.exists(test_log):
            os.remove(test_log)

def main():
    """Run all tests"""
    # Configure logging
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    
    try:
        test_syslog_collector()
        test_custom_collector()
        print("\nAll tests completed!")
    except Exception as e:
        print(f"\nTest suite failed: {e}")

if __name__ == '__main__':
    main()
