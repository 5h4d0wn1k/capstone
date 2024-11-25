#!/usr/bin/env python3

import os
import sys
import time
import json
import yaml
import logging
import threading
import platform
from typing import Dict, List, Any, Optional
import subprocess
from queue import Queue, Empty
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from loguru import logger
from datetime import datetime
import signal
from importlib.metadata import version, PackageNotFoundError
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler

# Import our modules
from modules.offensive import OffensiveTools
from modules.defensive import DefensiveTools
from modules.monitor import SystemMonitor
from modules.collectors.factory import CollectorFactory
from modules.collectors.base import BaseEventCollector

class SIEM:
    def __init__(self, config: Dict = None):
        """Initialize SIEM system with configuration"""
        self.config = config or {}
        self.setup_logging()
        self.load_config()
        
        # Initialize state flags
        self.is_running = False
        self.is_initialized = False
        self.processing = False
        self.shutdown_requested = False
        
        # Initialize components
        self.initialize_monitors()
        self.initialize_web_interface()
        
        self.is_initialized = True
        logger.info("SIEM system initialized successfully")

    def setup_logging(self):
        """Configure logging settings"""
        os.makedirs('logs', exist_ok=True)
        logger.add(
            "logs/siem.log",
            rotation="500 MB",
            retention="10 days",
            level="INFO",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
        )
        
    def load_config(self):
        """Load configuration from yaml file"""
        try:
            with open('config.yaml', 'r') as f:
                self.config.update(yaml.safe_load(f))
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            
    def initialize_monitors(self):
        """Initialize monitoring components"""
        from modules.monitors.process_monitor import ProcessMonitor
        from modules.monitors.network_monitor import NetworkMonitor
        from modules.monitors.file_monitor import FileMonitor
        from modules.monitors.registry_monitor import RegistryMonitor
        
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkMonitor()
        self.file_monitor = FileMonitor()
        self.registry_monitor = RegistryMonitor()
        
    def initialize_web_interface(self):
        """Initialize Flask app and SocketIO"""
        from flask import Flask, jsonify
        from flask_socketio import SocketIO
        
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, async_mode='threading', cors_allowed_origins="*")
        
        @self.app.route('/')
        def index():
            return 'SIEM Web Interface'
            
        @self.app.route('/api/events')
        def get_events():
            events = []
            if hasattr(self, 'process_monitor'):
                events.extend(self.process_monitor.get_events())
            if hasattr(self, 'network_monitor'):
                events.extend(self.network_monitor.get_events())
            if hasattr(self, 'file_monitor'):
                events.extend(self.file_monitor.get_events())
            if hasattr(self, 'registry_monitor'):
                events.extend(self.registry_monitor.get_events())
            return jsonify(events)
            
    def start_monitors(self):
        """Start all monitoring components"""
        if hasattr(self, 'process_monitor'):
            self.process_monitor.start()
        if hasattr(self, 'network_monitor'):
            self.network_monitor.start()
        if hasattr(self, 'file_monitor'):
            self.file_monitor.start()
        if hasattr(self, 'registry_monitor'):
            self.registry_monitor.start()
            
    def stop_monitors(self):
        """Stop all monitoring components"""
        if hasattr(self, 'process_monitor'):
            self.process_monitor.stop()
        if hasattr(self, 'network_monitor'):
            self.network_monitor.stop()
        if hasattr(self, 'file_monitor'):
            self.file_monitor.stop()
        if hasattr(self, 'registry_monitor'):
            self.registry_monitor.stop()
            
    def add_event(self, event: Dict):
        """Add event to the system"""
        if not self.is_initialized:
            logger.error("SIEM not initialized")
            return False
            
        try:
            # Emit event through WebSocket
            self.socketio.emit('new_event', event)
            return True
        except Exception as e:
            logger.error(f"Error adding event: {e}")
            return False
            
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the SIEM system"""
        if not self.is_initialized:
            logger.error("SIEM not initialized")
            return
            
        try:
            self.start_monitors()
            self.is_running = True
            self.socketio.run(self.app, host=host, port=port, debug=debug)
        except Exception as e:
            logger.error(f"Error running SIEM: {e}")
        finally:
            self.shutdown()
            
    def shutdown(self):
        """Shutdown the SIEM system"""
        self.is_running = False
        self.stop_monitors()
        logger.info("SIEM system shutdown complete")

if __name__ == '__main__':
    siem = SIEM({})
    siem.run(debug=True)
