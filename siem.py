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
    def __init__(self, config: Dict):
        """Initialize SIEM system with configuration"""
        self.setup_logging()
        self.load_config()
        self.check_dependencies()
        
        # Initialize state flags
        self.is_running = False
        self.is_initialized = False
        self.processing = False
        self.shutdown_requested = False
        
        # Real-time event processing configuration
        self.event_batch_size = 100  # Process events in small batches
        self.max_queue_size = 10000  # Maximum events in queue
        self.event_queue = Queue(maxsize=self.max_queue_size)
        
        # Real-time monitoring intervals (in seconds)
        self.intervals = {
            'process': 1.0,    # Process monitoring every 1 second
            'network': 0.5,    # Network monitoring every 0.5 seconds
            'metrics': 1.0,    # Metrics update every 1 second
            'health': 5.0      # Health check every 5 seconds
        }
        
        try:
            self.initialize_components()
            
            # Initialize Flask app with async mode
            self.app = Flask(__name__)
            self.socketio = SocketIO(self.app, async_mode='gevent', cors_allowed_origins="*")
            
            # Setup routes and real-time event handlers
            self.setup_routes()
            self.setup_socketio_handlers()
            
            # Component status tracking
            self.components_status = {
                'system_collector': False,
                'syslog_collector': False,
                'custom_collector': False,
                'system_monitor': False,
                'offensive_tools': False,
                'defensive_tools': False
            }
            
            # Initialize recovery mechanism
            self.last_health_check = time.time()
            self.health_check_interval = 5  # seconds
            self.component_restart_attempts = {}
            self.max_restart_attempts = 3
            
            self.is_initialized = True
            logger.info("SIEM system initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SIEM system: {e}")
            raise SystemExit("SIEM initialization failed")

    def setup_logging(self):
        """Configure logging settings"""
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
                self.config = yaml.safe_load(f)
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self.config = {}
            
    def check_dependencies(self):
        """Check and install required dependencies"""
        self.check_nmap()
        self.check_winpcap()
        self.check_python_packages()
        
    def check_nmap(self):
        """Check if Nmap is installed and accessible"""
        try:
            # Try to run nmap version command
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("Nmap is installed and accessible")
                return
        except FileNotFoundError:
            pass
            
        logger.warning("Nmap not found. Please install Nmap manually from https://nmap.org/download.html")
        logger.info("You can continue with limited functionality, but network scanning will be restricted")
        
    def check_winpcap(self):
        """Check if WinPcap/Npcap is installed"""
        if platform.system() == 'Windows':
            try:
                import winpcap
                logger.info("WinPcap/Npcap is installed")
            except ImportError:
                logger.warning("WinPcap/Npcap not found. Please install from https://www.winpcap.org/")
                logger.info("Packet capture functionality will be limited")
                
    def check_python_packages(self):
        """Check if required Python packages are installed"""
        required_packages = [
            'pyyaml',
            'python-nmap',
            'scapy',
            'requests',
            'aiohttp',
            'asyncio',
            'websockets',
            'pyOpenSSL',
            'loguru'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
                
        if missing_packages:
            logger.warning(f"Missing required packages: {', '.join(missing_packages)}")
            logger.info("Installing missing packages...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_packages)
                logger.info("Successfully installed missing packages")
            except Exception as e:
                logger.error(f"Error installing packages: {e}")
                
    def initialize_components(self):
        """Initialize offensive and defensive components"""
        try:
            # Initialize collector factory
            self.collector_factory = CollectorFactory()
            
            # Get available collectors for current platform
            available_collectors = self.collector_factory.get_available_collectors()
            logger.info(f"Available collectors: {available_collectors}")
            
            # Initialize collectors
            self.collectors = {}
            
            # Initialize system collector based on platform
            if 'system' in available_collectors and available_collectors['system']:
                try:
                    system_collector = self.collector_factory.create_collector(
                        'system',
                        self.config.get('system_logs', {})
                    )
                    if system_collector:
                        self.collectors['system'] = system_collector
                        logger.info(f"System collector initialized for platform {platform.system()}")
                except Exception as e:
                    logger.error(f"Error initializing system collector: {e}")
            
            # Initialize syslog collector
            try:
                syslog_collector = self.collector_factory.create_collector(
                    'syslog',
                    self.config.get('syslog', {
                        'port': 5140,
                        'protocol': 'UDP',
                        'buffer_size': 8192
                    })
                )
                if syslog_collector:
                    self.collectors['syslog'] = syslog_collector
                    logger.info("Syslog collector initialized")
            except Exception as e:
                logger.error(f"Error initializing syslog collector: {e}")
            
            # Initialize custom collector
            try:
                custom_collector = self.collector_factory.create_collector(
                    'custom',
                    self.config.get('custom_logs', {
                        'paths': [],
                        'patterns': []
                    })
                )
                if custom_collector:
                    self.collectors['custom'] = custom_collector
                    logger.info("Custom collector initialized")
            except Exception as e:
                logger.error(f"Error initializing custom collector: {e}")
            
            # Initialize offensive and defensive tools
            try:
                self.offensive = OffensiveTools(self.config.get('offensive', {}))
                logger.info("Offensive tools initialized")
            except Exception as e:
                logger.error(f"Error initializing offensive tools: {e}")
                self.offensive = None
            
            try:
                self.defensive = DefensiveTools(self.config.get('defensive', {}))
                logger.info("Defensive tools initialized")
            except Exception as e:
                logger.error(f"Error initializing defensive tools: {e}")
                self.defensive = None
            
            # Initialize system monitor
            try:
                self.monitor = SystemMonitor(self.config.get('monitor', {}))
                logger.info("System monitor initialized")
            except Exception as e:
                logger.error(f"Error initializing system monitor: {e}")
                self.monitor = None
            
        except Exception as e:
            logger.error(f"Error in component initialization: {e}")
            raise

    def setup_routes(self):
        """Setup Flask routes"""
        @self.app.route('/')
        def dashboard():
            """Serve the main SIEM dashboard."""
            return render_template('dashboard.html')

        @self.app.route('/status')
        def status():
            metrics = {}
            if self.monitor:
                metrics = self.monitor.get_metrics()
            
            return jsonify({
                'status': 'running',
                'components': self.components_status,
                'metrics': metrics,
                'timestamp': datetime.now().isoformat()
            })
            
        @self.app.route('/metrics')
        def metrics():
            if not self.monitor:
                return jsonify({'error': 'System monitor not available'}), 503
            
            return jsonify(self.monitor.get_metrics())

    def setup_socketio_handlers(self):
        """Setup Socket.IO event handlers for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Client connected: {request.sid}")
            # Send initial state
            self.socketio.emit('status_update', {
                'status': 'connected',
                'components': self.components_status,
                'timestamp': datetime.now().isoformat()
            })
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Client disconnected: {request.sid}")
        
        @self.socketio.on('subscribe_metrics')
        def handle_subscribe_metrics():
            """Handle real-time metrics subscription"""
            self.socketio.emit('metrics_update', {
                'metrics': self.get_current_metrics(),
                'timestamp': datetime.now().isoformat()
            })

    def start_components(self):
        """Start all system components"""
        try:
            # Start collectors
            for collector in self.collectors.values():
                try:
                    collector.start()
                    self.components_status[f"{collector.name}_collector"] = True
                except Exception as e:
                    logger.error(f"Failed to start collector {collector.name}: {e}")
                    self.components_status[f"{collector.name}_collector"] = False
                    continue  # Continue with other collectors even if one fails

            # Start monitor
            if self.monitor:
                try:
                    self.monitor.start()
                    self.components_status["system_monitor"] = True
                except Exception as e:
                    logger.error(f"Failed to start system monitor: {e}")
                    self.components_status["system_monitor"] = False

            # Start offensive tools
            if self.offensive:
                try:
                    self.offensive.start()
                    self.components_status["offensive_tools"] = True
                except Exception as e:
                    logger.error(f"Failed to start offensive tools: {e}")
                    self.components_status["offensive_tools"] = False

            # Start defensive tools
            if self.defensive:
                try:
                    self.defensive.start()
                    self.components_status["defensive_tools"] = True
                except Exception as e:
                    logger.error(f"Failed to start defensive tools: {e}")
                    self.components_status["defensive_tools"] = False

            # Start event processing
            self.start_event_processing()
            
            return True
        except Exception as e:
            logger.error(f"Failed to start components: {e}")
            return False

    def start(self):
        """Start SIEM system"""
        logger.info("Starting SIEM system")
        self.processing = True
        
        # Start event processing thread
        self.process_thread = threading.Thread(target=self._process_events, daemon=True)
        self.process_thread.start()
        
        # Start components
        self.start_components()
        
    def stop(self):
        """Stop SIEM system"""
        logger.info("Stopping SIEM system")
        self.processing = False
        
        # Stop components
        for collector in self.collectors.values():
            collector.stop()
        self.monitor.stop()
        if self.defensive:
            self.defensive.stop()
        if self.offensive:
            self.offensive.stop()
        
        # Wait for event processing to finish
        self.process_thread.join()
        
    def _process_events(self):
        """Process events in real-time"""
        while self.processing:
            try:
                # Process events in batches for better performance
                events = []
                for _ in range(self.event_batch_size):
                    try:
                        event = self.event_queue.get_nowait()
                        events.append(event)
                    except Empty:
                        break
                
                if events:
                    # Process batch of events
                    for event in events:
                        try:
                            processed_event = self._handle_event(event)
                            if processed_event:
                                # Emit real-time event update
                                self.socketio.emit('event_update', {
                                    'event': processed_event,
                                    'timestamp': datetime.now().isoformat()
                                })
                        except Exception as e:
                            logger.error(f"Error processing event: {e}")
                            continue
                
                # Small sleep to prevent CPU overload
                time.sleep(0.01)  # 10ms delay between batches
                
            except Exception as e:
                logger.error(f"Error in event processing loop: {e}")
                time.sleep(0.1)  # Slightly longer delay on error

    def _handle_event(self, event: Dict):
        """Handle different types of security events"""
        try:
            event_type = event.get('type')
            timestamp = event.get('timestamp', datetime.now().isoformat())
            
            if event_type == 'scan_result':
                self._handle_scan_result(event)
            elif event_type == 'alert':
                self._handle_alert(event)
            elif event_type == 'incident':
                self._handle_incident(event)
            else:
                logger.warning(f"Unknown event type: {event_type}")
                
            # Emit event to web interface
            self.socketio.emit('security_event', {
                'type': event_type,
                'timestamp': timestamp,
                'data': event
            })
        except Exception as e:
            logger.error(f"Error handling event: {e}")
            
    def _handle_scan_result(self, event: Dict):
        """Handle scan results"""
        target = event.get('target')
        results = event.get('results', {})
        logger.info(f"Processing scan result for target: {target}")
        
        # Check for vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            logger.warning(f"Found {len(vulnerabilities)} vulnerabilities for {target}")
            # Create incident for critical vulnerabilities
            critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
            if critical_vulns:
                self._create_incident(
                    title=f"Critical vulnerabilities found on {target}",
                    description=f"Found {len(critical_vulns)} critical vulnerabilities",
                    severity="high",
                    source="vulnerability_scan",
                    details={'vulnerabilities': critical_vulns}
                )
        
    def _handle_alert(self, event: Dict):
        """Handle security alerts"""
        alert_type = event.get('alert_type')
        message = event.get('message')
        severity = event.get('severity', 'medium')
        source = event.get('source')
        
        logger.warning(f"Security alert: {message}")
        
        # Check if alert should be escalated to incident
        if severity in ['high', 'critical'] or self._check_alert_threshold(alert_type):
            self._create_incident(
                title=f"Security alert escalated: {alert_type}",
                description=message,
                severity=severity,
                source=source,
                details=event
            )
            
    def _handle_incident(self, event: Dict):
        """Handle security incidents"""
        title = event.get('title')
        description = event.get('description')
        severity = event.get('severity', 'high')
        source = event.get('source')
        details = event.get('details', {})
        
        logger.error(f"Security incident: {title}")
        
        # Record incident
        incident_id = self._record_incident(event)
        
        # Take automated actions based on severity and type
        if severity == 'critical':
            self._automated_response(event)
            
        # Notify administrators
        self._notify_admins(incident_id, event)
        
        # Update web interface
        self.socketio.emit('incident', {
            'id': incident_id,
            'title': title,
            'description': description,
            'severity': severity,
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'status': 'new'
        })
        
    def _create_incident(self, title: str, description: str, severity: str, source: str, details: Dict):
        """Create a new security incident"""
        incident = {
            'type': 'incident',
            'title': title,
            'description': description,
            'severity': severity,
            'source': source,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.event_queue.put(incident)
        
    def _check_alert_threshold(self, alert_type: str) -> bool:
        """Check if alert threshold is exceeded"""
        # Implement alert threshold checking logic
        return False
        
    def _record_incident(self, incident: Dict) -> str:
        """Record incident in database/file"""
        # Implement incident recording logic
        incident_id = f"INC-{int(time.time())}"
        return incident_id
        
    def _automated_response(self, incident: Dict):
        """Execute automated response actions"""
        if self.defensive:
            # Implement automated response actions
            pass
            
    def _notify_admins(self, incident_id: str, incident: Dict):
        """Notify administrators about incident"""
        # Implement admin notification logic
        pass

    def health_check(self):
        """Perform health check on all components"""
        try:
            unhealthy_components = []
            
            # Check collectors
            for name, collector in self.collectors.items():
                if isinstance(collector, BaseEventCollector) and not collector.is_healthy():
                    unhealthy_components.append((f"{name}_collector", collector))
            
            # Check system monitor
            if self.monitor and not self.monitor.is_healthy():
                unhealthy_components.append(('system_monitor', self.monitor))
            
            # Check tools
            if self.defensive and not self.defensive.is_healthy():
                unhealthy_components.append(('defensive_tools', self.defensive))
            if self.offensive and not self.offensive.is_healthy():
                unhealthy_components.append(('offensive_tools', self.offensive))
            
            # Attempt recovery for unhealthy components
            for component_name, component in unhealthy_components:
                self._recover_component(component_name, component)
            
            # Update status
            self.socketio.emit('health_status', {
                'status': 'healthy' if not unhealthy_components else 'degraded',
                'unhealthy_components': [comp[0] for comp in unhealthy_components],
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")

    def _recover_component(self, component_name: str, component: Any):
        """Attempt to recover a failed component"""
        try:
            attempts = self.component_restart_attempts.get(component_name, 0)
            if attempts >= self.max_restart_attempts:
                logger.error(f"Max restart attempts reached for {component_name}")
                return
                
            logger.warning(f"Attempting to recover {component_name}")
            self.component_restart_attempts[component_name] = attempts + 1
            
            # Stop component
            if hasattr(component, 'stop'):
                component.stop()
                
            # Wait for cleanup
            time.sleep(2)
            
            # Start component
            if hasattr(component, 'start'):
                component.start()
                
            # Update status
            self.components_status[component_name] = True
            logger.info(f"Successfully recovered {component_name}")
            
            # Reset attempts on successful recovery
            self.component_restart_attempts[component_name] = 0
            
        except Exception as e:
            logger.error(f"Failed to recover {component_name}: {e}")
            
    def graceful_shutdown(self):
        """Perform graceful shutdown of SIEM system"""
        logger.info("Initiating graceful shutdown")
        self.shutdown_requested = True
        
        try:
            # Stop processing new events
            self.processing = False
            
            # Wait for event queue to drain
            timeout = time.time() + 30  # 30 seconds timeout
            while not self.event_queue.empty() and time.time() < timeout:
                time.sleep(1)
                
            # Stop all components
            self.stop()
            
            # Close Flask app
            if self.is_running:
                self.socketio.stop()
                
            logger.info("SIEM system shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            
        finally:
            self.is_running = False

    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the SIEM application"""
        try:
            # Start all monitoring and collection threads
            self.start()
            
            # Configure Gevent WSGI server for better performance
            http_server = WSGIServer((host, port), self.app, handler_class=WebSocketHandler)
            logger.info(f"Starting SIEM server on {host}:{port}")
            http_server.serve_forever()
            
        except Exception as e:
            logger.error(f"Error running SIEM server: {e}")
            self.stop()
            raise
        finally:
            self.graceful_shutdown()

if __name__ == '__main__':
    siem = SIEM({})
    siem.run(debug=True)
