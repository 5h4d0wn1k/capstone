from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import psutil
import json
from datetime import datetime, timedelta
import threading
import queue
import logging
from logging.handlers import RotatingFileHandler
import os
import time
from typing import Dict, Any, List
import socket
from loguru import logger

# Initialize Flask app with proper secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=60)

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler(
    'logs/web.log',
    maxBytes=1024 * 1024,  # 1MB
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Web server startup')

# Global variables
event_queue = queue.Queue()
event_lock = threading.Lock()
events: List[Dict[str, Any]] = []
connected_clients = set()
system_stats = {
    'cpu_percent': 0,
    'memory_percent': 0,
    'network_speed': 0,
    'active_alerts': 0
}

# SIEM instance reference
siem_instance = None

class Dashboard:
    def __init__(self):
        self.monitors = {
            'ProcessMonitor': {'active': True, 'description': 'Monitoring system processes'},
            'NetworkMonitor': {'active': True, 'description': 'Monitoring network traffic'},
            'FileMonitor': {'active': True, 'description': 'Monitoring file system changes'},
            'RegistryMonitor': {'active': True, 'description': 'Monitoring registry changes'}
        }
        self.stats_thread = None
        self.events_thread = None
        self.running = True
        
    def start(self):
        """Start dashboard background tasks"""
        self.stats_thread = threading.Thread(target=self.update_system_stats, daemon=True)
        self.events_thread = threading.Thread(target=self.process_events, daemon=True)
        
        self.stats_thread.start()
        self.events_thread.start()
    
    def stop(self):
        """Stop dashboard background tasks"""
        self.running = False
        if self.stats_thread:
            self.stats_thread.join(timeout=5)
        if self.events_thread:
            self.events_thread.join(timeout=5)
    
    def update_system_stats(self):
        """Update system statistics periodically"""
        while self.running:
            try:
                # CPU Usage
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # Memory Usage
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
                
                # Network Speed (KB/s)
                net_io = psutil.net_io_counters()
                network_speed = (net_io.bytes_sent + net_io.bytes_recv) / 1024
                
                # Update global stats
                system_stats.update({
                    'cpu_percent': round(cpu_percent, 1),
                    'memory_percent': round(memory_percent, 1),
                    'network_speed': round(network_speed, 2),
                    'active_alerts': len([e for e in events if e.get('severity') in ['Critical', 'High']])
                })
                
                # Broadcast to all clients
                socketio.emit('system_stats', system_stats)
                
            except Exception as e:
                logger.error(f"Error updating system stats: {e}")
            
            time.sleep(2)  # Update every 2 seconds
    
    def process_events(self):
        """Process events from the queue"""
        while self.running:
            try:
                if not event_queue.empty():
                    event = event_queue.get_nowait()
                    
                    # Add timestamp if not present
                    if 'timestamp' not in event:
                        event['timestamp'] = datetime.now().isoformat()
                    
                    # Add to events list
                    with event_lock:
                        events.append(event)
                        if len(events) > 1000:  # Keep last 1000 events
                            events.pop(0)
                    
                    # Broadcast to all clients
                    socketio.emit('new_event', event)
                    
                    # Update monitor status if needed
                    if event.get('monitor_status'):
                        self.monitors[event['source']]['active'] = event['monitor_status']
                        socketio.emit('monitor_status', self.monitors)
                    
            except queue.Empty:
                pass
            except Exception as e:
                logger.error(f"Error processing events: {e}")
            
            time.sleep(0.1)  # Prevent high CPU usage

# Initialize dashboard
dashboard = Dashboard()

@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    client_id = request.sid
    connected_clients.add(client_id)
    logger.info(f'Client connected: {client_id}')
    
    # Send initial data
    emit('monitor_status', dashboard.monitors)
    emit('system_stats', system_stats)
    
    # Send recent events
    with event_lock:
        for event in events[-100:]:  # Send last 100 events
            emit('new_event', event)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    client_id = request.sid
    if client_id in connected_clients:
        connected_clients.remove(client_id)
        logger.info(f'Client disconnected: {client_id}')

@socketio.on('request_initial_data')
def handle_initial_data():
    """Handle request for initial data"""
    emit('monitor_status', dashboard.monitors)
    emit('system_stats', system_stats)
    
    with event_lock:
        for event in events[-100:]:
            emit('new_event', event)

def add_event(event_data: Dict[str, Any]) -> bool:
    """Add an event to the processing queue
    
    Args:
        event_data: Event data dictionary
        
    Returns:
        bool: True if event was added successfully
    """
    try:
        # Validate event data
        if not isinstance(event_data, dict):
            logger.error("Invalid event data: not a dictionary")
            return False
        
        # Add timestamp if not present
        if 'timestamp' not in event_data:
            event_data['timestamp'] = datetime.now().isoformat()
        
        # Generate event ID if not present
        if 'id' not in event_data:
            event_data['id'] = f"evt_{int(datetime.now().timestamp())}"
        
        # Add to queue
        event_queue.put(event_data)
        
        # Log event
        logger.info(f'New event: {event_data}')
        
        return True
    except Exception as e:
        logger.error(f"Error adding event: {e}")
        return False

def validate_metric(value, min_val=0, max_val=100):
    """
    Validate and normalize a metric value.
    
    Args:
        value: The value to validate
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        
    Returns:
        float: Normalized value between min_val and max_val
    """
    try:
        val = float(value)
        return max(min_val, min(val, max_val))
    except (TypeError, ValueError):
        return min_val

def start_web_interface(siem, debug: bool = False):
    """Start web interface
    
    Args:
        siem: SIEM instance
        debug: Enable debug mode
    """
    global siem_instance
    siem_instance = siem
    
    try:
        # Start dashboard
        dashboard.start()
        
        # Find a free port
        port = find_free_port()
        logger.info(f"Starting web interface on port {port}")
        
        # Start Flask app
        socketio.run(app, host='0.0.0.0', port=port, debug=debug, use_reloader=False)
    except Exception as e:
        logger.error(f"Failed to start web interface: {e}")
    finally:
        dashboard.stop()

def find_free_port(start_port: int = 5000, max_tries: int = 10) -> int:
    """Find a free port starting from start_port
    
    Args:
        start_port: Starting port number
        max_tries: Maximum number of ports to try
        
    Returns:
        int: Available port number
        
    Raises:
        RuntimeError: If no free port is found
    """
    for port in range(start_port, start_port + max_tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"Could not find a free port in range {start_port}-{start_port + max_tries}")

if __name__ == '__main__':
    start_web_interface(None, debug=True)
