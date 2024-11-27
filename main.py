+import asyncio
import aiohttp
from aiohttp import web
import socketio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func
import logging
from datetime import datetime, timezone, timedelta
import json
import os
import psutil
from loguru import logger
import yaml
from pathlib import Path
from cryptography.fernet import Fernet
import numpy as np
from sklearn.ensemble import IsolationForest
import aiohttp_jinja2
import jinja2
from models import Base, EventModel, AlertModel, NetworkLogModel

# Initialize Socket.IO
sio = socketio.AsyncServer(async_mode='aiohttp', cors_allowed_origins='*')
app = web.Application()
sio.attach(app)

# Setup Jinja2 templates
aiohttp_jinja2.setup(app,
    loader=jinja2.FileSystemLoader(str(Path(__file__).parent / 'templates')))

# Setup static routes
app.router.add_static('/static', str(Path(__file__).parent / 'static'))

# Load configuration
def load_config():
    config_path = Path(__file__).parent / 'config.yaml'
    with open(config_path) as f:
        return yaml.safe_load(f)

config = load_config()

# Database setup
engine = create_async_engine(config['database']['url'])
SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Initialize ML model for anomaly detection
anomaly_detector = IsolationForest(contamination=0.1, random_state=42)

class SIEMCore:
    def __init__(self):
        self.events = []
        self.alerts = []
        self.threat_level = "LOW"
        self.system_health = 100
        self.connected_clients = set()
        self.event_counts = []
        self.alert_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
    async def initialize(self):
        """Initialize SIEM components"""
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SIEM: {str(e)}")
            raise

    async def monitor_system(self):
        """Monitor system health and resources"""
        while True:
            try:
                # Get system metrics
                cpu_percent = psutil.cpu_percent()
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                network_connections = len(psutil.net_connections())
                
                # Calculate system health (simple average of resources)
                self.system_health = 100 - ((cpu_percent + memory.percent + disk.percent) / 3)
                
                # Prepare update data
                update_data = {
                    'system_health': round(self.system_health, 2),
                    'threat_level': self.threat_level,
                    'active_alerts': len(self.alerts),
                    'events_per_minute': len(self.event_counts),
                    'network_connections': network_connections,
                    'system_load': round(cpu_percent, 2)
                }
                
                # Broadcast update
                await self.broadcast_update(update_data)
                
                await asyncio.sleep(5)  # Update every 5 seconds
            except Exception as e:
                logger.error(f"Error in system monitoring: {str(e)}")
                await asyncio.sleep(5)  # Wait before retrying

    async def process_events(self):
        """Process incoming events and generate alerts"""
        while True:
            try:
                # Process events in batch
                current_time = datetime.now(timezone.utc)
                self.event_counts = [e for e in self.event_counts 
                                   if (current_time - e).total_seconds() <= 60]
                
                # Update threat level
                await self.update_threat_level()
                
                # Update alert distribution
                await self._update_alert_distribution()
                
                # Prepare chart data
                chart_data = {
                    'event_timeline': {
                        'time': current_time.isoformat(),
                        'count': len(self.event_counts)
                    },
                    'alert_distribution': self.alert_distribution
                }
                
                # Broadcast chart updates
                await self.broadcast_chart_data(chart_data)
                
                await asyncio.sleep(1)  # Process every second
            except Exception as e:
                logger.error(f"Error in event processing: {str(e)}")
                await asyncio.sleep(1)

    async def _update_alert_distribution(self):
        """Update alert severity distribution"""
        try:
            async with SessionLocal() as session:
                # Count alerts by severity
                result = await session.execute(
                    select(AlertModel.severity, func.count(AlertModel.id))
                    .group_by(AlertModel.severity)
                )
                distribution = dict(result.all())
                
                # Update distribution
                self.alert_distribution = {
                    'critical': distribution.get('critical', 0),
                    'high': distribution.get('high', 0),
                    'medium': distribution.get('medium', 0),
                    'low': distribution.get('low', 0)
                }
        except Exception as e:
            logger.error(f"Error updating alert distribution: {str(e)}")

    async def update_threat_level(self):
        """Update overall threat level"""
        if self.alert_distribution['critical'] > 0:
            self.threat_level = "CRITICAL"
        elif self.alert_distribution['high'] > 2:
            self.threat_level = "HIGH"
        elif self.alert_distribution['medium'] > 5:
            self.threat_level = "MEDIUM"
        else:
            self.threat_level = "LOW"

    async def update_clients(self):
        """Send updates to connected clients"""
        while True:
            try:
                if self.connected_clients:
                    # Prepare update data
                    update_data = {
                        'system_health': round(self.system_health, 2),
                        'threat_level': self.threat_level,
                        'active_alerts': len(self.alerts),
                        'events_per_minute': len(self.event_counts),
                        'network_connections': len(psutil.net_connections()),
                        'system_load': round(psutil.cpu_percent(), 2)
                    }
                    
                    # Broadcast update
                    await self.broadcast_update(update_data)
                
                await asyncio.sleep(1)  # Update every second
            except Exception as e:
                logger.error(f"Error updating clients: {str(e)}")
                await asyncio.sleep(1)

    async def process_event(self, event_data):
        """Process incoming security event"""
        try:
            # Create event record
            event = EventModel(
                source=event_data['source'],
                event_type=event_data['type'],
                severity=event_data['severity'],
                timestamp=datetime.fromisoformat(event_data['data']['timestamp']),
                details=event_data['data']['details'],
                metadata=json.dumps(event_data['data']['metadata'])
            )
            
            # Create alert for high/critical events
            if event.severity in ['high', 'critical']:
                alert = AlertModel(
                    event_id=event.id,
                    severity=event.severity,
                    timestamp=event.timestamp,
                    rule=f"High severity {event.event_type} from {event.source}",
                    details=event.details
                )
                
                # Broadcast alert immediately
                await self.broadcast_alert({
                    'id': str(alert.id),
                    'severity': alert.severity,
                    'timestamp': alert.timestamp.isoformat(),
                    'rule': alert.rule,
                    'details': alert.details,
                    'source': event.source
                })
                
                self.alerts.append(alert)
                
                # Update threat level
                if event.severity == 'critical':
                    self.threat_level = "CRITICAL"
                elif event.severity == 'high' and self.threat_level not in ["CRITICAL"]:
                    self.threat_level = "HIGH"
                
                # Update alert distribution
                self.alert_distribution[event.severity] += 1
            
            # Store event
            async with SessionLocal() as session:
                session.add(event)
                if event.severity in ['high', 'critical']:
                    session.add(alert)
                await session.commit()
            
            # Update event counts
            self.event_counts.append(event)
            
            # Clean old events (keep last hour)
            hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            self.event_counts = [e for e in self.event_counts if e.timestamp > hour_ago]
            
            return True
            
        except Exception as e:
            logger.error(f"Error processing event: {str(e)}")
            return False

    async def broadcast_alert(self, alert_data):
        """Broadcast new alert to all connected clients"""
        try:
            if self.connected_clients:
                await sio.emit('alert', alert_data)
                logger.info(f"Broadcasted alert: {alert_data['message']}")
        except Exception as e:
            logger.error(f"Error broadcasting alert: {str(e)}")

    async def broadcast_update(self, data):
        """Broadcast update to all connected clients"""
        try:
            if self.connected_clients:
                await sio.emit('update', data)
        except Exception as e:
            logger.error(f"Error broadcasting update: {str(e)}")

    async def broadcast_chart_data(self, data):
        """Broadcast chart data to all connected clients"""
        try:
            if self.connected_clients:
                await sio.emit('chart_data', data)
        except Exception as e:
            logger.error(f"Error broadcasting chart data: {str(e)}")

# Initialize SIEM
siem = SIEMCore()

# Socket.IO event handlers
@sio.event
async def connect(sid, environ):
    """Handle client connection"""
    logger.info(f"Client connected: {sid}")
    siem.connected_clients.add(sid)
    
    # Send initial data to the new client
    update_data = {
        'system_health': round(siem.system_health, 2),
        'threat_level': siem.threat_level,
        'active_alerts': len(siem.alerts),
        'events_per_minute': len(siem.event_counts),
        'network_connections': len(psutil.net_connections()),
        'system_load': round(psutil.cpu_percent(), 2)
    }
    await sio.emit('update', update_data, room=sid)

@sio.event
async def disconnect(sid):
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {sid}")
    siem.connected_clients.remove(sid)

# API routes
async def handle_event(request):
    """Handle incoming events"""
    try:
        event_data = await request.json()
        result = await siem.process_event(event_data)
        if result:
            return web.json_response({"status": "success"})
        else:
            return web.json_response({"status": "error"}, status=500)
    except Exception as e:
        logger.error(f"Error handling event: {str(e)}")
        return web.json_response(
            {"status": "error", "message": str(e)}, 
            status=500
        )

# Web routes
@aiohttp_jinja2.template('dashboard.html')
async def handle_dashboard(request):
    """Serve dashboard page"""
    return {}

# Setup routes
app.router.add_get('/', handle_dashboard)
app.router.add_post('/api/events', handle_event)

async def init_app():
    """Initialize the application"""
    try:
        # Initialize SIEM components
        await siem.initialize()
        
        # Start background tasks
        asyncio.create_task(siem.monitor_system())
        asyncio.create_task(siem.process_events())
        asyncio.create_task(siem.update_clients())
        
        logger.info("SIEM system initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        raise

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger.add("siem.log", rotation="500 MB")
    
    # Run the application
    try:
        port = 8080
        while True:
            try:
                asyncio.run(init_app())
                web.run_app(app, host='127.0.0.1', port=port)
                break
            except OSError as e:
                if e.errno == 10048:  # Port is in use
                    port += 1
                    logger.warning(f"Port {port-1} is in use, trying port {port}")
                else:
                    raise
    except KeyboardInterrupt:
        logger.info("Shutting down SIEM system...")
    except Exception as e:
        logger.error(f"Error running SIEM system: {str(e)}")