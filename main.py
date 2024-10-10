import asyncio
import aiohttp
from aiohttp import web
import aiojobs
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, select
import win32evtlog
import win32evtlogutil
import win32con
import win32security
import logging
from datetime import datetime, timedelta
import json
import os

# Try to import pyshark, but provide a fallback if it's not available
try:
    import pyshark
except ImportError:
    print("WARNING: pyshark is not installed. Network capture will be disabled.")
    pyshark = None

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('WindowsSIEM')

Base = declarative_base()

class Event:
    def __init__(self, source, event_type, timestamp, data, severity):
        self.source = source
        self.event_type = event_type
        self.timestamp = timestamp
        self.data = data
        self.severity = severity

    def to_dict(self):
        return {
            'source': self.source,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'severity': self.severity
        }

class Alert:
    def __init__(self, rule, event):
        self.rule = rule
        self.event = event
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            'rule_name': self.rule.name,
            'severity': self.rule.severity,
            'timestamp': self.timestamp.isoformat(),
            'event': self.event.to_dict()
        }

class Rule:
    def __init__(self, name, severity='MEDIUM'):
        self.name = name
        self.severity = severity

    def matches(self, event):
        raise NotImplementedError

class WindowsEventRule(Rule):
    def __init__(self, name, event_id=None, source=None, level=None, severity='MEDIUM'):
        super().__init__(name, severity)
        self.event_id = event_id
        self.source = source
        self.level = level

    def matches(self, event):
        if self.event_id and str(event.data.get('EventID')) != str(self.event_id):
            return False
        if self.source and event.data.get('SourceName') != self.source:
            return False
        if self.level and event.data.get('Level') != self.level:
            return False
        return True

class EventModel(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    source = Column(String)
    event_type = Column(String)
    timestamp = Column(DateTime)
    data = Column(String)
    severity = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'source': self.source,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'severity': self.severity
        }

class AlertModel(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    rule_name = Column(String)
    severity = Column(String)
    timestamp = Column(DateTime)
    event_id = Column(Integer, ForeignKey('events.id'))
    status = Column(String, default='new')

    def to_dict(self):
        return {
            'id': self.id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'event_id': self.event_id,
            'status': self.status
        }

class NetworkLogModel(Base):
    __tablename__ = 'network_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    source_ip = Column(String)
    destination_ip = Column(String)
    protocol = Column(String)
    data = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'protocol': self.protocol,
            'data': self.data
        }

class AsyncDatabase:
    def __init__(self, db_url):
        self.engine = create_async_engine(db_url)
        self.SessionLocal = sessionmaker(
            bind=self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def init(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def store_event(self, event):
        async with self.SessionLocal() as session:
            db_event = EventModel(**event.to_dict())
            session.add(db_event)
            await session.commit()
            return db_event.id

    async def store_alert(self, alert, event_id):
        async with self.SessionLocal() as session:
            db_alert = AlertModel(
                rule_name=alert.rule.name,
                severity=alert.rule.severity,
                timestamp=alert.timestamp,
                event_id=event_id
            )
            session.add(db_alert)
            await session.commit()
            return db_alert.id

    async def store_network_log(self, log):
        async with self.SessionLocal() as session:
            db_log = NetworkLogModel(**log)
            session.add(db_log)
            await session.commit()
            return db_log.id

    async def get_recent_events(self, limit=100):
        async with self.SessionLocal() as session:
            result = await session.execute(
                select(EventModel).order_by(EventModel.timestamp.desc()).limit(limit)
            )
            return [row[0].to_dict() for row in result.fetchall()]

    async def get_recent_alerts(self, limit=100):
        async with self.SessionLocal() as session:
            result = await session.execute(
                select(AlertModel).order_by(AlertModel.timestamp.desc()).limit(limit)
            )
            return [row[0].to_dict() for row in result.fetchall()]

    async def get_recent_network_logs(self, limit=100):
        async with self.SessionLocal() as session:
            result = await session.execute(
                select(NetworkLogModel).order_by(NetworkLogModel.timestamp.desc()).limit(limit)
            )
            return [row[0].to_dict() for row in result.fetchall()]

    async def update_alert_status(self, alert_id, status):
        async with self.SessionLocal() as session:
            result = await session.execute(
                select(AlertModel).filter(AlertModel.id == alert_id)
            )
            alert = result.scalar_one_or_none()
            if alert:
                alert.status = status
                await session.commit()
                return True
            return False

class AsyncWindowsEventLogSource:
    def __init__(self, log_type='Security'):
        self.log_type = log_type
        self.last_read_time = datetime.now() - timedelta(minutes=1)
        
    async def collect_logs(self):
        events = []
        try:
            # Try to get administrative privileges
            handle = None
            try:
                handle = win32evtlog.OpenEventLog(None, self.log_type)
            except win32evtlog.error as e:
                if e.winerror == 1314:  # ERROR_PRIVILEGE_NOT_HELD
                    logger.warning(f"Not enough privileges to open {self.log_type} log. Try running as administrator.")
                    return events
                raise

            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            try:
                events_data = win32evtlog.ReadEventLog(handle, flags, 0)
            except Exception as e:
                logger.error(f"Error reading event log: {e}")
                return events
            
            for event_data in events_data:
                try:
                    # Convert pywintypes.datetime to Python datetime
                    timestamp = datetime.fromtimestamp(int(event_data.TimeGenerated.timestamp()))
                    
                    if timestamp <= self.last_read_time:
                        continue
                    
                    event = Event(
                        source=self.log_type,
                        event_type=str(event_data.EventID),
                        timestamp=timestamp,
                        data={
                            'EventID': event_data.EventID,
                            'SourceName': event_data.SourceName,
                            'Level': event_data.EventType,
                            'Description': win32evtlogutil.SafeFormatMessage(event_data, self.log_type)
                        },
                        severity=self._map_event_type_to_severity(event_data.EventType)
                    )
                    events.append(event)
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
                    continue
            
            self.last_read_time = datetime.now()
        except Exception as e:
            logger.error(f"Error collecting Windows Event Logs: {e}")
        finally:
            if handle:
                win32evtlog.CloseEventLog(handle)
        
        return events

    def _map_event_type_to_severity(self, event_type):
        severity_map = {
            win32evtlog.EVENTLOG_ERROR_TYPE: 'HIGH',
            win32evtlog.EVENTLOG_WARNING_TYPE: 'MEDIUM',
            win32evtlog.EVENTLOG_INFORMATION_TYPE: 'LOW',
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'LOW',
            win32evtlog.EVENTLOG_AUDIT_FAILURE: 'HIGH'
        }
        return severity_map.get(event_type, 'MEDIUM')

class AsyncNetworkLogSource:
    def __init__(self, interface='eth0'):
        self.interface = interface
        if pyshark is None:
            logger.warning("pyshark is not available. Network capture is disabled.")
        else:
            try:
                self.capture = pyshark.LiveCapture(interface=self.interface)
            except Exception as e:
                logger.error(f"Error initializing pyshark: {e}")
                self.capture = None

    async def collect_logs(self):
        logs = []
        if pyshark is None or self.capture is None:
            return logs

        try:
            for packet in self.capture.sniff_continuously(packet_count=10):
                log = {
                    'timestamp': datetime.now(),
                    'source_ip': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                    'destination_ip': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A',
                    'data': str(packet)
                }
                logs.append(log)
                await asyncio.sleep(0)  # Allow other tasks to run
        except Exception as e:
            logger.error(f"Error collecting network logs: {e}")

        return logs

class AsyncWindowsSIEM:
    def __init__(self, db_url='sqlite+aiosqlite:///siem.db'):
        self.log_sources = []
        self.rules = []
        self.db = AsyncDatabase(db_url)
        self.running = False
        self.app = None

    async def init(self):
        await self.db.init()

    def add_log_source(self, log_source):
        self.log_sources.append(log_source)

    def add_rule(self, rule):
        self.rules.append(rule)

    async def start(self):
        self.running = True
        await asyncio.gather(
            self._collect_logs(),
            self._analyze_events()
        )

    def stop(self):
        self.running = False

    async def _collect_logs(self):
        while self.running:
            for source in self.log_sources:
                try:
                    if isinstance(source, AsyncWindowsEventLogSource):
                        events = await source.collect_logs()
                        for event in events:
                            await self._process_event(event)
                    elif isinstance(source, AsyncNetworkLogSource):
                        logs = await source.collect_logs()
                        for log in logs:
                            await self.db.store_network_log(log)
                except Exception as e:
                    logger.error(f"Error collecting logs from {source.__class__.__name__}: {e}")
            await asyncio.sleep(1)

    async def _process_event(self, event):
        event_id = await self.db.store_event(event)
        
        for rule in self.rules:
            try:
                if rule.matches(event):
                    alert = Alert(rule, event)
                    alert_id = await self.db.store_alert(alert, event_id)
                    await self._handle_alert(alert, alert_id)
            except Exception as e:
                logger.error(f"Error processing rule {rule.name}: {e}")

    async def _handle_alert(self, alert, alert_id):
        logger.warning(f"Alert generated: {alert.rule.name} - {alert.event.data}")
        if self.app:
            await notify_clients(self.app, {'type': 'alert', 'alert': alert.to_dict()})

    async def _analyze_events(self):
        while self.running:
            # Implement your event analysis logic here
            # For example, you could periodically check for patterns in the events
            await asyncio.sleep(60)  # Sleep for 60 seconds between analysis runs

# API routes
async def get_events(request):
    try:
        events = await request.app['siem'].db.get_recent_events()
        return web.json_response(events)
    except Exception as e:
        logger.error(f"Error fetching events: {e}")
        return web.json_response({'error': 'Internal Server Error'}, status=500)

async def get_alerts(request):
    try:
        alerts = await request.app['siem'].db.get_recent_alerts()
        return web.json_response(alerts)
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return web.json_response({'error': 'Internal Server Error'}, status=500)

async def get_network_logs(request):
    try:
        logs = await request.app['siem'].db.get_recent_network_logs()
        return web.json_response(logs)
    except Exception as e:
        logger.error(f"Error fetching network logs: {e}")
        return web.json_response({'error': 'Internal Server Error'}, status=500)

async def update_alert(request):
    try:
        alert_id = int(request.match_info['alert_id'])
        data = await request.json()
        status = data.get('status')
        if status:
            success = await request.app['siem'].db.update_alert_status(alert_id, status)
            return web.json_response({'success': success})
        return web.json_response({'success': False, 'error': 'Invalid status'}, status=400)
    except Exception as e:
        logger.error(f"Error updating alert: {e}")
        return web.json_response({'error': 'Internal Server Error'}, status=500)

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await  ws.prepare(request)
    request.app['websockets'].add(ws)
    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                # Handle incoming WebSocket messages if needed
                pass
            elif msg.type == aiohttp.WSMsgType.ERROR:
                logger.error(f'WebSocket connection closed with exception {ws.exception()}')
    finally:
        request.app['websockets'].remove(ws)
    return ws

async def notify_clients(app, data):
    for ws in app['websockets']:
        try:
            await ws.send_json(data)
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")

async def start_background_tasks(app):
    app['siem_task'] = asyncio.create_task(app['siem'].start())

async def cleanup_background_tasks(app):
    app['siem'].stop()
    await app['siem_task']

async def serve_dashboard(request):
    return web.FileResponse('dashboard.html')

def main():
    app = web.Application()
    app['siem'] = AsyncWindowsSIEM()
    app['websockets'] = set()
    app['siem'].app = app

    # Add Windows Event Log sources
    app['siem'].add_log_source(AsyncWindowsEventLogSource('Security'))
    app['siem'].add_log_source(AsyncWindowsEventLogSource('System'))
    app['siem'].add_log_source(AsyncWindowsEventLogSource('Application'))
    
    # Add Network Log source
    app['siem'].add_log_source(AsyncNetworkLogSource())

    # Add Windows-specific rules
    app['siem'].add_rule(WindowsEventRule('Failed Login', event_id=4625, severity='HIGH'))
    app['siem'].add_rule(WindowsEventRule('Account Lockout', event_id=4740, severity='HIGH'))
    app['siem'].add_rule(WindowsEventRule('Service Failed', event_id=7034, source='Service Control Manager', severity='MEDIUM'))
    app['siem'].add_rule(WindowsEventRule('Windows Firewall Rule Modified', event_id=2004, source='Microsoft-Windows-Windows Firewall With Advanced Security', severity='MEDIUM'))

    app.router.add_get('/', serve_dashboard)
    app.router.add_get('/api/events', get_events)
    app.router.add_get('/api/alerts', get_alerts)
    app.router.add_get('/api/network_logs', get_network_logs)
    app.router.add_put('/api/alert/{alert_id}', update_alert)
    app.router.add_get('/ws', websocket_handler)

    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)

    web.run_app(app, port=8081)

if __name__ == '__main__':
    main()