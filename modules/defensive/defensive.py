import os
import sys
from loguru import logger
import asyncio
from typing import Dict, List, Optional, Union
import platform
import subprocess
import psutil
import hashlib
from datetime import datetime
import re
import yaml
import json
import aiohttp
import aiosqlite
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Optional imports
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    logger.warning("Yara module not available. Some features will be disabled.")
    YARA_AVAILABLE = False

try:
    from elasticsearch import AsyncElasticsearch
    ES_AVAILABLE = True
except ImportError:
    logger.warning("Elasticsearch not available. Some features will be disabled.")
    ES_AVAILABLE = False

try:
    from prometheus_client import start_http_server, Counter, Gauge, Histogram
    PROMETHEUS_AVAILABLE = True
except ImportError:
    logger.warning("Prometheus client not available. Metrics collection will be disabled.")
    PROMETHEUS_AVAILABLE = False

try:
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    logger.warning("Machine learning modules not available. Some features will be disabled.")
    ML_AVAILABLE = False

class DefensiveTools:
    def __init__(self, config: Dict, db_session: AsyncSession):
        """Initialize defensive security tools"""
        self.config = config
        self.db_session = db_session
        self.running = False
        self.tasks = []
        
    async def initialize(self):
        """Initialize all defensive components asynchronously"""
        try:
            await self.initialize_threat_detection()
            await self.initialize_ml_models()
            await self.initialize_metrics()
            await self.initialize_storage()
            self.running = True
            logger.info("Defensive tools initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize defensive tools: {e}")
            raise
            
    async def initialize_threat_detection(self):
        """Initialize threat detection components"""
        if YARA_AVAILABLE:
            rules_dir = self.config.get('defensive', {}).get('rules_dir', './rules')
            self.yara_rules = await self.load_yara_rules(rules_dir)
            
        # Initialize threat intelligence feeds
        self.threat_feeds = []
        feeds_config = self.config.get('defensive', {}).get('threat_feeds', [])
        for feed in feeds_config:
            try:
                await self.add_threat_feed(feed)
            except Exception as e:
                logger.error(f"Failed to load threat feed {feed['name']}: {e}")
                
    async def load_yara_rules(self, rules_dir: str) -> Optional[yara.Rules]:
        """Load YARA rules asynchronously"""
        if not os.path.exists(rules_dir):
            logger.warning(f"Rules directory {rules_dir} does not exist")
            return None
            
        try:
            rules = []
            for filename in os.listdir(rules_dir):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    with open(os.path.join(rules_dir, filename), 'r') as f:
                        rules.append(f.read())
            return yara.compile(sources=dict(enumerate(rules)))
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return None
            
    async def add_threat_feed(self, feed_config: Dict):
        """Add a threat intelligence feed"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(feed_config['url']) as response:
                    if response.status == 200:
                        data = await response.text()
                        self.threat_feeds.append({
                            'name': feed_config['name'],
                            'data': data,
                            'type': feed_config['type']
                        })
                        logger.info(f"Loaded threat feed: {feed_config['name']}")
        except Exception as e:
            logger.error(f"Failed to load threat feed {feed_config['name']}: {e}")
            
    async def initialize_ml_models(self):
        """Initialize machine learning models"""
        if not ML_AVAILABLE:
            return
            
        try:
            self.anomaly_detector = IsolationForest(
                contamination=float(self.config.get('defensive', {})
                .get('ml', {}).get('anomaly_threshold', 0.1))
            )
            logger.info("ML models initialized")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            
    async def initialize_metrics(self):
        """Initialize metrics collection"""
        if not PROMETHEUS_AVAILABLE:
            return
            
        try:
            self.metrics = {
                'events': Counter('siem_events_total', 'Total number of security events'),
                'alerts': Counter('siem_alerts_total', 'Total number of security alerts'),
                'threats': Counter('siem_threats_total', 'Total number of detected threats'),
                'response_time': Histogram('siem_response_time_seconds', 
                                        'Response time for threat detection')
            }
            metrics_port = self.config.get('defensive', {}).get('metrics_port', 9090)
            start_http_server(metrics_port)
            logger.info(f"Metrics server started on port {metrics_port}")
        except Exception as e:
            logger.error(f"Failed to initialize metrics: {e}")
            
    async def initialize_storage(self):
        """Initialize storage backends"""
        if ES_AVAILABLE:
            es_config = self.config.get('defensive', {}).get('elasticsearch', {})
            if es_config.get('enabled', False):
                try:
                    self.es = AsyncElasticsearch([es_config.get('url', 'http://localhost:9200')])
                    await self.es.info()
                    logger.info("Connected to Elasticsearch")
                except Exception as e:
                    logger.error(f"Failed to connect to Elasticsearch: {e}")
                    
    async def start(self):
        """Start defensive monitoring"""
        if not self.running:
            await self.initialize()
            
        try:
            self.tasks = [
                asyncio.create_task(self.monitor_system()),
                asyncio.create_task(self.process_events()),
                asyncio.create_task(self.analyze_threats())
            ]
            logger.info("Defensive monitoring started")
        except Exception as e:
            logger.error(f"Failed to start defensive monitoring: {e}")
            raise
            
    async def stop(self):
        """Stop defensive monitoring"""
        self.running = False
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        logger.info("Defensive monitoring stopped")
            
    async def monitor_system(self):
        """Monitor system for security events"""
        while self.running:
            try:
                # System monitoring logic
                system_info = {
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage': psutil.disk_usage('/').percent,
                    'network_connections': len(psutil.net_connections())
                }
                
                # Check for anomalies
                if await self.detect_anomaly(system_info):
                    await self.create_alert('system_anomaly', 'high', system_info)
                    
                await asyncio.sleep(self.config.get('defensive', {})
                                  .get('monitor_interval', 60))
            except Exception as e:
                logger.error(f"Error in system monitoring: {e}")
                await asyncio.sleep(5)
                
    async def process_events(self):
        """Process security events"""
        while self.running:
            try:
                # Query for new events
                async with self.db_session() as session:
                    stmt = select(EventModel).order_by(EventModel.timestamp.desc()).limit(100)
                    result = await session.execute(stmt)
                    events = result.scalars().all()
                    
                    for event in events:
                        await self.analyze_event(event)
                        
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error processing events: {e}")
                await asyncio.sleep(5)
                
    async def analyze_threats(self):
        """Analyze potential threats"""
        while self.running:
            try:
                # Analyze system logs
                if YARA_AVAILABLE and self.yara_rules:
                    await self.scan_files()
                    
                # Check threat feeds
                await self.check_threat_feeds()
                
                await asyncio.sleep(self.config.get('defensive', {})
                                  .get('threat_scan_interval', 300))
            except Exception as e:
                logger.error(f"Error in threat analysis: {e}")
                await asyncio.sleep(5)
                
    async def detect_anomaly(self, data: Dict) -> bool:
        """Detect anomalies in system data"""
        if not ML_AVAILABLE:
            return False
            
        try:
            # Convert data to feature vector
            features = pd.DataFrame([list(data.values())], columns=list(data.keys()))
            prediction = self.anomaly_detector.predict(features)
            return prediction[0] == -1
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return False
            
    async def create_alert(self, alert_type: str, severity: str, data: Dict):
        """Create a security alert"""
        try:
            async with self.db_session() as session:
                alert = AlertModel(
                    rule_name=alert_type,
                    severity=severity,
                    timestamp=datetime.utcnow(),
                    data=json.dumps(data)
                )
                session.add(alert)
                await session.commit()
                
            if PROMETHEUS_AVAILABLE:
                self.metrics['alerts'].inc()
                
            logger.warning(f"Security alert: {alert_type} - {severity}")
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            
    async def scan_files(self):
        """Scan files using YARA rules"""
        scan_paths = self.config.get('defensive', {}).get('scan_paths', ['/'])
        
        for path in scan_paths:
            try:
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            matches = self.yara_rules.match(file_path)
                            if matches:
                                await self.create_alert(
                                    'yara_match',
                                    'high',
                                    {'file': file_path, 'rules': [str(m) for m in matches]}
                                )
                        except Exception as e:
                            logger.debug(f"Error scanning file {file_path}: {e}")
            except Exception as e:
                logger.error(f"Error scanning path {path}: {e}")
                
    async def check_threat_feeds(self):
        """Check threat intelligence feeds"""
        for feed in self.threat_feeds:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(feed['url']) as response:
                        if response.status == 200:
                            data = await response.text()
                            # Compare with previous data
                            if data != feed['data']:
                                feed['data'] = data
                                await self.analyze_feed_update(feed)
            except Exception as e:
                logger.error(f"Error checking threat feed {feed['name']}: {e}")
                
    async def analyze_feed_update(self, feed: Dict):
        """Analyze updates from threat feeds"""
        try:
            # Process feed data based on type
            if feed['type'] == 'ip':
                await self.analyze_ip_feed(feed)
            elif feed['type'] == 'domain':
                await self.analyze_domain_feed(feed)
            elif feed['type'] == 'hash':
                await self.analyze_hash_feed(feed)
        except Exception as e:
            logger.error(f"Error analyzing feed {feed['name']}: {e}")
            
    async def analyze_event(self, event: 'EventModel'):
        """Analyze a security event"""
        try:
            if PROMETHEUS_AVAILABLE:
                self.metrics['events'].inc()
                
            # Apply detection rules
            severity = await self.apply_detection_rules(event)
            if severity:
                await self.create_alert(
                    'event_rule_match',
                    severity,
                    {'event_id': event.id, 'event_type': event.event_type}
                )
        except Exception as e:
            logger.error(f"Error analyzing event {event.id}: {e}")
            
    async def apply_detection_rules(self, event: 'EventModel') -> Optional[str]:
        """Apply detection rules to an event"""
        try:
            rules = self.config.get('defensive', {}).get('detection_rules', [])
            for rule in rules:
                if re.search(rule['pattern'], event.data):
                    return rule['severity']
            return None
        except Exception as e:
            logger.error(f"Error applying detection rules: {e}")
            return None
