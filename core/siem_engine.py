#!/usr/bin/env python3

import asyncio
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import yaml
from loguru import logger
from elasticsearch import AsyncElasticsearch
from kafka import KafkaConsumer, KafkaProducer
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import jwt
from cryptography.fernet import Fernet

class SIEMEngine:
    """Core SIEM Engine that orchestrates all components"""
    
    def __init__(self, config_path: str):
        """Initialize the SIEM Engine"""
        self.config = self._load_config(config_path)
        self.setup_logging()
        self.initialize_components()
        self.running = False
        
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load config: {e}")

    def setup_logging(self):
        """Configure logging based on settings"""
        logger.remove()  # Remove default handler
        logger.add(
            self.config['logging']['file'],
            level=self.config['logging']['level'],
            format=self.config['logging']['format'],
            rotation=self.config['logging']['max_size'],
            retention=self.config['logging']['backup_count']
        )

    def initialize_components(self):
        """Initialize all SIEM components"""
        try:
            # Initialize databases
            self._init_databases()
            
            # Initialize message brokers
            self._init_kafka()
            
            # Initialize collectors
            self._init_collectors()
            
            # Initialize analyzers
            self._init_analyzers()
            
            # Initialize response system
            self._init_response_system()
            
            logger.info("All SIEM components initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SIEM components: {e}")
            raise

    def _init_databases(self):
        """Initialize database connections"""
        # PostgreSQL
        db_config = self.config['database']
        db_url = f"postgresql+asyncpg://{db_config['user']}:{os.getenv(db_config['password_env'])}@{db_config['host']}:{db_config['port']}/{db_config['name']}"
        self.db_engine = create_async_engine(db_url, pool_size=db_config['pool_size'], max_overflow=db_config['max_overflow'])
        self.async_session = sessionmaker(self.db_engine, class_=AsyncSession)

        # Elasticsearch
        es_config = self.config['elasticsearch']
        self.es_client = AsyncElasticsearch(es_config['hosts'])

    def _init_kafka(self):
        """Initialize Kafka producers and consumers"""
        kafka_config = self.config['kafka']
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_config['bootstrap_servers'],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        
        self.consumer = KafkaConsumer(
            kafka_config['topics']['events'],
            bootstrap_servers=kafka_config['bootstrap_servers'],
            group_id=kafka_config['consumer_group'],
            auto_offset_reset=kafka_config['auto_offset_reset'],
            enable_auto_commit=kafka_config['enable_auto_commit']
        )

    def _init_collectors(self):
        """Initialize data collectors"""
        self.collectors = {}
        collector_config = self.config['collectors']
        
        # Windows Event Collector
        if collector_config['windows_event']['enabled']:
            from collectors.windows import WindowsEventCollector
            self.collectors['windows'] = WindowsEventCollector(collector_config['windows_event'])
        
        # Syslog Collector
        if collector_config['syslog']['enabled']:
            from collectors.syslog import SyslogCollector
            self.collectors['syslog'] = SyslogCollector(collector_config['syslog'])
        
        # Network Collector
        if collector_config['network']['enabled']:
            from collectors.network import NetworkCollector
            self.collectors['network'] = NetworkCollector(collector_config['network'])
        
        # File Collector
        if collector_config['file']['enabled']:
            from collectors.file import FileCollector
            self.collectors['file'] = FileCollector(collector_config['file'])

    def _init_analyzers(self):
        """Initialize analysis engines"""
        self.analyzers = {}
        analyzer_config = self.config['analyzers']
        
        # ML-based analyzers
        if 'ml_models' in analyzer_config:
            from analyzers.ml import MLAnalyzer
            self.analyzers['ml'] = MLAnalyzer(analyzer_config['ml_models'])
        
        # YARA rules
        if analyzer_config['yara_rules']['enabled']:
            from analyzers.yara import YaraAnalyzer
            self.analyzers['yara'] = YaraAnalyzer(analyzer_config['yara_rules'])
        
        # Sigma rules
        if analyzer_config['sigma_rules']['enabled']:
            from analyzers.sigma import SigmaAnalyzer
            self.analyzers['sigma'] = SigmaAnalyzer(analyzer_config['sigma_rules'])

    def _init_response_system(self):
        """Initialize incident response system"""
        response_config = self.config['response']
        
        if response_config['automation']['enabled']:
            from response.automation import ResponseAutomation
            self.response_system = ResponseAutomation(response_config)

    async def process_event(self, event: Dict[str, Any]):
        """Process a single event through the analysis pipeline"""
        try:
            # Store raw event
            await self._store_raw_event(event)
            
            # Analyze event
            analysis_results = await self._analyze_event(event)
            
            # Generate alerts if necessary
            if analysis_results['alerts']:
                await self._handle_alerts(analysis_results['alerts'])
            
            # Trigger automated response if configured
            if analysis_results['response_needed']:
                await self._trigger_response(analysis_results)
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            # Store failed event for retry
            await self._store_failed_event(event, str(e))

    async def _store_raw_event(self, event: Dict[str, Any]):
        """Store raw event in Elasticsearch"""
        try:
            index_name = f"{self.config['elasticsearch']['index_prefix']}-events-{datetime.now():%Y.%m.%d}"
            await self.es_client.index(index=index_name, document=event)
        except Exception as e:
            logger.error(f"Failed to store raw event: {e}")
            raise

    async def _analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Run event through all configured analyzers"""
        results = {
            'alerts': [],
            'response_needed': False,
            'severity': 'info',
            'findings': []
        }
        
        # Run ML analysis
        if 'ml' in self.analyzers:
            ml_results = await self.analyzers['ml'].analyze(event)
            results['findings'].extend(ml_results)
        
        # Check YARA rules
        if 'yara' in self.analyzers:
            yara_results = await self.analyzers['yara'].analyze(event)
            results['findings'].extend(yara_results)
        
        # Check Sigma rules
        if 'sigma' in self.analyzers:
            sigma_results = await self.analyzers['sigma'].analyze(event)
            results['findings'].extend(sigma_results)
        
        # Determine if alerts are needed
        if any(finding['severity'] in ['high', 'critical'] for finding in results['findings']):
            results['alerts'] = self._generate_alerts(results['findings'])
            results['response_needed'] = True
            results['severity'] = max(finding['severity'] for finding in results['findings'])
        
        return results

    def _generate_alerts(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate alerts from analysis findings"""
        alerts = []
        for finding in findings:
            if finding['severity'] in ['high', 'critical']:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'severity': finding['severity'],
                    'title': finding['title'],
                    'description': finding['description'],
                    'source': finding['source'],
                    'indicators': finding.get('indicators', []),
                    'recommendations': finding.get('recommendations', [])
                }
                alerts.append(alert)
        return alerts

    async def _handle_alerts(self, alerts: List[Dict[str, Any]]):
        """Handle generated alerts"""
        alert_config = self.config['alerts']
        
        for alert in alerts:
            # Store alert in database
            await self._store_alert(alert)
            
            # Send notifications
            if alert_config['channels']['email']['enabled']:
                await self._send_email_alert(alert)
            
            if alert_config['channels']['slack']['enabled']:
                await self._send_slack_alert(alert)
            
            if alert_config['channels']['webhook']['enabled']:
                await self._send_webhook_alert(alert)

    async def _trigger_response(self, analysis_results: Dict[str, Any]):
        """Trigger automated response actions"""
        if self.config['response']['automation']['enabled']:
            await self.response_system.execute_response(analysis_results)

    async def start(self):
        """Start the SIEM engine"""
        try:
            logger.info("Starting SIEM engine...")
            self.running = True
            
            # Start collectors
            for collector in self.collectors.values():
                await collector.start()
            
            # Start main event processing loop
            await self._event_processing_loop()
            
        except Exception as e:
            logger.error(f"Error starting SIEM engine: {e}")
            raise

    async def _event_processing_loop(self):
        """Main event processing loop"""
        while self.running:
            try:
                # Get events from Kafka
                for message in self.consumer:
                    event = message.value
                    await self.process_event(event)
                    
                    # Commit offset if auto-commit is disabled
                    if not self.config['kafka']['enable_auto_commit']:
                        self.consumer.commit()
                    
            except Exception as e:
                logger.error(f"Error in event processing loop: {e}")
                await asyncio.sleep(1)  # Prevent tight loop on error

    async def stop(self):
        """Stop the SIEM engine"""
        try:
            logger.info("Stopping SIEM engine...")
            self.running = False
            
            # Stop collectors
            for collector in self.collectors.values():
                await collector.stop()
            
            # Close connections
            await self.es_client.close()
            self.producer.close()
            self.consumer.close()
            await self.db_engine.dispose()
            
            logger.info("SIEM engine stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping SIEM engine: {e}")
            raise

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all components"""
        health = {
            'status': 'healthy',
            'components': {}
        }
        
        try:
            # Check database connectivity
            async with self.async_session() as session:
                await session.execute(sa.text('SELECT 1'))
            health['components']['database'] = 'healthy'
        except Exception as e:
            health['components']['database'] = f'unhealthy: {str(e)}'
            health['status'] = 'degraded'
        
        try:
            # Check Elasticsearch
            if await self.es_client.ping():
                health['components']['elasticsearch'] = 'healthy'
            else:
                health['components']['elasticsearch'] = 'unhealthy: failed to ping'
                health['status'] = 'degraded'
        except Exception as e:
            health['components']['elasticsearch'] = f'unhealthy: {str(e)}'
            health['status'] = 'degraded'
        
        # Check collectors
        for name, collector in self.collectors.items():
            try:
                if await collector.health_check():
                    health['components'][f'collector_{name}'] = 'healthy'
                else:
                    health['components'][f'collector_{name}'] = 'unhealthy'
                    health['status'] = 'degraded'
            except Exception as e:
                health['components'][f'collector_{name}'] = f'unhealthy: {str(e)}'
                health['status'] = 'degraded'
        
        return health

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM Engine')
    parser.add_argument('--config', type=str, default='config/siem_config.yaml',
                      help='Path to configuration file')
    args = parser.parse_args()
    
    async def main():
        engine = SIEMEngine(args.config)
        await engine.start()
        
        try:
            # Keep running until interrupted
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await engine.stop()
    
    asyncio.run(main())
