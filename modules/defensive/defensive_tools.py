#!/usr/bin/env python3

import os
import sys
import time
import json
import yaml
import logging
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from datetime import datetime
import subprocess
from pathlib import Path
import re
import hashlib
import yara
import sigma
from elasticsearch import AsyncElasticsearch
from kafka import KafkaConsumer, KafkaProducer
import numpy as np
from sklearn.ensemble import IsolationForest
from ..detectors.ml_detector import MLThreatDetector

class DefensiveTools:
    def __init__(self, config: Dict[str, Any]):
        """Initialize defensive security tools"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.es = AsyncElasticsearch([config.get('elasticsearch_url', 'http://localhost:9200')])
        self.ml_detector = MLThreatDetector(config)
        self.initialize_kafka()
        self.load_rules()
        
    def initialize_kafka(self):
        """Initialize Kafka producer and consumer"""
        kafka_config = self.config.get('kafka', {})
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_config.get('bootstrap_servers', 'localhost:9092'),
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        
        self.consumer = KafkaConsumer(
            'siem_events',
            bootstrap_servers=kafka_config.get('bootstrap_servers', 'localhost:9092'),
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
    
    def load_rules(self):
        """Load YARA and Sigma rules"""
        rules_dir = Path(self.config.get('rules_dir', 'rules'))
        
        # Load YARA rules
        yara_rules = []
        for yara_file in rules_dir.glob('*.yar'):
            try:
                rule = yara.compile(str(yara_file))
                yara_rules.append(rule)
            except Exception as e:
                self.logger.error(f"Failed to load YARA rule {yara_file}: {str(e)}")
        
        self.yara_rules = yara_rules
        
        # Load Sigma rules
        self.sigma_rules = []
        for sigma_file in rules_dir.glob('*.yml'):
            try:
                with open(sigma_file) as f:
                    rule = yaml.safe_load(f)
                    self.sigma_rules.append(rule)
            except Exception as e:
                self.logger.error(f"Failed to load Sigma rule {sigma_file}: {str(e)}")
    
    async def monitor_events(self):
        """Monitor and analyze security events"""
        try:
            async for event in self.consume_events():
                # Analyze event
                analysis_results = await self.analyze_event(event)
                
                # Handle threats
                if analysis_results.get('is_threat', False):
                    await self.handle_threat(event, analysis_results)
                
                # Store event and analysis
                await self.store_event(event, analysis_results)
                
        except Exception as e:
            self.logger.error(f"Event monitoring failed: {str(e)}")
            raise
    
    async def consume_events(self):
        """Consume events from Kafka"""
        for message in self.consumer:
            yield message.value
    
    async def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security event using multiple detection methods"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'event_id': event.get('id'),
            'detections': []
        }
        
        # Rule-based detection
        yara_matches = self.check_yara_rules(event)
        sigma_matches = self.check_sigma_rules(event)
        
        # ML-based detection
        ml_analysis = self.ml_detector.evaluate_threat(event)
        
        # Combine results
        results['detections'].extend(yara_matches)
        results['detections'].extend(sigma_matches)
        results['ml_analysis'] = ml_analysis
        
        # Determine if event is a threat
        results['is_threat'] = (
            len(yara_matches) > 0 or 
            len(sigma_matches) > 0 or 
            ml_analysis.get('threat_probability', 0) > 0.7
        )
        
        return results
    
    def check_yara_rules(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check event against YARA rules"""
        matches = []
        
        # Convert event to string for YARA matching
        event_str = json.dumps(event).encode('utf-8')
        
        for rule in self.yara_rules:
            try:
                rule_matches = rule.match(data=event_str)
                if rule_matches:
                    matches.append({
                        'type': 'YARA',
                        'rule': rule_matches[0].rule,
                        'tags': rule_matches[0].tags,
                        'severity': 'High'
                    })
            except Exception as e:
                self.logger.error(f"YARA rule check failed: {str(e)}")
        
        return matches
    
    def check_sigma_rules(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check event against Sigma rules"""
        matches = []
        
        for rule in self.sigma_rules:
            try:
                # Simple rule matching (implement full Sigma logic in production)
                conditions = rule.get('detection', {}).get('condition', {})
                if self.match_sigma_condition(event, conditions):
                    matches.append({
                        'type': 'Sigma',
                        'rule': rule.get('title'),
                        'description': rule.get('description'),
                        'severity': rule.get('level', 'Medium')
                    })
            except Exception as e:
                self.logger.error(f"Sigma rule check failed: {str(e)}")
        
        return matches
    
    def match_sigma_condition(self, event: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Match event against Sigma rule condition"""
        # Implement your Sigma rule matching logic here
        # This is a simplified version
        return False
    
    async def handle_threat(self, event: Dict[str, Any], analysis: Dict[str, Any]):
        """Handle detected threats"""
        try:
            # Generate alert
            alert = self.generate_alert(event, analysis)
            
            # Store alert
            await self.store_alert(alert)
            
            # Trigger response actions
            await self.trigger_response(alert)
            
            # Notify
            await self.send_notifications(alert)
            
        except Exception as e:
            self.logger.error(f"Threat handling failed: {str(e)}")
    
    def generate_alert(self, event: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security alert"""
        return {
            'timestamp': datetime.now().isoformat(),
            'alert_id': hashlib.sha256(str(time.time()).encode()).hexdigest()[:12],
            'event': event,
            'analysis': analysis,
            'severity': self.calculate_severity(analysis),
            'recommendations': self.generate_recommendations(analysis)
        }
    
    def calculate_severity(self, analysis: Dict[str, Any]) -> str:
        """Calculate alert severity"""
        if analysis.get('ml_analysis', {}).get('threat_probability', 0) > 0.9:
            return 'Critical'
        elif len(analysis.get('detections', [])) > 1:
            return 'High'
        elif analysis.get('ml_analysis', {}).get('threat_probability', 0) > 0.7:
            return 'Medium'
        return 'Low'
    
    def generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate response recommendations"""
        recommendations = []
        
        # Add recommendations based on detection type
        for detection in analysis.get('detections', []):
            if detection['type'] == 'SQL Injection':
                recommendations.extend([
                    'Review and update input validation',
                    'Implement prepared statements',
                    'Update WAF rules'
                ])
            elif detection['type'] == 'XSS':
                recommendations.extend([
                    'Implement content security policy',
                    'Update XSS filters',
                    'Sanitize user input'
                ])
        
        return list(set(recommendations))
    
    async def store_alert(self, alert: Dict[str, Any]):
        """Store alert in Elasticsearch"""
        try:
            await self.es.index(
                index=f"siem-alerts-{datetime.now():%Y.%m}",
                document=alert
            )
        except Exception as e:
            self.logger.error(f"Failed to store alert: {str(e)}")
    
    async def trigger_response(self, alert: Dict[str, Any]):
        """Trigger automated response actions"""
        severity = alert.get('severity')
        
        if severity in ['Critical', 'High']:
            # Implement automated response actions
            await self.block_ip(alert.get('event', {}).get('source_ip'))
            await self.quarantine_host(alert.get('event', {}).get('host'))
    
    async def block_ip(self, ip: Optional[str]):
        """Block malicious IP address"""
        if not ip:
            return
        
        try:
            # Implement IP blocking logic (e.g., update firewall rules)
            self.logger.info(f"Blocking IP: {ip}")
            
            # Send to Kafka for distributed blocking
            self.producer.send('blocked_ips', {'ip': ip, 'timestamp': datetime.now().isoformat()})
            
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip}: {str(e)}")
    
    async def quarantine_host(self, host: Optional[str]):
        """Quarantine compromised host"""
        if not host:
            return
        
        try:
            # Implement host quarantine logic
            self.logger.info(f"Quarantining host: {host}")
            
            # Send to Kafka for distributed quarantine
            self.producer.send('quarantined_hosts', {
                'host': host,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine host {host}: {str(e)}")
    
    async def send_notifications(self, alert: Dict[str, Any]):
        """Send alert notifications"""
        try:
            # Send to Kafka for notification processing
            self.producer.send('siem_notifications', alert)
            
            # Log alert
            self.logger.warning(f"Security Alert: {alert['alert_id']} - Severity: {alert['severity']}")
            
        except Exception as e:
            self.logger.error(f"Failed to send notifications: {str(e)}")
    
    async def store_event(self, event: Dict[str, Any], analysis: Dict[str, Any]):
        """Store event and analysis results"""
        try:
            document = {
                'event': event,
                'analysis': analysis,
                'timestamp': datetime.now().isoformat()
            }
            
            await self.es.index(
                index=f"siem-events-{datetime.now():%Y.%m}",
                document=document
            )
            
        except Exception as e:
            self.logger.error(f"Failed to store event: {str(e)}")
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            await self.es.close()
            self.producer.close()
            self.consumer.close()
        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")
