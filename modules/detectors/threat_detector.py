#!/usr/bin/env python3

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from loguru import logger
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict
import re
import yara
import json
import os

class ThreatDetector:
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the enhanced threat detector with ML capabilities"""
        self.patterns = []
        self.event_history = defaultdict(list)
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.yara_rules = {}
        self.initialize_components(config_path)
        
    def initialize_components(self, config_path: Optional[str] = None):
        """Initialize all detection components"""
        self.initialize_default_patterns()
        self.load_yara_rules()
        self.initialize_ml_model()
        
    def initialize_default_patterns(self):
        """Initialize comprehensive threat patterns"""
        default_patterns = [
            {
                'pattern': 'bruteforce',
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': 'high',
                'indicators': ['failed_login', 'invalid_credentials']
            },
            {
                'pattern': 'port_scan',
                'threshold': 100,
                'timeframe': 60,  # 1 minute
                'severity': 'medium',
                'port_range': (1, 1024)
            },
            {
                'pattern': 'suspicious_smb',
                'threshold': 1,
                'timeframe': 60,
                'severity': 'high',
                'signatures': ['encrypted_files', 'mass_delete']
            },
            {
                'pattern': 'data_exfiltration',
                'threshold': 3,
                'timeframe': 300,
                'severity': 'critical',
                'size_threshold': 10000000  # 10MB
            },
            {
                'pattern': 'privilege_escalation',
                'threshold': 1,
                'timeframe': 60,
                'severity': 'critical',
                'indicators': ['sudo_abuse', 'token_manipulation']
            }
        ]
        self.patterns = default_patterns
        
    def load_yara_rules(self):
        """Load YARA rules for malware detection"""
        rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
        if os.path.exists(rules_dir):
            for rule_file in os.listdir(rules_dir):
                if rule_file.endswith('.yar'):
                    try:
                        rule_path = os.path.join(rules_dir, rule_file)
                        self.yara_rules[rule_file] = yara.compile(rule_path)
                    except Exception as e:
                        logger.error(f"Failed to load YARA rule {rule_file}: {e}")

    def initialize_ml_model(self):
        """Initialize and train the anomaly detection model"""
        # Load historical data if available
        history_file = 'event_history.json'
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                historical_data = json.load(f)
                if historical_data:
                    X = np.array(historical_data)
                    self.anomaly_detector.fit(X)

    def detect(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhanced threat detection with multiple detection methods"""
        threats = []
        
        # 1. Pattern-based detection
        pattern_threats = self._detect_patterns(event)
        threats.extend(pattern_threats)
        
        # 2. Anomaly detection using ML
        if self._is_anomaly(event):
            threats.append({
                'type': 'anomaly',
                'source': event.get('source_ip'),
                'destination': event.get('destination_ip'),
                'severity': 'high',
                'timestamp': datetime.now().isoformat(),
                'details': 'Unusual behavior detected by ML model'
            })
        
        # 3. YARA rule matching for malware detection
        if 'file_content' in event:
            yara_matches = self._check_yara_rules(event['file_content'])
            threats.extend(yara_matches)
        
        # 4. Behavioral analysis
        behavior_threats = self._analyze_behavior(event)
        threats.extend(behavior_threats)
        
        # Update event history for future analysis
        self._update_history(event)
        
        return threats

    def _detect_patterns(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect known attack patterns"""
        threats = []
        
        # Check each pattern against the event
        for pattern in self.patterns:
            if self._matches_pattern(event, pattern):
                threats.append({
                    'type': pattern['pattern'],
                    'source': event.get('source_ip'),
                    'destination': event.get('destination_ip'),
                    'severity': pattern['severity'],
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Matched pattern: {pattern['pattern']}"
                })
        
        return threats

    def _is_anomaly(self, event: Dict[str, Any]) -> bool:
        """Use ML to detect anomalies"""
        try:
            # Extract numerical features from event
            features = self._extract_features(event)
            if features is None:
                return False
            
            # Reshape for sklearn
            X = np.array(features).reshape(1, -1)
            
            # Predict returns -1 for anomalies and 1 for normal data
            return self.anomaly_detector.predict(X)[0] == -1
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return False

    def _check_yara_rules(self, content: bytes) -> List[Dict[str, Any]]:
        """Check content against YARA rules"""
        threats = []
        
        for rule_name, rule in self.yara_rules.items():
            matches = rule.match(data=content)
            if matches:
                threats.append({
                    'type': 'malware',
                    'rule': rule_name,
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Matched YARA rule: {rule_name}"
                })
        
        return threats

    def _analyze_behavior(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze system and user behavior"""
        threats = []
        
        # Check for suspicious process behavior
        if 'process' in event:
            process_threats = self._analyze_process_behavior(event['process'])
            threats.extend(process_threats)
        
        # Check for suspicious network behavior
        if 'network' in event:
            network_threats = self._analyze_network_behavior(event['network'])
            threats.extend(network_threats)
        
        # Check for suspicious file system activity
        if 'filesystem' in event:
            filesystem_threats = self._analyze_filesystem_behavior(event['filesystem'])
            threats.extend(filesystem_threats)
        
        return threats

    def _update_history(self, event: Dict[str, Any]):
        """Update event history for temporal analysis"""
        # Extract relevant features
        features = self._extract_features(event)
        if features:
            source = event.get('source_ip', 'unknown')
            self.event_history[source].append({
                'timestamp': datetime.now().isoformat(),
                'features': features
            })
            
            # Maintain history size
            if len(self.event_history[source]) > 1000:
                self.event_history[source] = self.event_history[source][-1000:]

    def _extract_features(self, event: Dict[str, Any]) -> Optional[List[float]]:
        """Extract numerical features from event for ML analysis"""
        try:
            features = []
            
            # Add basic numeric features
            features.append(float(event.get('bytes_transferred', 0)))
            features.append(float(event.get('duration', 0)))
            features.append(float(event.get('port', 0)))
            
            # Add derived features
            if 'start_time' in event and 'end_time' in event:
                duration = (event['end_time'] - event['start_time']).total_seconds()
                features.append(duration)
            
            return features
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def _matches_pattern(self, event: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """Check if event matches a given pattern"""
        # Implement pattern matching logic here
        # This is a placeholder for demonstration
        return True

    def _analyze_process_behavior(self, process: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze process behavior"""
        # Implement process behavior analysis logic here
        # This is a placeholder for demonstration
        return []

    def _analyze_network_behavior(self, network: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze network behavior"""
        # Implement network behavior analysis logic here
        # This is a placeholder for demonstration
        return []

    def _analyze_filesystem_behavior(self, filesystem: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze file system behavior"""
        # Implement file system behavior analysis logic here
        # This is a placeholder for demonstration
        return []
