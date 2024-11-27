#!/usr/bin/env python3

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from loguru import logger
import json
import os

class BehavioralAnalyzer:
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the behavioral analyzer"""
        self.behavior_patterns = defaultdict(list)
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.cluster_detector = DBSCAN(eps=0.3, min_samples=2)
        self.known_patterns = set()
        self.threat_scores = defaultdict(float)
        self.initialize_components(config_path)

    def initialize_components(self, config_path: Optional[str] = None):
        """Initialize analyzer components"""
        try:
            self._load_config(config_path)
            self._initialize_ml_models()
            self._load_known_patterns()
        except Exception as e:
            logger.error(f"Failed to initialize behavioral analyzer: {e}")
            raise

    def _load_config(self, config_path: Optional[str] = None):
        """Load configuration from file"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.known_patterns.update(config.get('known_patterns', []))

    def _initialize_ml_models(self):
        """Initialize and train ML models"""
        history_file = 'behavior_history.json'
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                historical_data = json.load(f)
                if historical_data:
                    X = np.array(historical_data)
                    self.anomaly_detector.fit(X)
                    self.cluster_detector.fit(X)

    def _load_known_patterns(self):
        """Load known behavior patterns"""
        patterns_file = 'known_patterns.json'
        if os.path.exists(patterns_file):
            with open(patterns_file, 'r') as f:
                patterns = json.load(f)
                self.known_patterns.update(patterns)

    async def analyze_behavior(self, system_data: Dict[str, Any], network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system and network behavior together"""
        try:
            # Extract features from both data sources
            features = self._extract_combined_features(system_data, network_data)
            
            # Perform various analyses
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'anomalies': [],
                'patterns': [],
                'threat_score': 0.0,
                'recommendations': []
            }

            # 1. Check for known malicious patterns
            pattern_matches = self._check_known_patterns(system_data, network_data)
            if pattern_matches:
                analysis['patterns'].extend(pattern_matches)
                analysis['threat_score'] += len(pattern_matches) * 0.5

            # 2. ML-based anomaly detection
            if self._is_anomaly(features):
                analysis['anomalies'].append({
                    'type': 'behavioral',
                    'severity': 'high',
                    'details': 'Unusual behavior pattern detected'
                })
                analysis['threat_score'] += 1.0

            # 3. Cluster analysis for behavior grouping
            cluster_findings = self._analyze_clusters(features)
            if cluster_findings:
                analysis['patterns'].extend(cluster_findings)

            # 4. Time-series analysis
            temporal_findings = await self._analyze_temporal_patterns(system_data, network_data)
            if temporal_findings:
                analysis['patterns'].extend(temporal_findings)

            # 5. Generate recommendations
            analysis['recommendations'] = self._generate_recommendations(analysis)

            # Update behavior history
            self._update_history(features, analysis)

            return analysis

        except Exception as e:
            logger.error(f"Error in behavior analysis: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }

    def _extract_combined_features(self, system_data: Dict[str, Any], network_data: Dict[str, Any]) -> np.ndarray:
        """Extract features from both system and network data"""
        features = []

        # System features
        if system_data:
            features.extend([
                float(system_data.get('cpu_percent', 0)),
                float(system_data.get('memory_percent', 0)),
                float(system_data.get('process_count', 0)),
                float(system_data.get('thread_count', 0))
            ])

        # Network features
        if network_data:
            features.extend([
                float(network_data.get('bytes_sent', 0)),
                float(network_data.get('bytes_received', 0)),
                float(network_data.get('packets_count', 0)),
                float(network_data.get('error_rate', 0))
            ])

        return np.array(features)

    def _check_known_patterns(self, system_data: Dict[str, Any], network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for known malicious behavior patterns"""
        matches = []

        # Define pattern matching rules
        patterns = {
            'data_exfiltration': {
                'condition': lambda s, n: (
                    n.get('bytes_sent', 0) > 1000000 and  # Large outbound traffic
                    n.get('destination_ports', []).intersection({21, 22, 443, 8080})  # Common exfil ports
                ),
                'severity': 'critical'
            },
            'crypto_mining': {
                'condition': lambda s, n: (
                    s.get('cpu_percent', 0) > 90 and  # High CPU usage
                    n.get('destination_ports', []).intersection({3333, 8332, 8333})  # Common mining ports
                ),
                'severity': 'high'
            },
            'lateral_movement': {
                'condition': lambda s, n: (
                    n.get('internal_connections', 0) > 10 and  # Multiple internal connections
                    n.get('destination_ports', []).intersection({445, 135, 139})  # Common lateral movement ports
                ),
                'severity': 'critical'
            }
        }

        # Check each pattern
        for pattern_name, pattern_def in patterns.items():
            if pattern_def['condition'](system_data, network_data):
                matches.append({
                    'pattern': pattern_name,
                    'severity': pattern_def['severity'],
                    'timestamp': datetime.now().isoformat()
                })

        return matches

    def _is_anomaly(self, features: np.ndarray) -> bool:
        """Detect anomalies using the ML model"""
        try:
            features_reshaped = features.reshape(1, -1)
            return self.anomaly_detector.predict(features_reshaped)[0] == -1
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return False

    def _analyze_clusters(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Analyze behavior clusters"""
        findings = []
        try:
            features_reshaped = features.reshape(1, -1)
            cluster = self.cluster_detector.fit_predict(features_reshaped)
            
            # Analyze cluster characteristics
            if cluster[0] == -1:  # Noise point in DBSCAN
                findings.append({
                    'type': 'cluster_analysis',
                    'details': 'Behavior does not match any known cluster',
                    'severity': 'medium'
                })
            
        except Exception as e:
            logger.error(f"Cluster analysis failed: {e}")
        
        return findings

    async def _analyze_temporal_patterns(self, system_data: Dict[str, Any], network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze patterns over time"""
        findings = []

        try:
            # Get recent history
            recent_system = self.behavior_patterns['system'][-100:]
            recent_network = self.behavior_patterns['network'][-100:]

            # Check for sudden changes
            if recent_system and recent_network:
                # System metrics changes
                cpu_change = system_data.get('cpu_percent', 0) - recent_system[-1].get('cpu_percent', 0)
                mem_change = system_data.get('memory_percent', 0) - recent_system[-1].get('memory_percent', 0)

                # Network metrics changes
                traffic_change = (
                    network_data.get('bytes_total', 0) - 
                    recent_network[-1].get('bytes_total', 0)
                )

                # Detect sudden spikes
                if abs(cpu_change) > 50:  # CPU usage changed by 50%
                    findings.append({
                        'type': 'temporal_analysis',
                        'details': f'Sudden CPU usage change: {cpu_change:+.1f}%',
                        'severity': 'medium'
                    })

                if abs(mem_change) > 30:  # Memory usage changed by 30%
                    findings.append({
                        'type': 'temporal_analysis',
                        'details': f'Sudden memory usage change: {mem_change:+.1f}%',
                        'severity': 'medium'
                    })

                if traffic_change > 1000000:  # Traffic increased by 1MB
                    findings.append({
                        'type': 'temporal_analysis',
                        'details': 'Sudden increase in network traffic',
                        'severity': 'high'
                    })

        except Exception as e:
            logger.error(f"Temporal analysis failed: {e}")

        return findings

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        # Add recommendations based on threat score
        if analysis['threat_score'] > 2.0:
            recommendations.append("Immediately investigate system for potential compromise")
        elif analysis['threat_score'] > 1.0:
            recommendations.append("Increase monitoring and review security logs")

        # Add pattern-specific recommendations
        for pattern in analysis['patterns']:
            if pattern['pattern'] == 'data_exfiltration':
                recommendations.extend([
                    "Review and restrict outbound network connections",
                    "Implement DLP solutions",
                    "Audit file access patterns"
                ])
            elif pattern['pattern'] == 'crypto_mining':
                recommendations.extend([
                    "Review and terminate suspicious processes",
                    "Implement process whitelisting",
                    "Monitor CPU usage patterns"
                ])
            elif pattern['pattern'] == 'lateral_movement':
                recommendations.extend([
                    "Segment network to prevent lateral movement",
                    "Implement strict access controls",
                    "Enable enhanced auditing on critical systems"
                ])

        # Add recommendations based on anomalies
        if analysis['anomalies']:
            recommendations.extend([
                "Review system and network logs for unusual activities",
                "Temporarily restrict network access for affected systems",
                "Conduct thorough security audit"
            ])

        return list(set(recommendations))  # Remove duplicates

    def _update_history(self, features: np.ndarray, analysis: Dict[str, Any]):
        """Update behavior history"""
        timestamp = datetime.now().isoformat()
        
        # Store features
        self.behavior_patterns['features'].append({
            'timestamp': timestamp,
            'features': features.tolist(),
            'threat_score': analysis['threat_score']
        })

        # Maintain history size
        max_history = 1000
        if len(self.behavior_patterns['features']) > max_history:
            self.behavior_patterns['features'] = self.behavior_patterns['features'][-max_history:]

    def save_state(self):
        """Save analyzer state to disk"""
        try:
            with open('behavior_history.json', 'w') as f:
                json.dump(self.behavior_patterns, f)
        except Exception as e:
            logger.error(f"Failed to save behavioral analyzer state: {e}")

    def load_state(self):
        """Load analyzer state from disk"""
        try:
            if os.path.exists('behavior_history.json'):
                with open('behavior_history.json', 'r') as f:
                    self.behavior_patterns = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load behavioral analyzer state: {e}")

    async def start(self):
        """Start the behavioral analyzer"""
        try:
            self.load_state()
            logger.info("Behavioral analyzer started successfully")
        except Exception as e:
            logger.error(f"Failed to start behavioral analyzer: {e}")
            raise

    async def stop(self):
        """Stop the behavioral analyzer"""
        try:
            self.save_state()
            logger.info("Behavioral analyzer stopped successfully")
        except Exception as e:
            logger.error(f"Failed to stop behavioral analyzer: {e}")
            raise
