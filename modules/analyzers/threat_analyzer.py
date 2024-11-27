"""Threat analysis implementation for SIEM platform."""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from loguru import logger

class ThreatAnalyzer:
    """Threat analysis and correlation engine."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize threat analyzer.
        
        Args:
            config: Analyzer configuration
        """
        self.config = config.get('threat_analyzer', {})
        self.enabled = self.config.get('enabled', True)
        self.threat_score_threshold = self.config.get('threat_score_threshold', 70)
        self.correlation_window = self.config.get('correlation_window', 3600)  # 1 hour
        self.load_threat_patterns()
        
    def load_threat_patterns(self) -> None:
        """Load threat detection patterns."""
        try:
            patterns_file = os.path.join(
                os.path.dirname(__file__),
                'data',
                'threat_patterns.json'
            )
            
            if not os.path.exists(patterns_file):
                logger.warning("Threat patterns file not found, creating default patterns")
                self._create_default_patterns(patterns_file)
                
            with open(patterns_file, 'r') as f:
                self.patterns = json.load(f)
                
            logger.info(f"Loaded {len(self.patterns)} threat patterns")
            
        except Exception as e:
            logger.error(f"Error loading threat patterns: {e}")
            self.patterns = []
            
    def _create_default_patterns(self, file_path: str) -> None:
        """Create default threat patterns.
        
        Args:
            file_path: Path to patterns file
        """
        default_patterns = [
            {
                "id": "BRUTE_FORCE",
                "name": "Brute Force Attack",
                "description": "Multiple failed login attempts",
                "conditions": {
                    "event_type": "FAILED_LOGIN_ATTEMPT",
                    "threshold": 5,
                    "timeframe": 300  # 5 minutes
                },
                "severity": "high",
                "score": 80
            },
            {
                "id": "PRIVILEGE_ESCALATION",
                "name": "Privilege Escalation",
                "description": "Suspicious privilege elevation activities",
                "conditions": {
                    "event_types": [
                        "SPECIAL_PRIVILEGES_LOGON",
                        "AUDIT_POLICY_CHANGE"
                    ],
                    "timeframe": 600  # 10 minutes
                },
                "severity": "critical",
                "score": 90
            },
            {
                "id": "SYSTEM_ABUSE",
                "name": "System Resource Abuse",
                "description": "Sustained high resource usage",
                "conditions": {
                    "event_types": [
                        "HIGH_CPU_USAGE",
                        "HIGH_MEMORY_USAGE"
                    ],
                    "threshold": 3,
                    "timeframe": 900  # 15 minutes
                },
                "severity": "medium",
                "score": 60
            }
        ]
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(default_patterns, f, indent=2)
        except Exception as e:
            logger.error(f"Error creating default patterns: {e}")
            
    def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze events for threats.
        
        Args:
            events: List of events to analyze
            
        Returns:
            List of detected threats
        """
        if not self.enabled or not events:
            return []
            
        threats = []
        try:
            # Group events by type
            event_groups = {}
            for event in events:
                event_type = event['type']
                if event_type not in event_groups:
                    event_groups[event_type] = []
                event_groups[event_type].append(event)
                
            # Check each pattern
            for pattern in self.patterns:
                try:
                    matches = self._match_pattern(pattern, event_groups)
                    if matches:
                        threat = {
                            'timestamp': datetime.now().isoformat(),
                            'pattern_id': pattern['id'],
                            'name': pattern['name'],
                            'description': pattern['description'],
                            'severity': pattern['severity'],
                            'score': pattern['score'],
                            'matched_events': matches
                        }
                        threats.append(threat)
                except Exception as e:
                    logger.error(f"Error matching pattern {pattern['id']}: {e}")
                    
        except Exception as e:
            logger.error(f"Error analyzing events: {e}")
            
        return threats
        
    def _match_pattern(self, pattern: Dict[str, Any], event_groups: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Match events against threat pattern.
        
        Args:
            pattern: Threat pattern
            event_groups: Grouped events
            
        Returns:
            List of matching events
        """
        try:
            conditions = pattern['conditions']
            matches = []
            
            # Single event type pattern
            if 'event_type' in conditions:
                event_type = conditions['event_type']
                if event_type in event_groups:
                    events = event_groups[event_type]
                    if len(events) >= conditions.get('threshold', 1):
                        # Check timeframe
                        timeframe = conditions.get('timeframe', self.correlation_window)
                        recent_events = self._filter_recent_events(events, timeframe)
                        if len(recent_events) >= conditions.get('threshold', 1):
                            matches.extend(recent_events)
                            
            # Multiple event types pattern
            elif 'event_types' in conditions:
                event_types = conditions['event_types']
                timeframe = conditions.get('timeframe', self.correlation_window)
                
                # Collect events of all specified types
                pattern_events = []
                for event_type in event_types:
                    if event_type in event_groups:
                        pattern_events.extend(event_groups[event_type])
                        
                # Check combined conditions
                if pattern_events:
                    recent_events = self._filter_recent_events(pattern_events, timeframe)
                    if len(recent_events) >= conditions.get('threshold', 1):
                        matches.extend(recent_events)
                        
            return matches
            
        except Exception as e:
            logger.error(f"Error matching pattern: {e}")
            return []
            
    def _filter_recent_events(self, events: List[Dict[str, Any]], timeframe: int) -> List[Dict[str, Any]]:
        """Filter events within timeframe.
        
        Args:
            events: List of events
            timeframe: Timeframe in seconds
            
        Returns:
            List of recent events
        """
        try:
            now = datetime.now()
            recent = []
            
            for event in events:
                try:
                    event_time = datetime.fromisoformat(event['timestamp'])
                    if (now - event_time).total_seconds() <= timeframe:
                        recent.append(event)
                except:
                    continue
                    
            return recent
            
        except Exception as e:
            logger.error(f"Error filtering events: {e}")
            return []
            
    def get_threat_score(self, threats: List[Dict[str, Any]]) -> int:
        """Calculate overall threat score.
        
        Args:
            threats: List of detected threats
            
        Returns:
            Threat score (0-100)
        """
        try:
            if not threats:
                return 0
                
            # Calculate weighted average of threat scores
            total_score = sum(threat['score'] for threat in threats)
            return min(100, total_score // len(threats))
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return 0
            
    def get_recommendations(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Get mitigation recommendations.
        
        Args:
            threats: List of detected threats
            
        Returns:
            List of recommendations
        """
        recommendations = []
        try:
            for threat in threats:
                pattern_id = threat['pattern_id']
                
                if pattern_id == 'BRUTE_FORCE':
                    recommendations.extend([
                        "Enable account lockout policies",
                        "Implement multi-factor authentication",
                        "Review and update password complexity requirements"
                    ])
                elif pattern_id == 'PRIVILEGE_ESCALATION':
                    recommendations.extend([
                        "Audit user privileges and remove unnecessary elevated access",
                        "Enable detailed security auditing for privilege changes",
                        "Implement just-in-time access for administrative tasks"
                    ])
                elif pattern_id == 'SYSTEM_ABUSE':
                    recommendations.extend([
                        "Review and optimize system resource allocation",
                        "Implement resource usage quotas",
                        "Monitor and terminate suspicious processes"
                    ])
                    
        except Exception as e:
            logger.error(f"Error getting recommendations: {e}")
            
        return list(set(recommendations))  # Remove duplicates
