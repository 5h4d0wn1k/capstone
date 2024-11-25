"""Event correlation engine for detecting attack patterns."""

from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
import json
from collections import defaultdict
from loguru import logger

from .base import BaseDetector

class CorrelationEngine(BaseDetector):
    """Correlates events to detect attack patterns."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize correlation engine.
        
        Args:
            config: Engine configuration
        """
        super().__init__(config)
        self.name = "correlation_engine"
        self.description = "Event correlation engine"
        
        # Configuration
        self.time_window = config.get("correlation_window_minutes", 30)
        self.min_events = config.get("min_correlated_events", 3)
        self.max_events = config.get("max_correlated_events", 1000)
        
        # State
        self.event_buffer: List[Dict[str, Any]] = []
        self.correlation_patterns = self.load_patterns()
        
    def load_patterns(self) -> List[Dict[str, Any]]:
        """Load correlation patterns.
        
        Returns:
            List of pattern dictionaries
        """
        # These patterns could be loaded from a config file
        return [
            {
                "name": "Brute Force Attack",
                "description": "Multiple failed login attempts",
                "event_types": ["login_failed"],
                "min_occurrences": 5,
                "group_by": ["source_ip", "target_user"],
                "severity": "high"
            },
            {
                "name": "Privilege Escalation",
                "description": "Successful privilege elevation after failed attempts",
                "sequence": [
                    {"event_type": "login_success"},
                    {"event_type": "privilege_change"},
                    {"event_type": "admin_action"}
                ],
                "group_by": ["user"],
                "severity": "critical"
            },
            {
                "name": "Data Exfiltration",
                "description": "Large volume of outbound data transfers",
                "event_types": ["file_access", "network_connection"],
                "min_occurrences": 10,
                "filters": {
                    "direction": "outbound",
                    "size_threshold": 1000000  # 1MB
                },
                "group_by": ["source_ip", "user"],
                "severity": "high"
            }
        ]
        
    def cleanup_old_events(self) -> None:
        """Remove events outside the correlation window."""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=self.time_window)
        
        self.event_buffer = [
            event for event in self.event_buffer
            if datetime.fromisoformat(event.get("timestamp", "")) > cutoff
        ]
        
    def group_events(self, events: List[Dict[str, Any]], 
                    group_by: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Group events by specified fields.
        
        Args:
            events: Events to group
            group_by: Fields to group by
            
        Returns:
            Dictionary of grouped events
        """
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        for event in events:
            # Create group key from specified fields
            key_parts = []
            for field in group_by:
                value = event.get(field, "unknown")
                key_parts.append(f"{field}:{value}")
            key = "|".join(key_parts)
            
            groups[key].append(event)
            
        return groups
        
    def check_sequence(self, events: List[Dict[str, Any]], 
                      sequence: List[Dict[str, Any]]) -> bool:
        """Check if events match a required sequence.
        
        Args:
            events: Events to check
            sequence: Required sequence of event types
            
        Returns:
            True if sequence matches, False otherwise
        """
        if len(events) < len(sequence):
            return False
            
        # Sort events by timestamp
        sorted_events = sorted(
            events,
            key=lambda e: datetime.fromisoformat(e.get("timestamp", ""))
        )
        
        # Try to find sequence
        seq_idx = 0
        for event in sorted_events:
            required = sequence[seq_idx]
            matches = True
            
            # Check all required fields
            for field, value in required.items():
                if event.get(field) != value:
                    matches = False
                    break
                    
            if matches:
                seq_idx += 1
                if seq_idx == len(sequence):
                    return True
                    
        return False
        
    def check_filters(self, event: Dict[str, Any], 
                     filters: Dict[str, Any]) -> bool:
        """Check if event matches filters.
        
        Args:
            event: Event to check
            filters: Required field values
            
        Returns:
            True if matches, False otherwise
        """
        for field, required in filters.items():
            value = event.get(field)
            
            # Handle numeric comparisons
            if isinstance(required, (int, float)):
                try:
                    if float(value) < required:
                        return False
                except:
                    return False
            # String comparison
            elif value != required:
                return False
                
        return True
        
    async def analyze(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze event for correlations.
        
        Args:
            event: Event to analyze
            
        Returns:
            Alert dictionary if correlation detected, None otherwise
        """
        if not self.enabled:
            return None
            
        # Add event to buffer
        self.event_buffer.append(event)
        
        # Cleanup old events
        self.cleanup_old_events()
        
        # Check each pattern
        for pattern in self.correlation_patterns:
            try:
                # Group events if specified
                group_by = pattern.get("group_by", [])
                if group_by:
                    grouped_events = self.group_events(self.event_buffer, group_by)
                else:
                    # Use all events as single group
                    grouped_events = {"all": self.event_buffer}
                    
                # Check each group
                for group_key, group_events in grouped_events.items():
                    correlation_detected = False
                    
                    # Check for sequence pattern
                    if "sequence" in pattern:
                        correlation_detected = self.check_sequence(
                            group_events, 
                            pattern["sequence"]
                        )
                    # Check for frequency pattern
                    elif "event_types" in pattern:
                        matching_events = []
                        
                        # Filter events by type and custom filters
                        for e in group_events:
                            event_type = e.get("event_type")
                            if (event_type in pattern["event_types"] and
                                self.check_filters(e, pattern.get("filters", {}))):
                                matching_events.append(e)
                                
                        # Check if we have enough matching events
                        correlation_detected = (
                            len(matching_events) >= pattern.get("min_occurrences", 1)
                        )
                        
                    if correlation_detected:
                        description = (
                            f"Correlation pattern '{pattern['name']}' detected: "
                            f"{pattern['description']} (group: {group_key})"
                        )
                        
                        alert = self.create_alert(
                            event=event,
                            threat_type="correlation",
                            severity=pattern.get("severity", "medium"),
                            description=description
                        )
                        
                        self.log_detection(alert)
                        return alert
                        
            except Exception as e:
                logger.error(f"Error checking correlation pattern: {e}")
                
        return None
