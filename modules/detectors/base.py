"""Base class for threat detectors."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

from loguru import logger

class BaseDetector(ABC):
    """Base class for all threat detectors."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize detector.
        
        Args:
            config: Detector configuration
        """
        self.config = config
        self.name = "base_detector"
        self.description = "Base threat detector"
        self.enabled = config.get("enabled", True)
        self.severity_levels = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        
    @abstractmethod
    async def analyze(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze an event for threats.
        
        Args:
            event: Event to analyze
            
        Returns:
            Alert dictionary if threat detected, None otherwise
        """
        pass
        
    def create_alert(self, event: Dict[str, Any], threat_type: str, 
                    severity: str, description: str) -> Dict[str, Any]:
        """Create an alert from a detected threat.
        
        Args:
            event: Original event that triggered the alert
            threat_type: Type of threat detected
            severity: Severity level (low, medium, high, critical)
            description: Detailed description of the threat
            
        Returns:
            Alert dictionary
        """
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "detector": self.name,
            "threat_type": threat_type,
            "severity": severity,
            "severity_level": self.severity_levels.get(severity.lower(), 0),
            "description": description,
            "event_id": event.get("id"),
            "event_source": event.get("source"),
            "event_type": event.get("event_type"),
            "raw_event": json.dumps(event)
        }
        
    def check_severity(self, indicators: List[str]) -> str:
        """Determine severity based on threat indicators.
        
        Args:
            indicators: List of threat indicators
            
        Returns:
            Severity level string
        """
        # Map indicators to severity levels
        severity_map = self.config.get("severity_map", {})
        max_severity = "low"
        
        for indicator in indicators:
            if indicator in severity_map:
                indicator_severity = severity_map[indicator]
                if (self.severity_levels.get(indicator_severity.lower(), 0) > 
                    self.severity_levels.get(max_severity.lower(), 0)):
                    max_severity = indicator_severity
                    
        return max_severity
        
    def log_detection(self, alert: Dict[str, Any]) -> None:
        """Log a threat detection.
        
        Args:
            alert: Alert dictionary
        """
        logger.warning(
            f"Threat detected by {self.name}: "
            f"[{alert['severity'].upper()}] {alert['description']}"
        )
