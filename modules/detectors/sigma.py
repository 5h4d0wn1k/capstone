"""Sigma rule-based threat detector."""

import os
from typing import Dict, List, Optional, Any
import yaml
from loguru import logger

from .base import BaseDetector

class SigmaDetector(BaseDetector):
    """Detector that uses Sigma rules for threat detection."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Sigma detector.
        
        Args:
            config: Detector configuration
        """
        super().__init__(config)
        self.name = "sigma_detector"
        self.description = "Sigma rule-based threat detector"
        self.rules_dir = config.get("rules_dir", "rules/sigma")
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()
        
    def load_rules(self) -> None:
        """Load Sigma rules from rules directory."""
        try:
            # Get absolute path to rules directory
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            rules_path = os.path.join(base_dir, self.rules_dir)
            
            # Load each .yml file in the rules directory
            for root, _, files in os.walk(rules_path):
                for file in files:
                    if file.endswith('.yml'):
                        rule_path = os.path.join(root, file)
                        try:
                            with open(rule_path, 'r') as f:
                                rule = yaml.safe_load(f)
                                if self.validate_rule(rule):
                                    self.rules.append(rule)
                        except Exception as e:
                            logger.error(f"Error loading rule {rule_path}: {e}")
                            
            logger.info(f"Loaded {len(self.rules)} Sigma rules")
        except Exception as e:
            logger.error(f"Error loading Sigma rules: {e}")
            
    def validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate a Sigma rule.
        
        Args:
            rule: Rule dictionary to validate
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['title', 'description', 'logsource', 'detection']
        
        # Check required fields
        for field in required_fields:
            if field not in rule:
                logger.warning(f"Rule missing required field: {field}")
                return False
                
        # Validate detection section
        detection = rule.get('detection', {})
        if not isinstance(detection, dict):
            logger.warning("Detection section must be a dictionary")
            return False
            
        # Must have at least one detection condition
        if 'condition' not in detection:
            logger.warning("Rule missing detection condition")
            return False
            
        return True
        
    def match_condition(self, event: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if an event matches a detection condition.
        
        Args:
            event: Event to check
            condition: Detection condition dictionary
            
        Returns:
            True if matches, False otherwise
        """
        # Get event data as dictionary
        event_data = event.get('data', {})
        if isinstance(event_data, str):
            try:
                event_data = yaml.safe_load(event_data)
            except:
                event_data = {}
                
        # Check each field in the condition
        for field, pattern in condition.items():
            value = event_data.get(field)
            
            if isinstance(pattern, str):
                # String pattern matching
                if not value or pattern.lower() not in str(value).lower():
                    return False
            elif isinstance(pattern, list):
                # List of patterns - any match is sufficient
                if not value or not any(p.lower() in str(value).lower() for p in pattern):
                    return False
            elif isinstance(pattern, dict):
                # Dictionary of sub-conditions
                if not self.match_condition({"data": value}, pattern):
                    return False
                    
        return True
        
    async def analyze(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze an event using Sigma rules.
        
        Args:
            event: Event to analyze
            
        Returns:
            Alert dictionary if threat detected, None otherwise
        """
        if not self.enabled:
            return None
            
        for rule in self.rules:
            try:
                detection = rule.get('detection', {})
                condition = detection.get('condition', {})
                
                # Check if event matches the rule
                if self.match_condition(event, condition):
                    # Create alert
                    description = (
                        f"Sigma rule '{rule['title']}' matched: {rule['description']}"
                    )
                    severity = rule.get('level', 'medium')
                    
                    alert = self.create_alert(
                        event=event,
                        threat_type="sigma_rule_match",
                        severity=severity,
                        description=description
                    )
                    
                    self.log_detection(alert)
                    return alert
                    
            except Exception as e:
                logger.error(f"Error applying rule {rule.get('title', 'unknown')}: {e}")
                
        return None
