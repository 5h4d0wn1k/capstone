"""Factory for creating and managing threat detectors."""

from typing import Dict, List, Any, Type
import importlib
import inspect
import os
from loguru import logger

from .base import BaseDetector
from .sigma import SigmaDetector
from .anomaly import AnomalyDetector
from .correlation import CorrelationEngine

class DetectorFactory:
    """Factory for creating and managing threat detectors."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize detector factory.
        
        Args:
            config: Factory configuration
        """
        self.config = config
        self.detectors: Dict[str, BaseDetector] = {}
        self.detector_classes: Dict[str, Type[BaseDetector]] = {}
        self.discover_detectors()
        self.initialize_detectors()
        
    def discover_detectors(self) -> None:
        """Discover available detector classes."""
        # Get all detector classes in this package
        detector_classes = [
            SigmaDetector,
            AnomalyDetector,
            CorrelationEngine
        ]
        
        # Register each detector class
        for cls in detector_classes:
            try:
                # Create instance to get name
                temp_instance = cls({"enabled": False})
                name = temp_instance.name
                self.detector_classes[name] = cls
                logger.info(f"Discovered detector: {name}")
            except Exception as e:
                logger.error(f"Error discovering detector {cls.__name__}: {e}")
                
    def initialize_detectors(self) -> None:
        """Initialize configured detectors."""
        # Get detector configurations
        detector_configs = self.config.get("detectors", {})
        
        # Initialize each configured detector
        for name, config in detector_configs.items():
            if name in self.detector_classes:
                try:
                    detector_class = self.detector_classes[name]
                    detector = detector_class(config)
                    self.detectors[name] = detector
                    logger.info(f"Initialized detector: {name}")
                except Exception as e:
                    logger.error(f"Error initializing detector {name}: {e}")
            else:
                logger.warning(f"Unknown detector type: {name}")
                
    async def analyze_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze event with all enabled detectors.
        
        Args:
            event: Event to analyze
            
        Returns:
            List of alerts from detectors
        """
        alerts = []
        
        for detector in self.detectors.values():
            if detector.enabled:
                try:
                    alert = await detector.analyze(event)
                    if alert:
                        alerts.append(alert)
                except Exception as e:
                    logger.error(f"Error in detector {detector.name}: {e}")
                    
        return alerts
        
    def get_detector(self, name: str) -> BaseDetector:
        """Get detector by name.
        
        Args:
            name: Detector name
            
        Returns:
            Detector instance
        
        Raises:
            KeyError: If detector not found
        """
        if name not in self.detectors:
            raise KeyError(f"Detector not found: {name}")
        return self.detectors[name]
        
    def get_detector_status(self) -> List[Dict[str, Any]]:
        """Get status of all detectors.
        
        Returns:
            List of detector status dictionaries
        """
        status = []
        
        for name, detector in self.detectors.items():
            status.append({
                "name": name,
                "description": detector.description,
                "enabled": detector.enabled,
                "config": self.config.get("detectors", {}).get(name, {})
            })
            
        return status
