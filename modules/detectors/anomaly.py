"""Machine learning-based anomaly detector."""

from typing import Dict, List, Optional, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime, timedelta
from collections import defaultdict
import json
from loguru import logger

from .base import BaseDetector

class AnomalyDetector(BaseDetector):
    """Machine learning-based anomaly detector."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize anomaly detector.
        
        Args:
            config: Detector configuration
        """
        super().__init__(config)
        self.name = "anomaly_detector"
        self.description = "Machine learning anomaly detector"
        
        # Configuration
        self.training_window = config.get("training_window_hours", 24)
        self.min_training_events = config.get("min_training_events", 1000)
        self.contamination = config.get("contamination", 0.1)
        self.retrain_interval = config.get("retrain_interval_hours", 6)
        
        # Model files
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        models_dir = os.path.join(base_dir, "models")
        os.makedirs(models_dir, exist_ok=True)
        self.model_path = os.path.join(models_dir, "anomaly_model.joblib")
        self.scaler_path = os.path.join(models_dir, "anomaly_scaler.joblib")
        
        # State
        self.model = None
        self.scaler = None
        self.last_training = None
        self.training_events: List[Dict[str, Any]] = []
        self.feature_names = [
            "event_count",
            "unique_users",
            "unique_sources",
            "error_ratio",
            "warning_ratio",
            "after_hours_ratio"
        ]
        
        # Load or initialize models
        self.load_models()
        
    def load_models(self) -> None:
        """Load trained models from disk."""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                logger.info("Loaded existing anomaly detection models")
            else:
                logger.info("No existing models found, will train on new data")
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            
    def save_models(self) -> None:
        """Save trained models to disk."""
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            logger.info("Saved anomaly detection models")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
            
    def extract_features(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features from a list of events.
        
        Args:
            events: List of events to extract features from
            
        Returns:
            Feature matrix
        """
        # Count metrics
        event_count = len(events)
        users = set()
        sources = set()
        error_count = 0
        warning_count = 0
        after_hours_count = 0
        
        # Process events
        for event in events:
            # Users
            user = event.get("user")
            if user:
                users.add(user)
                
            # Sources
            source = event.get("source")
            if source:
                sources.add(source)
                
            # Event types
            event_type = event.get("event_type", "").lower()
            if "error" in event_type:
                error_count += 1
            elif "warning" in event_type:
                warning_count += 1
                
            # Time of day
            try:
                timestamp = datetime.fromisoformat(event.get("timestamp", ""))
                hour = timestamp.hour
                if hour < 6 or hour > 18:  # After business hours
                    after_hours_count += 1
            except:
                pass
                
        # Calculate ratios
        error_ratio = error_count / event_count if event_count > 0 else 0
        warning_ratio = warning_count / event_count if event_count > 0 else 0
        after_hours_ratio = after_hours_count / event_count if event_count > 0 else 0
        
        # Create feature vector
        features = [
            event_count,
            len(users),
            len(sources),
            error_ratio,
            warning_ratio,
            after_hours_ratio
        ]
        
        return np.array(features).reshape(1, -1)
        
    def train(self, events: List[Dict[str, Any]]) -> None:
        """Train anomaly detection model.
        
        Args:
            events: List of events to train on
        """
        if len(events) < self.min_training_events:
            logger.warning(
                f"Not enough events for training: {len(events)} < {self.min_training_events}"
            )
            return
            
        try:
            # Extract features
            X = np.vstack([self.extract_features(chunk) 
                          for chunk in self.chunk_events(events)])
            
            # Scale features
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Train model
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42
            )
            self.model.fit(X_scaled)
            
            # Save models
            self.save_models()
            self.last_training = datetime.utcnow()
            
            logger.info(f"Trained anomaly detection model on {len(events)} events")
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            
    def chunk_events(self, events: List[Dict[str, Any]], 
                    window_minutes: int = 5) -> List[List[Dict[str, Any]]]:
        """Split events into time windows.
        
        Args:
            events: List of events to chunk
            window_minutes: Size of time window in minutes
            
        Returns:
            List of event chunks
        """
        chunks: Dict[datetime, List[Dict[str, Any]]] = defaultdict(list)
        
        for event in events:
            try:
                timestamp = datetime.fromisoformat(event.get("timestamp", ""))
                window_start = timestamp.replace(
                    minute=timestamp.minute - (timestamp.minute % window_minutes),
                    second=0,
                    microsecond=0
                )
                chunks[window_start].append(event)
            except:
                continue
                
        return list(chunks.values())
        
    async def analyze(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze an event for anomalies.
        
        Args:
            event: Event to analyze
            
        Returns:
            Alert dictionary if anomaly detected, None otherwise
        """
        if not self.enabled:
            return None
            
        # Store event for training
        self.training_events.append(event)
        
        # Check if we need to train/retrain
        now = datetime.utcnow()
        need_training = (
            self.model is None or
            self.last_training is None or
            (now - self.last_training) > timedelta(hours=self.retrain_interval)
        )
        
        if need_training:
            # Get training window
            cutoff = now - timedelta(hours=self.training_window)
            training_data = [
                e for e in self.training_events
                if datetime.fromisoformat(e.get("timestamp", "")) > cutoff
            ]
            
            # Train if we have enough data
            if len(training_data) >= self.min_training_events:
                self.train(training_data)
                
            # Cleanup old events
            self.training_events = training_data
            
        # Skip detection if model isn't ready
        if self.model is None or self.scaler is None:
            return None
            
        try:
            # Get recent events including current
            recent_events = self.training_events[-100:]  # Last 100 events
            
            # Extract and scale features
            X = self.extract_features(recent_events)
            X_scaled = self.scaler.transform(X)
            
            # Predict
            score = self.model.score_samples(X_scaled)[0]
            is_anomaly = score < self.model.threshold_
            
            if is_anomaly:
                description = (
                    f"Anomalous behavior detected (score: {score:.3f}). "
                    f"Unusual pattern in recent events."
                )
                
                alert = self.create_alert(
                    event=event,
                    threat_type="anomaly",
                    severity="high",
                    description=description
                )
                
                self.log_detection(alert)
                return alert
                
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            
        return None
