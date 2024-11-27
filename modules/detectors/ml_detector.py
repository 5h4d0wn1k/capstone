#!/usr/bin/env python3

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
import joblib
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

class MLThreatDetector:
    def __init__(self, config: Dict[str, Any]):
        """Initialize ML-based threat detector with configuration"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize models
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        
        # Initialize deep learning model for sequence analysis
        self.sequence_model = self._build_sequence_model()
        
        # Initialize scaler for feature normalization
        self.scaler = StandardScaler()
        
    def _build_sequence_model(self) -> keras.Model:
        """Build and return a deep learning model for sequence analysis"""
        model = keras.Sequential([
            keras.layers.LSTM(64, input_shape=(None, 50), return_sequences=True),
            keras.layers.Dropout(0.2),
            keras.layers.LSTM(32),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def preprocess_features(self, events: List[Dict]) -> np.ndarray:
        """Preprocess events into feature vectors"""
        features = []
        for event in events:
            feature_vector = [
                event.get('timestamp', 0),
                hash(event.get('source_ip', '')),
                hash(event.get('destination_ip', '')),
                event.get('bytes_sent', 0),
                event.get('bytes_received', 0),
                event.get('duration', 0),
                hash(event.get('protocol', '')),
                event.get('port', 0),
                event.get('packet_count', 0),
                int(event.get('is_encrypted', False))
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def train_anomaly_detector(self, normal_events: List[Dict]):
        """Train the anomaly detection model on normal events"""
        features = self.preprocess_features(normal_events)
        scaled_features = self.scaler.fit_transform(features)
        self.anomaly_detector.fit(scaled_features)
        
    def detect_anomalies(self, events: List[Dict]) -> List[bool]:
        """Detect anomalies in events"""
        features = self.preprocess_features(events)
        scaled_features = self.scaler.transform(features)
        predictions = self.anomaly_detector.predict(scaled_features)
        return [pred == -1 for pred in predictions]
    
    def train_classifier(self, events: List[Dict], labels: List[int]):
        """Train the classifier on labeled events"""
        features = self.preprocess_features(events)
        scaled_features = self.scaler.fit_transform(features)
        self.classifier.fit(scaled_features, labels)
    
    def classify_threats(self, events: List[Dict]) -> List[float]:
        """Classify events as threats (returns probability)"""
        features = self.preprocess_features(events)
        scaled_features = self.scaler.transform(features)
        return self.classifier.predict_proba(scaled_features)[:, 1]
    
    def analyze_sequence(self, event_sequence: List[Dict]) -> float:
        """Analyze a sequence of events for suspicious patterns"""
        features = self.preprocess_features(event_sequence)
        scaled_features = self.scaler.transform(features)
        
        # Reshape for LSTM input
        sequence = scaled_features.reshape(1, len(event_sequence), -1)
        return float(self.sequence_model.predict(sequence)[0])
    
    def save_models(self, path: str):
        """Save all models to disk"""
        joblib.dump(self.anomaly_detector, f"{path}/anomaly_detector.joblib")
        joblib.dump(self.classifier, f"{path}/classifier.joblib")
        joblib.dump(self.scaler, f"{path}/scaler.joblib")
        self.sequence_model.save(f"{path}/sequence_model")
        
    def load_models(self, path: str):
        """Load all models from disk"""
        self.anomaly_detector = joblib.load(f"{path}/anomaly_detector.joblib")
        self.classifier = joblib.load(f"{path}/classifier.joblib")
        self.scaler = joblib.load(f"{path}/scaler.joblib")
        self.sequence_model = keras.models.load_model(f"{path}/sequence_model")
    
    def evaluate_threat(self, event: Dict) -> Dict[str, Any]:
        """Comprehensive threat evaluation of a single event"""
        features = self.preprocess_features([event])
        scaled_features = self.scaler.transform(features)
        
        # Get predictions from all models
        is_anomaly = self.anomaly_detector.predict(scaled_features)[0] == -1
        threat_prob = float(self.classifier.predict_proba(scaled_features)[0, 1])
        sequence_score = float(self.sequence_model.predict(scaled_features.reshape(1, 1, -1))[0])
        
        return {
            'timestamp': datetime.now().isoformat(),
            'event_id': event.get('id', 'unknown'),
            'is_anomaly': is_anomaly,
            'threat_probability': threat_prob,
            'sequence_score': sequence_score,
            'overall_risk_score': (threat_prob + sequence_score) / 2,
            'source': event.get('source_ip', 'unknown'),
            'destination': event.get('destination_ip', 'unknown'),
            'alert_level': 'high' if threat_prob > 0.8 else 'medium' if threat_prob > 0.5 else 'low'
        }
