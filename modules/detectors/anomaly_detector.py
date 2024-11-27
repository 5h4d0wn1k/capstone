#!/usr/bin/env python3

from datetime import datetime
from typing import Dict, List, Any
from loguru import logger

class AnomalyDetector:
    def __init__(self):
        """Initialize the anomaly detector with default settings"""
        self.baseline = {}
        self.whitelist = []
        self.thresholds = {
            'cpu_usage': 90.0,
            'memory_usage': 85.0,
            'network_traffic': 1000000
        }
        
    def detect(self, data: Dict[str, float]) -> List[Dict[str, Any]]:
        """Detect anomalies in the provided system data"""
        anomalies = []
        
        # Compare with thresholds
        if data.get('cpu_usage', 0) > self.thresholds['cpu_usage']:
            anomalies.append({
                'type': 'high_cpu_usage',
                'value': data['cpu_usage'],
                'threshold': self.thresholds['cpu_usage'],
                'timestamp': datetime.now().isoformat()
            })
            
        if data.get('memory_usage', 0) > self.thresholds['memory_usage']:
            anomalies.append({
                'type': 'high_memory_usage',
                'value': data['memory_usage'],
                'threshold': self.thresholds['memory_usage'],
                'timestamp': datetime.now().isoformat()
            })
            
        if data.get('network_traffic', 0) > self.thresholds['network_traffic']:
            anomalies.append({
                'type': 'high_network_traffic',
                'value': data['network_traffic'],
                'threshold': self.thresholds['network_traffic'],
                'timestamp': datetime.now().isoformat()
            })
            
        return anomalies
        
    def get_baseline(self) -> Dict[str, float]:
        """Get the baseline metrics for comparison"""
        return self.baseline
        
    def update_baseline(self, data: Dict[str, float]):
        """Update the baseline metrics"""
        self.baseline = data
        
    def compare_to_baseline(self, data: Dict[str, float]) -> List[Dict[str, Any]]:
        """Compare current data with baseline and return deviations"""
        deviations = []
        baseline = self.get_baseline()
        
        for metric, value in data.items():
            if metric in baseline:
                deviation = abs(value - baseline[metric])
                if deviation > (baseline[metric] * 0.2):  # 20% deviation threshold
                    deviations.append({
                        'metric': metric,
                        'current_value': value,
                        'baseline_value': baseline[metric],
                        'deviation': deviation,
                        'timestamp': datetime.now().isoformat()
                    })
                    
        return deviations
        
    def add_whitelist(self, entry: Dict[str, Any]):
        """Add an entry to the whitelist"""
        self.whitelist.append(entry)
        
    def check_whitelist(self, entry: Dict[str, Any]) -> bool:
        """Check if an entry is in the whitelist"""
        return entry in self.whitelist
