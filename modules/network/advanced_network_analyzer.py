#!/usr/bin/env python3

import pyshark
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress
import numpy as np
from sklearn.ensemble import IsolationForest
from loguru import logger
import json
import os

class AdvancedNetworkAnalyzer:
    def __init__(self, interface: str = 'eth0', config_path: Optional[str] = None):
        """Initialize the advanced network analyzer"""
        self.interface = interface
        self.capture = None
        self.traffic_history = defaultdict(list)
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.known_protocols = set()
        self.suspicious_ports = {22, 23, 3389, 445, 135, 137, 138, 139}  # Common attack vectors
        self.initialize_components(config_path)

    def initialize_components(self, config_path: Optional[str] = None):
        """Initialize analyzer components"""
        try:
            self.capture = pyshark.LiveCapture(interface=self.interface)
            self._load_config(config_path)
            self._initialize_ml_model()
        except Exception as e:
            logger.error(f"Failed to initialize network analyzer: {e}")
            raise

    def _load_config(self, config_path: Optional[str] = None):
        """Load configuration from file"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.suspicious_ports.update(config.get('suspicious_ports', []))
                self.known_protocols.update(config.get('known_protocols', []))

    def _initialize_ml_model(self):
        """Initialize and train the anomaly detection model"""
        history_file = 'network_history.json'
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                historical_data = json.load(f)
                if historical_data:
                    X = np.array(historical_data)
                    self.anomaly_detector.fit(X)

    async def start_capture(self):
        """Start capturing and analyzing network traffic"""
        try:
            for packet in self.capture.sniff_continuously():
                await self.analyze_packet(packet)
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            raise

    async def analyze_packet(self, packet) -> Dict[str, Any]:
        """Analyze a single packet for suspicious behavior"""
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            
            # Perform various analyses
            threat_level = 0
            findings = []

            # 1. Check for suspicious ports
            if self._check_suspicious_ports(packet_info):
                threat_level += 1
                findings.append("Suspicious port detected")

            # 2. Check for unusual protocols
            if self._check_unusual_protocol(packet_info):
                threat_level += 1
                findings.append("Unusual protocol detected")

            # 3. Check for potential port scanning
            if await self._check_port_scanning(packet_info):
                threat_level += 2
                findings.append("Potential port scanning detected")

            # 4. Check for unusual packet sizes
            if self._check_unusual_packet_size(packet_info):
                threat_level += 1
                findings.append("Unusual packet size detected")

            # 5. ML-based anomaly detection
            if self._is_anomaly(packet_info):
                threat_level += 2
                findings.append("ML model detected anomaly")

            # Update traffic history
            self._update_traffic_history(packet_info)

            return {
                'timestamp': datetime.now().isoformat(),
                'source_ip': packet_info.get('source_ip'),
                'destination_ip': packet_info.get('destination_ip'),
                'protocol': packet_info.get('protocol'),
                'threat_level': threat_level,
                'findings': findings,
                'raw_data': packet_info
            }

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
            return None

    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """Extract relevant information from packet"""
        try:
            info = {
                'timestamp': datetime.now(),
                'size': packet.length if hasattr(packet, 'length') else 0,
                'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN'
            }

            # Extract IP information if available
            if hasattr(packet, 'ip'):
                info.update({
                    'source_ip': packet.ip.src,
                    'destination_ip': packet.ip.dst,
                    'ttl': int(packet.ip.ttl)
                })

            # Extract port information if available
            if hasattr(packet, 'tcp'):
                info.update({
                    'source_port': int(packet.tcp.srcport),
                    'destination_port': int(packet.tcp.dstport),
                    'tcp_flags': packet.tcp.flags
                })
            elif hasattr(packet, 'udp'):
                info.update({
                    'source_port': int(packet.udp.srcport),
                    'destination_port': int(packet.udp.dstport)
                })

            return info
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return {}

    def _check_suspicious_ports(self, packet_info: Dict[str, Any]) -> bool:
        """Check if packet uses suspicious ports"""
        src_port = packet_info.get('source_port')
        dst_port = packet_info.get('destination_port')
        return any(port in self.suspicious_ports for port in [src_port, dst_port] if port)

    def _check_unusual_protocol(self, packet_info: Dict[str, Any]) -> bool:
        """Check if packet uses an unusual protocol"""
        protocol = packet_info.get('protocol', 'UNKNOWN')
        return protocol not in self.known_protocols

    async def _check_port_scanning(self, packet_info: Dict[str, Any]) -> bool:
        """Check for potential port scanning behavior"""
        source_ip = packet_info.get('source_ip')
        if not source_ip:
            return False

        # Get recent history for this IP
        recent_packets = [p for p in self.traffic_history[source_ip]
                         if datetime.now() - p['timestamp'] < timedelta(minutes=1)]
        
        # Check for multiple different ports in a short time
        unique_ports = {p.get('destination_port') for p in recent_packets if p.get('destination_port')}
        return len(unique_ports) > 10  # Threshold for port scanning detection

    def _check_unusual_packet_size(self, packet_info: Dict[str, Any]) -> bool:
        """Check if packet size is unusual"""
        size = packet_info.get('size', 0)
        return size > 1500 or size < 20  # Common MTU is 1500 bytes

    def _is_anomaly(self, packet_info: Dict[str, Any]) -> bool:
        """Use ML to detect network anomalies"""
        try:
            features = self._extract_features(packet_info)
            if features is None:
                return False

            X = np.array(features).reshape(1, -1)
            return self.anomaly_detector.predict(X)[0] == -1
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return False

    def _extract_features(self, packet_info: Dict[str, Any]) -> Optional[List[float]]:
        """Extract numerical features for ML analysis"""
        try:
            features = [
                float(packet_info.get('size', 0)),
                float(packet_info.get('ttl', 0)),
                float(packet_info.get('source_port', 0)),
                float(packet_info.get('destination_port', 0))
            ]
            return features
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def _update_traffic_history(self, packet_info: Dict[str, Any]):
        """Update traffic history for future analysis"""
        source_ip = packet_info.get('source_ip')
        if source_ip:
            self.traffic_history[source_ip].append(packet_info)
            
            # Maintain history size
            if len(self.traffic_history[source_ip]) > 1000:
                self.traffic_history[source_ip] = self.traffic_history[source_ip][-1000:]

    async def generate_traffic_report(self) -> Dict[str, Any]:
        """Generate a comprehensive traffic analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_ips': len(self.traffic_history),
            'protocols': defaultdict(int),
            'suspicious_activities': [],
            'top_talkers': [],
            'port_statistics': defaultdict(int)
        }

        for ip, packets in self.traffic_history.items():
            # Count protocols
            for packet in packets:
                protocol = packet.get('protocol', 'UNKNOWN')
                report['protocols'][protocol] += 1

                # Count ports
                if 'destination_port' in packet:
                    report['port_statistics'][packet['destination_port']] += 1

            # Calculate traffic volume
            traffic_volume = sum(p.get('size', 0) for p in packets)
            report['top_talkers'].append({
                'ip': ip,
                'volume': traffic_volume,
                'packet_count': len(packets)
            })

        # Sort top talkers by volume
        report['top_talkers'].sort(key=lambda x: x['volume'], reverse=True)
        report['top_talkers'] = report['top_talkers'][:10]  # Keep top 10

        return report

    def close(self):
        """Clean up resources"""
        if self.capture:
            self.capture.close()
