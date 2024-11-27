#!/usr/bin/env python3

import asyncio
import pyshark
from typing import Dict, List, Any, Optional
import json
from loguru import logger
from kafka import KafkaProducer
from datetime import datetime
import ipaddress
import socket
import struct
import threading
from collections import defaultdict
import numpy as np
from scapy.all import *

class NetworkCollector:
    """Advanced Network Traffic Collector"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the Network Collector"""
        self.config = config
        self.running = False
        self.producer = None
        self.capture = None
        self.stats = defaultdict(int)
        self.baseline = defaultdict(list)
        self.anomaly_threshold = 2.0  # Standard deviations
        self.initialize_components()

    def initialize_components(self):
        """Initialize collector components"""
        try:
            self._init_kafka_producer()
            self._init_packet_capture()
            self._init_baseline_stats()
        except Exception as e:
            logger.error(f"Failed to initialize network collector: {e}")
            raise

    def _init_kafka_producer(self):
        """Initialize Kafka producer"""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers='localhost:9092',
                value_serializer=lambda x: json.dumps(x).encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Failed to initialize Kafka producer: {e}")
            raise

    def _init_packet_capture(self):
        """Initialize packet capture"""
        try:
            interface = self.config.get('interface', 'any')
            bpf_filter = self.config.get('bpf_filter', '')
            
            # Initialize live capture
            self.capture = pyshark.LiveCapture(
                interface=interface,
                bpf_filter=bpf_filter,
                use_json=True,
                include_raw=True
            )
            
            logger.info(f"Packet capture initialized on interface: {interface}")
        except Exception as e:
            logger.error(f"Failed to initialize packet capture: {e}")
            raise

    def _init_baseline_stats(self):
        """Initialize baseline network statistics"""
        self.baseline = {
            'bytes_per_second': [],
            'packets_per_second': [],
            'unique_ips': set(),
            'protocols': defaultdict(int),
            'ports': defaultdict(int)
        }

    async def start(self):
        """Start network collection"""
        try:
            logger.info("Starting Network Collector...")
            self.running = True
            
            # Start collection tasks
            collection_task = asyncio.create_task(self._collect_packets())
            analysis_task = asyncio.create_task(self._analyze_traffic())
            
            # Wait for tasks
            await asyncio.gather(collection_task, analysis_task)
            
        except Exception as e:
            logger.error(f"Error starting Network Collector: {e}")
            raise

    async def stop(self):
        """Stop network collection"""
        logger.info("Stopping Network Collector...")
        self.running = False
        if self.capture:
            self.capture.close()
        if self.producer:
            self.producer.close()

    async def _collect_packets(self):
        """Collect and process network packets"""
        try:
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                
                # Process packet
                packet_data = self._process_packet(packet)
                
                if packet_data:
                    # Update statistics
                    self._update_stats(packet_data)
                    
                    # Check for anomalies
                    anomalies = self._check_anomalies(packet_data)
                    if anomalies:
                        packet_data['anomalies'] = anomalies
                    
                    # Send to Kafka
                    self.producer.send('siem.network', packet_data)
                
        except Exception as e:
            logger.error(f"Error in packet collection: {e}")
            if self.running:
                # Attempt to restart collection
                await asyncio.sleep(1)
                await self._collect_packets()

    def _process_packet(self, packet) -> Dict[str, Any]:
        """Process a single packet"""
        try:
            packet_dict = {
                'timestamp': datetime.now().isoformat(),
                'length': packet.length,
                'protocol': packet.highest_layer,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None
            }

            # Extract IP information
            if hasattr(packet, 'ip'):
                packet_dict.update({
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'ttl': packet.ip.ttl
                })

            # Extract port information
            if hasattr(packet, 'tcp'):
                packet_dict.update({
                    'src_port': packet.tcp.srcport,
                    'dst_port': packet.tcp.dstport,
                    'tcp_flags': packet.tcp.flags
                })
            elif hasattr(packet, 'udp'):
                packet_dict.update({
                    'src_port': packet.udp.srcport,
                    'dst_port': packet.udp.dstport
                })

            # Add application layer information
            if hasattr(packet, 'http'):
                packet_dict['application'] = {
                    'protocol': 'HTTP',
                    'method': getattr(packet.http, 'request_method', ''),
                    'host': getattr(packet.http, 'host', ''),
                    'uri': getattr(packet.http, 'request_uri', '')
                }
            elif hasattr(packet, 'dns'):
                packet_dict['application'] = {
                    'protocol': 'DNS',
                    'qry_name': getattr(packet.dns, 'qry_name', ''),
                    'qry_type': getattr(packet.dns, 'qry_type', '')
                }

            # Enrich with threat intelligence
            self._enrich_packet(packet_dict)

            return packet_dict

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None

    def _enrich_packet(self, packet_dict: Dict[str, Any]):
        """Enrich packet with threat intelligence"""
        try:
            # Check for known malicious IPs
            if packet_dict.get('src_ip'):
                # This would typically query a threat intel database
                packet_dict['src_ip_reputation'] = self._check_ip_reputation(packet_dict['src_ip'])
            
            if packet_dict.get('dst_ip'):
                packet_dict['dst_ip_reputation'] = self._check_ip_reputation(packet_dict['dst_ip'])

            # Check for suspicious ports
            if packet_dict.get('dst_port'):
                packet_dict['port_risk'] = self._assess_port_risk(packet_dict['dst_port'])

        except Exception as e:
            logger.error(f"Error enriching packet: {e}")

    def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation (simplified example)"""
        # In practice, this would query threat intel feeds
        suspicious_ranges = [
            '185.0.0.0/8',    # Known spam range
            '192.168.0.0/16'  # Internal network (suspicious if external traffic)
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in suspicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return {
                        'score': 'high_risk',
                        'reason': f'IP in suspicious range {range_str}'
                    }
            return {'score': 'low_risk', 'reason': 'No known risks'}
        except Exception:
            return {'score': 'unknown', 'reason': 'Failed to check reputation'}

    def _assess_port_risk(self, port: int) -> str:
        """Assess the risk level of a port"""
        high_risk_ports = {
            22: 'SSH',
            23: 'Telnet',
            445: 'SMB',
            3389: 'RDP',
            4444: 'Metasploit'
        }
        
        medium_risk_ports = {
            21: 'FTP',
            137: 'NetBIOS',
            161: 'SNMP'
        }
        
        if port in high_risk_ports:
            return 'high'
        elif port in medium_risk_ports:
            return 'medium'
        return 'low'

    def _update_stats(self, packet_data: Dict[str, Any]):
        """Update network statistics"""
        try:
            # Update packet counts
            self.stats['total_packets'] += 1
            self.stats['total_bytes'] += packet_data['length']
            
            # Update protocol stats
            protocol = packet_data['protocol']
            self.stats['protocols'][protocol] += 1
            
            # Update IP stats
            if packet_data.get('src_ip'):
                self.baseline['unique_ips'].add(packet_data['src_ip'])
            if packet_data.get('dst_ip'):
                self.baseline['unique_ips'].add(packet_data['dst_ip'])
            
            # Update port stats
            if packet_data.get('dst_port'):
                self.baseline['ports'][packet_data['dst_port']] += 1
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")

    def _check_anomalies(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for network anomalies"""
        anomalies = []
        
        try:
            # Check for volume anomalies
            if len(self.baseline['bytes_per_second']) > 60:  # 1-minute baseline
                avg_bytes = np.mean(self.baseline['bytes_per_second'])
                std_bytes = np.std(self.baseline['bytes_per_second'])
                
                if packet_data['length'] > avg_bytes + (self.anomaly_threshold * std_bytes):
                    anomalies.append({
                        'type': 'volume_anomaly',
                        'severity': 'medium',
                        'description': 'Unusual packet size detected'
                    })
            
            # Check for port scan behavior
            if self._detect_port_scan(packet_data):
                anomalies.append({
                    'type': 'port_scan',
                    'severity': 'high',
                    'description': 'Potential port scanning detected'
                })
            
            # Check for suspicious protocols
            if self._detect_suspicious_protocol(packet_data):
                anomalies.append({
                    'type': 'suspicious_protocol',
                    'severity': 'medium',
                    'description': 'Suspicious protocol detected'
                })
            
        except Exception as e:
            logger.error(f"Error checking anomalies: {e}")
        
        return anomalies

    def _detect_port_scan(self, packet_data: Dict[str, Any]) -> bool:
        """Detect potential port scanning behavior"""
        try:
            src_ip = packet_data.get('src_ip')
            if not src_ip:
                return False
            
            # Track unique ports per IP
            if not hasattr(self, '_port_scan_tracking'):
                self._port_scan_tracking = defaultdict(set)
            
            if packet_data.get('dst_port'):
                self._port_scan_tracking[src_ip].add(packet_data['dst_port'])
            
            # If an IP has tried more than 10 different ports in a short time
            return len(self._port_scan_tracking[src_ip]) > 10
            
        except Exception as e:
            logger.error(f"Error in port scan detection: {e}")
            return False

    def _detect_suspicious_protocol(self, packet_data: Dict[str, Any]) -> bool:
        """Detect suspicious protocols"""
        suspicious_protocols = {
            'TELNET', 'SMB', 'NETBIOS'
        }
        return packet_data['protocol'].upper() in suspicious_protocols

    async def _analyze_traffic(self):
        """Periodic traffic analysis"""
        while self.running:
            try:
                # Analyze traffic patterns
                analysis = self._analyze_traffic_patterns()
                
                # Send analysis results to Kafka
                if analysis:
                    self.producer.send('siem.network.analysis', analysis)
                
                # Wait before next analysis
                await asyncio.sleep(60)  # Analyze every minute
                
            except Exception as e:
                logger.error(f"Error in traffic analysis: {e}")
                await asyncio.sleep(1)

    def _analyze_traffic_patterns(self) -> Dict[str, Any]:
        """Analyze traffic patterns"""
        try:
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'interval': '1m',
                'metrics': {
                    'total_packets': self.stats['total_packets'],
                    'total_bytes': self.stats['total_bytes'],
                    'unique_ips': len(self.baseline['unique_ips']),
                    'protocols': dict(self.stats['protocols']),
                    'top_ports': self._get_top_n(self.baseline['ports'], 10)
                },
                'anomalies': [],
                'threats': []
            }
            
            # Reset counters for next interval
            self.stats = defaultdict(int)
            self.stats['protocols'] = defaultdict(int)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing traffic patterns: {e}")
            return None

    def _get_top_n(self, counter: Dict, n: int) -> List[tuple]:
        """Get top N items from a counter"""
        return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]

    async def health_check(self) -> bool:
        """Check if collector is healthy"""
        try:
            # Check if capture interface is available
            if not self.capture:
                return False
            
            # Check Kafka producer
            if not self.producer:
                return False
            
            return True
        except Exception:
            return False
