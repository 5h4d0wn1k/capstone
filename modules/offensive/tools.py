#!/usr/bin/env python3

import os
import sys
import json
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from loguru import logger
import aiohttp
import aiofiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

class OffensiveTools:
    """Offensive security tools for vulnerability scanning and assessment."""
    
    def __init__(self, config: Dict[str, Any], db_session: AsyncSession):
        """Initialize offensive tools.
        
        Args:
            config: Tool configuration
            db_session: Async database session
        """
        self.config = config
        self.db_session = db_session
        self.enabled = config.get('enabled', True)
        self.scan_interval = config.get('scan_interval', 3600)  # Default 1 hour
        self.targets = config.get('targets', [])
        self.ports = config.get('ports', [])
        self.running = False
        self.tasks = []
        
    async def initialize(self):
        """Initialize offensive tools asynchronously."""
        try:
            # Initialize vulnerability database
            self.vuln_db = await self._load_vulnerability_database()
            logger.info("Vulnerability database loaded")
            
            # Initialize scanning tools
            await self._initialize_scanning_tools()
            
            self.running = True
            logger.info("Offensive tools initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize offensive tools: {e}")
            raise
            
    async def _load_vulnerability_database(self) -> Dict:
        """Load vulnerability database asynchronously."""
        try:
            db_path = self.config.get('vuln_db_path', 'data/vulnerabilities.json')
            if os.path.exists(db_path):
                async with aiofiles.open(db_path, 'r') as f:
                    content = await f.read()
                    return json.loads(content)
            return {}
        except Exception as e:
            logger.error(f"Failed to load vulnerability database: {e}")
            return {}
            
    async def _initialize_scanning_tools(self):
        """Initialize scanning tools asynchronously."""
        try:
            # Initialize tool configurations
            self.scan_configs = {
                'ports': self.ports,
                'timeout': self.config.get('scan_timeout', 30),
                'concurrency': self.config.get('scan_concurrency', 10)
            }
            
            # Test connectivity
            for target in self.targets[:1]:  # Test first target
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f'http://{target}', timeout=5) as response:
                            if response.status == 200:
                                logger.info(f"Connectivity test successful: {target}")
                except Exception:
                    logger.warning(f"Connectivity test failed for {target}")
                    
        except Exception as e:
            logger.error(f"Failed to initialize scanning tools: {e}")
            
    async def start(self):
        """Start offensive scanning."""
        if not self.enabled:
            logger.warning("Offensive tools are disabled")
            return
            
        if not self.running:
            await self.initialize()
            
        try:
            self.tasks = [
                asyncio.create_task(self._scanning_loop()),
                asyncio.create_task(self._vulnerability_check_loop()),
                asyncio.create_task(self._report_generation_loop())
            ]
            logger.info("Offensive scanning started")
            
        except Exception as e:
            logger.error(f"Failed to start offensive scanning: {e}")
            raise
            
    async def stop(self):
        """Stop offensive scanning."""
        self.running = False
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        logger.info("Offensive scanning stopped")
            
    async def _scanning_loop(self):
        """Main scanning loop."""
        while self.running:
            try:
                for target in self.targets:
                    scan_result = await self.scan_target(target)
                    await self._process_scan_result(scan_result)
                    
                await asyncio.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"Error in scanning loop: {e}")
                await asyncio.sleep(60)  # Wait before retry
                
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Scan a target for vulnerabilities asynchronously.
        
        Args:
            target: Target host or network
            
        Returns:
            Scan results
        """
        try:
            results = {
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'ports': {},
                'vulnerabilities': []
            }
            
            # Port scanning
            open_ports = await self._scan_ports(target)
            results['ports'] = open_ports
            
            # Service detection
            if open_ports:
                services = await self._detect_services(target, open_ports)
                results['services'] = services
                
                # Vulnerability checking
                vulns = await self._check_vulnerabilities(target, services)
                results['vulnerabilities'] = vulns
                
            return results
            
        except Exception as e:
            logger.error(f"Error scanning target {target}: {e}")
            return {'error': str(e)}
            
    async def _scan_ports(self, target: str) -> Dict[int, str]:
        """Scan ports asynchronously."""
        open_ports = {}
        
        async def check_port(port):
            try:
                # Create socket connection
                future = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(
                    future, timeout=self.scan_configs['timeout']
                )
                open_ports[port] = 'open'
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
                
        try:
            # Create tasks for port scanning
            tasks = []
            for port in self.scan_configs['ports']:
                tasks.append(asyncio.create_task(check_port(port)))
                
            # Run port scans concurrently
            await asyncio.gather(*tasks)
            return open_ports
            
        except Exception as e:
            logger.error(f"Error scanning ports for {target}: {e}")
            return {}
            
    async def _detect_services(self, target: str, open_ports: Dict[int, str]) -> Dict[int, Dict]:
        """Detect services on open ports asynchronously."""
        services = {}
        
        async def probe_service(port):
            try:
                future = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(
                    future, timeout=self.scan_configs['timeout']
                )
                
                # Send probe
                writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
                await writer.drain()
                
                # Read response
                data = await reader.read(1024)
                writer.close()
                await writer.wait_closed()
                
                # Analyze response
                services[port] = {
                    'banner': data.decode('utf-8', errors='ignore'),
                    'service': self._identify_service(data)
                }
                
            except Exception as e:
                logger.debug(f"Error probing service on port {port}: {e}")
                
        try:
            tasks = []
            for port in open_ports:
                tasks.append(asyncio.create_task(probe_service(port)))
                
            await asyncio.gather(*tasks)
            return services
            
        except Exception as e:
            logger.error(f"Error detecting services for {target}: {e}")
            return {}
            
    def _identify_service(self, data: bytes) -> str:
        """Identify service from probe response."""
        try:
            data_str = data.decode('utf-8', errors='ignore').lower()
            
            # Common service signatures
            if b'ssh' in data: return 'ssh'
            if b'http' in data: return 'http'
            if b'ftp' in data: return 'ftp'
            if b'smtp' in data: return 'smtp'
            
            return 'unknown'
            
        except Exception:
            return 'unknown'
            
    async def _check_vulnerabilities(self, target: str, services: Dict[int, Dict]) -> List[Dict]:
        """Check for vulnerabilities in detected services."""
        vulnerabilities = []
        
        try:
            for port, service_info in services.items():
                service = service_info['service']
                banner = service_info['banner']
                
                # Check vulnerability database
                service_vulns = self.vuln_db.get(service, [])
                for vuln in service_vulns:
                    if vuln['signature'] in banner:
                        vulnerabilities.append({
                            'port': port,
                            'service': service,
                            'vulnerability': vuln['name'],
                            'severity': vuln['severity'],
                            'description': vuln['description']
                        })
                        
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error checking vulnerabilities for {target}: {e}")
            return []
            
    async def _process_scan_result(self, result: Dict):
        """Process and store scan results."""
        try:
            if 'error' in result:
                logger.error(f"Scan error: {result['error']}")
                return
                
            # Store results in database
            async with self.db_session() as session:
                scan_record = ScanResultModel(
                    target=result['target'],
                    timestamp=datetime.fromisoformat(result['timestamp']),
                    data=json.dumps(result)
                )
                session.add(scan_record)
                await session.commit()
                
            # Check for critical vulnerabilities
            critical_vulns = [
                v for v in result.get('vulnerabilities', [])
                if v['severity'] in ['critical', 'high']
            ]
            
            if critical_vulns:
                await self._alert_critical_vulnerabilities(result['target'], critical_vulns)
                
        except Exception as e:
            logger.error(f"Error processing scan result: {e}")
            
    async def _alert_critical_vulnerabilities(self, target: str, vulnerabilities: List[Dict]):
        """Alert on critical vulnerabilities."""
        try:
            async with self.db_session() as session:
                for vuln in vulnerabilities:
                    alert = AlertModel(
                        timestamp=datetime.utcnow(),
                        source='offensive_scan',
                        severity=vuln['severity'],
                        message=f"Critical vulnerability found in {target}: {vuln['vulnerability']}"
                    )
                    session.add(alert)
                await session.commit()
                
            logger.warning(f"Critical vulnerabilities found in {target}")
            
        except Exception as e:
            logger.error(f"Error creating vulnerability alerts: {e}")
            
    async def _vulnerability_check_loop(self):
        """Periodic vulnerability database updates."""
        while self.running:
            try:
                # Update vulnerability database
                await self._update_vulnerability_database()
                await asyncio.sleep(86400)  # Daily updates
                
            except Exception as e:
                logger.error(f"Error in vulnerability check loop: {e}")
                await asyncio.sleep(3600)  # Retry after an hour
                
    async def _update_vulnerability_database(self):
        """Update vulnerability database from sources."""
        try:
            sources = self.config.get('vuln_db_sources', [])
            for source in sources:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(source['url']) as response:
                            if response.status == 200:
                                data = await response.json()
                                # Merge with existing database
                                self.vuln_db.update(data)
                                
                except Exception as e:
                    logger.error(f"Error updating from source {source['name']}: {e}")
                    
            # Save updated database
            db_path = self.config.get('vuln_db_path', 'data/vulnerabilities.json')
            async with aiofiles.open(db_path, 'w') as f:
                await f.write(json.dumps(self.vuln_db))
                
        except Exception as e:
            logger.error(f"Error updating vulnerability database: {e}")
            
    async def _report_generation_loop(self):
        """Generate periodic scan reports."""
        while self.running:
            try:
                await self._generate_scan_report()
                await asyncio.sleep(3600)  # Hourly reports
                
            except Exception as e:
                logger.error(f"Error in report generation loop: {e}")
                await asyncio.sleep(300)  # Retry after 5 minutes
                
    async def _generate_scan_report(self):
        """Generate comprehensive scan report."""
        try:
            async with self.db_session() as session:
                # Query recent scan results
                stmt = select(ScanResultModel).order_by(
                    ScanResultModel.timestamp.desc()
                ).limit(100)
                
                results = await session.execute(stmt)
                scans = results.scalars().all()
                
                # Generate report
                report = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'summary': {
                        'total_scans': len(scans),
                        'vulnerabilities': self._summarize_vulnerabilities(scans)
                    },
                    'details': [json.loads(scan.data) for scan in scans]
                }
                
                # Save report
                report_path = f"reports/scan_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
                os.makedirs('reports', exist_ok=True)
                
                async with aiofiles.open(report_path, 'w') as f:
                    await f.write(json.dumps(report, indent=2))
                    
                logger.info(f"Scan report generated: {report_path}")
                
        except Exception as e:
            logger.error(f"Error generating scan report: {e}")
            
    def _summarize_vulnerabilities(self, scans: List['ScanResultModel']) -> Dict:
        """Summarize vulnerabilities from scan results."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for scan in scans:
            try:
                data = json.loads(scan.data)
                for vuln in data.get('vulnerabilities', []):
                    severity = vuln['severity'].lower()
                    if severity in summary:
                        summary[severity] += 1
            except Exception as e:
                logger.error(f"Error processing scan for summary: {e}")
                
        return summary
