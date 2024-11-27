#!/usr/bin/env python3

import asyncio
import win32evtlog
import win32security
import win32api
import win32con
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json
from loguru import logger
import win32evtlogutil
import winerror
from kafka import KafkaProducer

class WindowsEventCollector:
    """Collector for Windows Event Logs"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the Windows Event Collector"""
        self.config = config
        self.running = False
        self.last_read_time = {}
        self.producer = None
        self.initialize_producer()

    def initialize_producer(self):
        """Initialize Kafka producer"""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers='localhost:9092',
                value_serializer=lambda x: json.dumps(x).encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Failed to initialize Kafka producer: {e}")
            raise

    async def start(self):
        """Start collecting Windows events"""
        try:
            logger.info("Starting Windows Event Collector...")
            self.running = True
            
            # Start collection tasks for each channel
            tasks = []
            for channel in self.config['channels']:
                tasks.append(asyncio.create_task(self._collect_events(channel)))
            
            # Wait for all tasks
            await asyncio.gather(*tasks)
            
        except Exception as e:
            logger.error(f"Error starting Windows Event Collector: {e}")
            raise

    async def stop(self):
        """Stop collecting Windows events"""
        logger.info("Stopping Windows Event Collector...")
        self.running = False
        if self.producer:
            self.producer.close()

    async def _collect_events(self, channel: str):
        """Collect events from a specific Windows Event Log channel"""
        while self.running:
            try:
                # Open event log
                handle = win32evtlog.OpenEventLog(None, channel)
                
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                # Get events
                events = self._read_events(handle, channel)
                
                # Process and send events
                for event in events:
                    await self._process_event(event, channel)
                
                # Close handle
                win32evtlog.CloseEventLog(handle)
                
                # Wait for next collection interval
                await asyncio.sleep(self.config['interval'])
                
            except Exception as e:
                logger.error(f"Error collecting events from channel {channel}: {e}")
                await asyncio.sleep(1)  # Prevent tight loop on error

    def _read_events(self, handle: Any, channel: str) -> List[Dict[str, Any]]:
        """Read events from Windows Event Log"""
        events = []
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        try:
            while True:
                events_raw = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events_raw:
                    break
                
                for event in events_raw:
                    # Convert event to dictionary
                    event_dict = self._convert_event_to_dict(event)
                    
                    # Check if we've already processed this event
                    if self._is_new_event(event_dict, channel):
                        events.append(event_dict)
        
        except Exception as e:
            if e.winerror != winerror.ERROR_NO_MORE_ITEMS:
                logger.error(f"Error reading events from channel {channel}: {e}")
        
        return events

    def _convert_event_to_dict(self, event: Any) -> Dict[str, Any]:
        """Convert Windows Event to dictionary format"""
        try:
            # Get event category and description
            try:
                category = win32evtlogutil.SafeFormatMessage(event, event.SourceName)
                description = win32evtlogutil.SafeFormatMessage(event, event.StringInserts)
            except Exception:
                category = str(event.EventCategory)
                description = str(event.StringInserts)

            # Get user information
            try:
                sid = event.Sid
                if sid:
                    try:
                        domain, user, typ = win32security.LookupAccountSid(None, sid)
                        username = f"{domain}\\{user}"
                    except Exception:
                        username = str(sid)
                else:
                    username = "N/A"
            except Exception:
                username = "Unknown"

            # Convert event to dictionary
            event_dict = {
                'timestamp': str(event.TimeGenerated),
                'source': event.SourceName,
                'event_id': event.EventID & 0xFFFF,  # Mask out qualifiers
                'event_type': self._get_event_type(event.EventType),
                'category': category,
                'description': description,
                'user': username,
                'computer': event.ComputerName,
                'record_number': event.RecordNumber,
                'raw_data': str(event.Data) if event.Data else None
            }

            return event_dict
            
        except Exception as e:
            logger.error(f"Error converting event to dictionary: {e}")
            return {
                'error': f"Failed to convert event: {str(e)}",
                'raw_event': str(event)
            }

    def _get_event_type(self, event_type: int) -> str:
        """Convert Windows event type to string"""
        event_types = {
            win32con.EVENTLOG_SUCCESS: 'Success',
            win32con.EVENTLOG_ERROR_TYPE: 'Error',
            win32con.EVENTLOG_WARNING_TYPE: 'Warning',
            win32con.EVENTLOG_INFORMATION_TYPE: 'Information',
            win32con.EVENTLOG_AUDIT_SUCCESS: 'Audit Success',
            win32con.EVENTLOG_AUDIT_FAILURE: 'Audit Failure'
        }
        return event_types.get(event_type, f'Unknown ({event_type})')

    def _is_new_event(self, event: Dict[str, Any], channel: str) -> bool:
        """Check if event is new based on timestamp"""
        event_time = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
        
        if channel not in self.last_read_time:
            self.last_read_time[channel] = event_time
            return True
        
        if event_time > self.last_read_time[channel]:
            self.last_read_time[channel] = event_time
            return True
        
        return False

    async def _process_event(self, event: Dict[str, Any], channel: str):
        """Process and send event to Kafka"""
        try:
            # Enrich event with additional context
            enriched_event = self._enrich_event(event)
            
            # Add metadata
            enriched_event.update({
                'collector': 'windows_event',
                'channel': channel,
                'collection_timestamp': datetime.now().isoformat()
            })
            
            # Send to Kafka
            self.producer.send('siem.events', enriched_event)
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")

    def _enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with additional context"""
        try:
            enriched = event.copy()
            
            # Add severity level
            enriched['severity'] = self._determine_severity(event)
            
            # Add MITRE ATT&CK mapping if available
            attack_mapping = self._map_to_mitre_attack(event)
            if attack_mapping:
                enriched['mitre_attack'] = attack_mapping
            
            # Add asset information
            enriched['asset'] = self._get_asset_info(event['computer'])
            
            return enriched
            
        except Exception as e:
            logger.error(f"Error enriching event: {e}")
            return event

    def _determine_severity(self, event: Dict[str, Any]) -> str:
        """Determine event severity"""
        if event['event_type'] in ['Error', 'Audit Failure']:
            return 'high'
        elif event['event_type'] == 'Warning':
            return 'medium'
        else:
            return 'low'

    def _map_to_mitre_attack(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Map event to MITRE ATT&CK framework"""
        # This is a simplified example. In practice, you would have a more comprehensive mapping
        attack_mappings = {
            4624: {  # Successful logon
                'tactic': 'Initial Access',
                'technique': 'Valid Accounts',
                'technique_id': 'T1078'
            },
            4625: {  # Failed logon
                'tactic': 'Initial Access',
                'technique': 'Brute Force',
                'technique_id': 'T1110'
            },
            4688: {  # Process creation
                'tactic': 'Execution',
                'technique': 'Command and Scripting Interpreter',
                'technique_id': 'T1059'
            }
        }
        
        return attack_mappings.get(event['event_id'])

    def _get_asset_info(self, computer_name: str) -> Dict[str, Any]:
        """Get asset information for the computer"""
        try:
            # This is a simplified example. In practice, you would query an asset database
            return {
                'hostname': computer_name,
                'domain': win32api.GetDomainName(),
                'type': 'windows_workstation'  # You would determine this from asset database
            }
        except Exception:
            return {
                'hostname': computer_name,
                'type': 'unknown'
            }

    async def health_check(self) -> bool:
        """Check if collector is healthy"""
        try:
            # Try to open a test channel
            handle = win32evtlog.OpenEventLog(None, 'System')
            win32evtlog.CloseEventLog(handle)
            
            # Check Kafka producer
            if not self.producer:
                return False
            
            return True
        except Exception:
            return False
