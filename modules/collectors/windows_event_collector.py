"""Windows Event Log collector implementation."""

import win32evtlog
import win32security
import win32api
import win32con
from datetime import datetime
from typing import Dict, Any, List, Optional
from loguru import logger
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from models import EventModel

class WindowsEventCollector:
    """Windows Event Log collector."""
    
    def __init__(self, config: Dict[str, Any], db_session: AsyncSession):
        """Initialize collector.
        
        Args:
            config: Collector configuration
            db_session: Async database session
        """
        self.config = config
        self.db_session = db_session
        self.enabled = self.config.get('enabled', True)
        self.channels = self.config.get('channels', ['System', 'Security', 'Application'])
        self.batch_size = self.config.get('batch_size', 100)
        self.poll_interval = self.config.get('poll_interval', 10)
        self.running = False
        self.tasks = []
        
    async def start(self) -> None:
        """Start collecting events."""
        if not self.enabled:
            logger.warning("Windows Event collector is disabled")
            return
            
        try:
            self.running = True
            for channel in self.channels:
                task = asyncio.create_task(self._collect_events(channel))
                self.tasks.append(task)
            logger.info(f"Windows Event collector started for channels: {', '.join(self.channels)}")
            
        except Exception as e:
            logger.error(f"Failed to start Windows Event collector: {e}")
            self.running = False
            raise
            
    async def stop(self) -> None:
        """Stop collecting events."""
        self.running = False
        if self.tasks:
            for task in self.tasks:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            self.tasks.clear()
        logger.info("Windows Event collector stopped")
        
    async def _collect_events(self, channel: str) -> None:
        """Collect events from a specific Windows Event Log channel.
        
        Args:
            channel: Event log channel name
        """
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while self.running:
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                events_to_commit = []
                
                try:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    
                    for event in events:
                        if not self.running:
                            break
                            
                        event_data = {
                            'source': event.SourceName,
                            'event_type': str(event.EventType),
                            'timestamp': datetime.fromtimestamp(event.TimeGenerated),
                            'data': str(event.StringInserts),
                            'severity': self._get_event_severity(event.EventType)
                        }
                        
                        events_to_commit.append(EventModel(**event_data))
                        
                        if len(events_to_commit) >= self.batch_size:
                            await self._commit_events(events_to_commit)
                            events_to_commit.clear()
                            
                    if events_to_commit:
                        await self._commit_events(events_to_commit)
                        
                finally:
                    win32evtlog.CloseEventLog(handle)
                    
            except Exception as e:
                logger.error(f"Error collecting events from {channel}: {e}")
                
            await asyncio.sleep(self.poll_interval)
            
    async def _commit_events(self, events: List[EventModel]) -> None:
        """Commit collected events to the database.
        
        Args:
            events: List of event models to commit
        """
        try:
            async with self.db_session() as session:
                async with session.begin():
                    for event in events:
                        session.add(event)
            logger.debug(f"Committed {len(events)} events to database")
            
        except Exception as e:
            logger.error(f"Failed to commit events to database: {e}")
            
    def _get_event_severity(self, event_type: int) -> str:
        """Get event severity based on event type.
        
        Args:
            event_type: Windows event type
            
        Returns:
            Severity level string
        """
        severity_map = {
            win32evtlog.EVENTLOG_ERROR_TYPE: 'ERROR',
            win32evtlog.EVENTLOG_WARNING_TYPE: 'WARNING',
            win32evtlog.EVENTLOG_INFORMATION_TYPE: 'INFO',
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'SUCCESS',
            win32evtlog.EVENTLOG_AUDIT_FAILURE: 'FAILURE'
        }
        return severity_map.get(event_type, 'UNKNOWN')

async def main():
    config = {
        'enabled': True,
        'channels': ['System', 'Security', 'Application'],
        'batch_size': 100,
        'poll_interval': 10
    }
    db_session = AsyncSession(bind=engine)  # Replace with your database engine
    collector = WindowsEventCollector(config, db_session)
    await collector.start()
    await asyncio.sleep(10)
    await collector.stop()

if __name__ == "__main__":
    asyncio.run(main())
