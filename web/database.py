"""Database management for the SIEM system."""

from typing import List, Optional, Any
from datetime import datetime
import json

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, select
from sqlalchemy.ext.asyncio import AsyncEngine

from .logging import get_logger
from .config import config

logger = get_logger(__name__)
Base = declarative_base()

class EventModel(Base):
    """Model for security events."""
    
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True)
    source = Column(String)
    event_type = Column(String)
    timestamp = Column(DateTime)
    data = Column(String)
    severity = Column(String)
    
    def to_dict(self) -> dict:
        """Convert event to dictionary.
        
        Returns:
            Dictionary representation of event
        """
        return {
            "id": self.id,
            "source": self.source,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "data": json.loads(self.data),
            "severity": self.severity
        }

class AlertModel(Base):
    """Model for security alerts."""
    
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    rule_name = Column(String)
    severity = Column(String)
    timestamp = Column(DateTime)
    event_id = Column(Integer, ForeignKey("events.id"))
    status = Column(String, default="new")
    
    def to_dict(self) -> dict:
        """Convert alert to dictionary.
        
        Returns:
            Dictionary representation of alert
        """
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "status": self.status
        }

class AsyncDatabase:
    """Asynchronous database manager."""
    
    def __init__(self, db_url: Optional[str] = None):
        """Initialize database connection.
        
        Args:
            db_url: Database URL. If None, uses config value.
        """
        self.db_url = db_url or config.get("database.url", "sqlite+aiosqlite:///siem.db")
        self.engine: Optional[AsyncEngine] = None
        self.SessionLocal: Optional[sessionmaker] = None
    
    async def init(self) -> None:
        """Initialize database connection and create tables."""
        try:
            self.engine = create_async_engine(self.db_url)
            self.SessionLocal = sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    async def get_session(self) -> AsyncSession:
        """Get a database session.
        
        Returns:
            AsyncSession instance
        """
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        return self.SessionLocal()
    
    async def store_event(self, event: dict) -> int:
        """Store an event in the database.
        
        Args:
            event: Event data dictionary
            
        Returns:
            ID of stored event
        """
        async with await self.get_session() as session:
            db_event = EventModel(
                source=event["source"],
                event_type=event["event_type"],
                timestamp=event["timestamp"],
                data=json.dumps(event["data"]),
                severity=event["severity"]
            )
            session.add(db_event)
            await session.commit()
            return db_event.id
    
    async def store_alert(self, alert: dict) -> int:
        """Store an alert in the database.
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            ID of stored alert
        """
        async with await self.get_session() as session:
            db_alert = AlertModel(**alert)
            session.add(db_alert)
            await session.commit()
            return db_alert.id
    
    async def get_recent_events(self, limit: int = 100) -> List[dict]:
        """Get recent events from database.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of event dictionaries
        """
        async with await self.get_session() as session:
            result = await session.execute(
                select(EventModel)
                .order_by(EventModel.timestamp.desc())
                .limit(limit)
            )
            events = result.scalars().all()
            return [event.to_dict() for event in events]
    
    async def get_recent_alerts(self, limit: int = 100) -> List[dict]:
        """Get recent alerts from database.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of alert dictionaries
        """
        async with await self.get_session() as session:
            result = await session.execute(
                select(AlertModel)
                .order_by(AlertModel.timestamp.desc())
                .limit(limit)
            )
            alerts = result.scalars().all()
            return [alert.to_dict() for alert in alerts]
    
    async def update_alert_status(self, alert_id: int, status: str) -> None:
        """Update alert status.
        
        Args:
            alert_id: ID of alert to update
            status: New status value
        """
        async with await self.get_session() as session:
            result = await session.execute(
                select(AlertModel).where(AlertModel.id == alert_id)
            )
            alert = result.scalar_one_or_none()
            if alert:
                alert.status = status
                await session.commit()
            else:
                logger.warning(f"Alert {alert_id} not found")
