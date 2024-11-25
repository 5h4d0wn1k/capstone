"""Alert management system."""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship
from loguru import logger

Base = declarative_base()

class Alert(Base):
    """Alert model."""
    
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, nullable=False)  # low, medium, high, critical
    status = Column(String, default="new")  # new, investigating, resolved, false_positive
    source = Column(String)  # detector name
    event_id = Column(String)  # reference to triggering event
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    assigned_to = Column(String)  # username
    resolved_by = Column(String)  # username
    resolution_notes = Column(Text)
    false_positive = Column(Boolean, default=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary.
        
        Returns:
            Alert dictionary
        """
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "event_id": self.event_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "assigned_to": self.assigned_to,
            "resolved_by": self.resolved_by,
            "resolution_notes": self.resolution_notes,
            "false_positive": self.false_positive
        }

class AlertNote(Base):
    """Notes on alerts."""
    
    __tablename__ = "alert_notes"
    
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    user = Column(String, nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    alert = relationship("Alert", backref="notes")
    
class AlertManager:
    """Alert management system."""
    
    def __init__(self, config: Dict[str, Any], db_session: Session):
        """Initialize alert manager.
        
        Args:
            config: Alert configuration
            db_session: Database session
        """
        self.config = config
        self.db = db_session
        
    def create_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """Create new alert.
        
        Args:
            alert_data: Alert data
            
        Returns:
            Created alert
        """
        alert = Alert(**alert_data)
        self.db.add(alert)
        self.db.commit()
        
        logger.warning(f"New alert created: {alert.title} ({alert.severity})")
        return alert
        
    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Get alert by ID.
        
        Args:
            alert_id: Alert ID
            
        Returns:
            Alert if found, None otherwise
        """
        return self.db.query(Alert).filter(Alert.id == alert_id).first()
        
    def update_alert(self, alert_id: int, 
                    update_data: Dict[str, Any]) -> Optional[Alert]:
        """Update alert.
        
        Args:
            alert_id: Alert ID
            update_data: Data to update
            
        Returns:
            Updated alert if found, None otherwise
        """
        alert = self.get_alert(alert_id)
        if not alert:
            return None
            
        # Update fields
        for key, value in update_data.items():
            if hasattr(alert, key):
                setattr(alert, key, value)
                
        alert.updated_at = datetime.utcnow()
        self.db.commit()
        
        return alert
        
    def add_note(self, alert_id: int, user: str, note: str) -> Optional[AlertNote]:
        """Add note to alert.
        
        Args:
            alert_id: Alert ID
            user: Username
            note: Note text
            
        Returns:
            Created note if alert found, None otherwise
        """
        alert = self.get_alert(alert_id)
        if not alert:
            return None
            
        note = AlertNote(
            alert_id=alert_id,
            user=user,
            note=note
        )
        
        self.db.add(note)
        self.db.commit()
        
        return note
        
    def get_alerts(self, filters: Dict[str, Any] = None, 
                  limit: int = 100) -> List[Alert]:
        """Get alerts with filters.
        
        Args:
            filters: Filter conditions
            limit: Maximum alerts to return
            
        Returns:
            List of alerts
        """
        query = self.db.query(Alert)
        
        if filters:
            if "severity" in filters:
                query = query.filter(Alert.severity == filters["severity"])
            if "status" in filters:
                query = query.filter(Alert.status == filters["status"])
            if "source" in filters:
                query = query.filter(Alert.source == filters["source"])
            if "assigned_to" in filters:
                query = query.filter(Alert.assigned_to == filters["assigned_to"])
                
        return query.order_by(Alert.created_at.desc()).limit(limit).all()
        
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics.
        
        Returns:
            Statistics dictionary
        """
        stats = {
            "total": self.db.query(Alert).count(),
            "by_severity": {},
            "by_status": {},
            "by_source": {}
        }
        
        # Count by severity
        for severity in ["low", "medium", "high", "critical"]:
            count = self.db.query(Alert).filter(
                Alert.severity == severity
            ).count()
            stats["by_severity"][severity] = count
            
        # Count by status
        for status in ["new", "investigating", "resolved", "false_positive"]:
            count = self.db.query(Alert).filter(
                Alert.status == status
            ).count()
            stats["by_status"][status] = count
            
        # Count by source
        sources = self.db.query(Alert.source).distinct().all()
        for (source,) in sources:
            count = self.db.query(Alert).filter(
                Alert.source == source
            ).count()
            stats["by_source"][source] = count
            
        return stats
        
    def resolve_alert(self, alert_id: int, user: str, 
                     notes: str = None, false_positive: bool = False) -> Optional[Alert]:
        """Resolve alert.
        
        Args:
            alert_id: Alert ID
            user: Username
            notes: Resolution notes
            false_positive: Whether alert is false positive
            
        Returns:
            Updated alert if found, None otherwise
        """
        alert = self.get_alert(alert_id)
        if not alert:
            return None
            
        # Update alert
        update_data = {
            "status": "resolved",
            "resolved_by": user,
            "resolution_notes": notes,
            "false_positive": false_positive,
            "updated_at": datetime.utcnow()
        }
        
        return self.update_alert(alert_id, update_data)
        
    def assign_alert(self, alert_id: int, user: str) -> Optional[Alert]:
        """Assign alert to user.
        
        Args:
            alert_id: Alert ID
            user: Username to assign to
            
        Returns:
            Updated alert if found, None otherwise
        """
        return self.update_alert(alert_id, {
            "assigned_to": user,
            "status": "investigating"
        })
