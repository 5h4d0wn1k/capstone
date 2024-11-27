from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class EventModel(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    source = Column(String)
    event_type = Column(String)
    timestamp = Column(DateTime)
    data = Column(String)
    severity = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'source': self.source,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'severity': self.severity
        }

class AlertModel(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    rule_name = Column(String)
    severity = Column(String)
    timestamp = Column(DateTime)
    event_id = Column(Integer, ForeignKey('events.id'))
    status = Column(String, default='new')

    def to_dict(self):
        return {
            'id': self.id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'event_id': self.event_id,
            'status': self.status
        }

class NetworkLogModel(Base):
    __tablename__ = 'network_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    source_ip = Column(String)
    destination_ip = Column(String)
    protocol = Column(String)
    data = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'protocol': self.protocol,
            'data': self.data
        }
