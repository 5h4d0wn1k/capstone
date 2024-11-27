"""Log collectors for SIEM platform."""

from .windows_event_collector import WindowsEventCollector
from .syslog_collector import SyslogCollector
from .custom_collector import CustomLogCollector

__all__ = [
    'WindowsEventCollector',
    'SyslogCollector',
    'CustomLogCollector'
]
