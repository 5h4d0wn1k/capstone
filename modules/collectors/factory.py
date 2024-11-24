import platform
from typing import Dict, Optional
from loguru import logger
from .base import BaseEventCollector
from .windows import WindowsEventCollector
from .linux import LinuxEventCollector
from .syslog import SyslogCollector
from .custom import CustomLogCollector

class CollectorFactory:
    """Factory class for creating platform-specific collectors"""
    
    @staticmethod
    def create_collector(collector_type: str, config: Dict) -> Optional[BaseEventCollector]:
        """Create a collector instance based on type and platform"""
        try:
            current_platform = platform.system().lower()
            
            if collector_type == 'system':
                # System collectors are platform-specific
                if current_platform == 'windows':
                    return WindowsEventCollector(config)
                elif current_platform == 'linux':
                    return LinuxEventCollector(config)
                else:
                    logger.warning(f"No system collector available for platform: {current_platform}")
                    return None
                    
            elif collector_type == 'syslog':
                # Syslog collector works on any platform that supports syslog
                return SyslogCollector(config)
                
            elif collector_type == 'custom':
                # Custom log collector works on any platform
                return CustomLogCollector(config)
                
            else:
                logger.error(f"Unknown collector type: {collector_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating collector {collector_type}: {e}")
            return None
            
    @staticmethod
    def get_available_collectors() -> Dict[str, list]:
        """Get list of available collectors for current platform"""
        current_platform = platform.system().lower()
        
        # Basic collectors available on all platforms
        collectors = {
            'basic': ['custom', 'syslog'],
            'system': []
        }
        
        # Add platform-specific collectors
        if current_platform == 'windows':
            collectors['system'].append('windows')
        elif current_platform == 'linux':
            collectors['system'].append('linux')
            
        return collectors
