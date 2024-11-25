#!/usr/bin/env python3

"""Default configuration for the SIEM system."""

import os
import secrets
from datetime import timedelta

# Web interface configuration
WEB_CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'DEBUG': False,
    'SECRET_KEY': secrets.token_hex(32),
    'SESSION_TYPE': 'filesystem',
    'PERMANENT_SESSION_LIFETIME': timedelta(days=1)
}

# Monitoring configuration
MONITOR_CONFIG = {
    'ProcessMonitor': {
        'enabled': True,
        'update_interval': 1,  # seconds
        'thresholds': {
            'cpu_percent': 90,
            'memory_percent': 80
        }
    },
    'NetworkMonitor': {
        'enabled': True,
        'update_interval': 1,  # seconds
        'suspicious_ports': [22, 23, 445, 3389],  # SSH, Telnet, SMB, RDP
        'max_connections': 1000
    },
    'FileMonitor': {
        'enabled': True,
        'watch_paths': [
            os.environ.get('SYSTEMROOT', 'C:\\Windows'),
            os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
            os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')
        ],
        'suspicious_extensions': ['.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs'],
        'max_events': 10000
    },
    'RegistryMonitor': {
        'enabled': True,
        'update_interval': 1,  # seconds
        'suspicious_keys': [
            'software\\microsoft\\windows\\currentversion\\run',
            'software\\microsoft\\windows\\currentversion\\runonce',
            'software\\wow6432node\\microsoft\\windows\\currentversion\\run',
            'system\\currentcontrolset\\services'
        ],
        'max_events': 10000
    }
}

# Defensive tools configuration
DEFENSIVE_CONFIG = {
    'enabled': True,
    'log_level': 'INFO',
    'max_alerts': 1000,
    'alert_threshold': 'Medium',
    'response_actions': {
        'block_ip': True,
        'kill_process': True,
        'restore_registry': True
    }
}

# Offensive tools configuration
OFFENSIVE_CONFIG = {
    'enabled': True,
    'scan_interval': 3600,  # seconds
    'max_scan_threads': 10,
    'nmap_args': '-sS -sV -O -T4',
    'vuln_scan': True,
    'brute_force': False
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
        },
        'file': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.FileHandler',
            'filename': 'siem.log',
            'mode': 'a',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default', 'file'],
            'level': 'INFO',
            'propagate': True
        }
    }
}

# Event collection configuration
COLLECTOR_CONFIG = {
    'WindowsEventCollector': {
        'enabled': True,
        'channels': ['Security', 'System', 'Application'],
        'max_events': 10000
    },
    'SyslogCollector': {
        'enabled': True,
        'host': '0.0.0.0',
        'port': 514,
        'max_events': 10000
    },
    'CustomCollector': {
        'enabled': True,
        'sources': [],
        'max_events': 10000
    }
}

# Complete configuration dictionary
CONFIG = {
    'web': WEB_CONFIG,
    'monitor': MONITOR_CONFIG,
    'defensive': DEFENSIVE_CONFIG,
    'offensive': OFFENSIVE_CONFIG,
    'logging': LOGGING_CONFIG,
    'collector': COLLECTOR_CONFIG
}
