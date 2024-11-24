#!/usr/bin/env python3

import os
import sys
import yaml
import logging
from loguru import logger
import signal
import time

def setup_logging():
    """Configure logging with both file and console output"""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logger.add(
        "logs/siem.log",
        rotation="500 MB",
        retention="10 days",
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
    )

def load_config():
    """Load SIEM configuration from config.yaml"""
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Shutdown signal received. Stopping SIEM...")
    if 'siem' in globals():
        siem.shutdown()
    sys.exit(0)

def main():
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize logging
    setup_logging()
    logger.info("Starting SIEM system...")
    
    # Load configuration
    config = load_config()
    
    try:
        # Import SIEM after logging is setup
        from siem import SIEM
        global siem
        siem = SIEM(config)
        
        # Start SIEM
        siem.run(debug=False)
        
    except Exception as e:
        logger.error(f"Failed to start SIEM: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
