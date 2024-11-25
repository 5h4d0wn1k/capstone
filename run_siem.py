#!/usr/bin/env python3
"""SIEM System Runner

This script initializes and runs the SIEM system with the web interface.
"""

import yaml
import argparse
import sys
import os
from loguru import logger
from siem.siem import SIEM

def load_config(config_path: str) -> dict:
    """Load configuration from YAML file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        sys.exit(1)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="SIEM System Runner")
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    args = parser.parse_args()

    # Configure logging
    logger.remove()  # Remove default handler
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level>"
    )
    
    if args.debug:
        logger.add(sys.stderr, format=log_format, level="DEBUG")
        logger.add("logs/debug.log", format=log_format, level="DEBUG", rotation="1 day")
    else:
        logger.add(sys.stderr, format=log_format, level="INFO")
        logger.add("logs/siem.log", format=log_format, level="INFO", rotation="1 day")

    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)

    # Load configuration
    config = load_config(args.config)
    logger.info(f"Loaded configuration from {args.config}")

    try:
        # Initialize SIEM system
        siem = SIEM(config)
        logger.info("Initialized SIEM system")

        # Run SIEM system
        logger.info("Starting SIEM system...")
        siem.run(debug=args.debug)

    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        siem.shutdown()
        logger.info("SIEM system stopped")
    except Exception as e:
        logger.error(f"SIEM system error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
