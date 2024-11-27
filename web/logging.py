"""Logging configuration for the SIEM system."""

import sys
import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

from .config import config

def setup_logging(log_level: Optional[str] = None) -> None:
    """Configure logging for the SIEM system.
    
    Args:
        log_level: Optional override for log level from config
    """
    # Create logs directory if it doesn't exist
    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    # Get log level from config or parameter
    level = (log_level or config.get("logging.level", "INFO")).upper()
    log_level_num = getattr(logging, level)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level_num)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level_num)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler
    file_handler = RotatingFileHandler(
        log_dir / "siem.log",
        maxBytes=10_000_000,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level_num)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # Create separate error log
    error_handler = RotatingFileHandler(
        log_dir / "error.log",
        maxBytes=10_000_000,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    root_logger.addHandler(error_handler)

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name.
    
    Args:
        name: Name for the logger, typically __name__
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
