"""Configuration package for the SIEM system."""

from .default_config import CONFIG as DEFAULT_CONFIG

def load_config(config_file=None):
    """
    Load configuration from file or use defaults.
    
    Args:
        config_file (str, optional): Path to configuration file
        
    Returns:
        dict: Configuration dictionary
    """
    if config_file:
        try:
            with open(config_file, 'r') as f:
                import json
                config = json.load(f)
                return config
        except Exception as e:
            from loguru import logger
            logger.error(f"Error loading config from {config_file}: {e}")
            logger.info("Using default configuration")
            
    return DEFAULT_CONFIG
