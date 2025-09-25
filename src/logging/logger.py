"""
Core logging configuration and setup for ArgusPI v2
"""

import os
import logging
import logging.handlers
from pathlib import Path
import colorlog
import yaml


def setup_logging(config_path=None):
    """Setup logging configuration"""
    # Load configuration
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent / "config" / "default.yaml"
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    log_config = config.get('logging', {})
    
    # Create logs directory if it doesn't exist
    log_dir = Path(__file__).parent.parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    log_level = getattr(logging, log_config.get('level', 'INFO'))
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # File handler with rotation
    log_file = log_dir / "arguspi.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=_parse_size(log_config.get('max_size', '10M')),
        backupCount=log_config.get('backup_count', 5)
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler with colors (if enabled)
    if log_config.get('console_output', True):
        console_handler = colorlog.StreamHandler()
        console_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    logging.info("Logging system initialized")


def _parse_size(size_str):
    """Parse size string like '10M' to bytes"""
    size_str = size_str.upper()
    if size_str.endswith('K'):
        return int(size_str[:-1]) * 1024
    elif size_str.endswith('M'):
        return int(size_str[:-1]) * 1024 * 1024
    elif size_str.endswith('G'):
        return int(size_str[:-1]) * 1024 * 1024 * 1024
    else:
        return int(size_str)


def get_logger(name):
    """Get a logger with the specified name"""
    return logging.getLogger(name)