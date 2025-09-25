"""
Configuration management for ArgusPI v2
"""

import os
import logging
import yaml
from pathlib import Path
from typing import Dict, Any

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class Config:
    """Configuration manager with environment variable override support"""
    
    def __init__(self, config_file=None):
        self.config_file = config_file or Path(__file__).parent.parent.parent / "config" / "default.yaml"
        self._config = {}
        self.load()
    
    def load(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                self._config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def get(self, key: str, default=None) -> Any:
        """Get configuration value with dot notation support"""
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
        except (KeyError, TypeError):
            value = default
        
        # Check for environment variable override
        env_key = '_'.join(['ARGUS'] + [k.upper() for k in keys])
        env_value = os.getenv(env_key)
        if env_value is not None:
            # Try to convert to appropriate type
            if isinstance(value, bool):
                value = env_value.lower() in ('true', '1', 'yes', 'on')
            elif isinstance(value, int):
                try:
                    value = int(env_value)
                except ValueError:
                    pass
            elif isinstance(value, float):
                try:
                    value = float(env_value)
                except ValueError:
                    pass
            else:
                value = env_value
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, config_file=None):
        """Save configuration to file"""
        file_path = config_file or self.config_file
        try:
            with open(file_path, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise
    
    @property
    def data(self) -> Dict[str, Any]:
        """Get raw configuration data"""
        return self._config