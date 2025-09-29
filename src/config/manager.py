"""
Configuration management for ArgusPI v2
"""

import os
import logging
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

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
        value, _ = self.get_with_override(key, default)
        return value

    def get_with_override(self, key: str, default=None) -> Tuple[Any, bool]:
        """Return a configuration value and whether an environment override was applied."""
        keys = key.split('.') if key else []
        value: Any = self._config
        value_missing = False

        for part in keys:
            if isinstance(value, dict) and part in value:
                value = value[part]
                continue
            if isinstance(value, list):
                try:
                    index = int(part)
                except ValueError:
                    value_missing = True
                    value = default
                    break
                if 0 <= index < len(value):
                    value = value[index]
                    continue
            value_missing = True
            value = default
            break

        return self._apply_env_override(keys, value, default, value_missing)

    def _apply_env_override(
        self,
        keys: Sequence[str],
        current_value: Any,
        default: Any,
        value_missing: bool,
    ) -> Tuple[Any, bool]:
        env_value = self._lookup_env_override(keys)
        if env_value is None:
            return current_value, False

        template = current_value if not value_missing else default
        success, coerced = self._coerce_env_value(env_value, template)
        if not success:
            return current_value, False
        return coerced, True

    def _lookup_env_override(self, keys: Sequence[str]) -> Optional[str]:
        if not keys:
            return None
        parts = [str(k).upper() for k in keys]
        nested_key = "__".join(parts)
        candidates = [
            "_".join(["ARGUS"] + parts),
            f"ARGUS_{nested_key}",
            f"ARGUS__{nested_key}",
        ]
        for candidate in candidates:
            if candidate in os.environ:
                return os.environ[candidate]
        return None

    @staticmethod
    def _coerce_env_value(raw_value: str, template: Any) -> Tuple[bool, Any]:
        if isinstance(template, bool):
            lowered = raw_value.strip().lower()
            if lowered in {'true', '1', 'yes', 'on', 'y', 't'}:
                return True, True
            if lowered in {'false', '0', 'no', 'off', 'n', 'f'}:
                return True, False
            return False, template

        if isinstance(template, int) and not isinstance(template, bool):
            try:
                return True, int(raw_value.strip(), 0)
            except ValueError:
                return False, template

        if isinstance(template, float):
            try:
                return True, float(raw_value.strip())
            except ValueError:
                return False, template

        if isinstance(template, list):
            try:
                parsed = yaml.safe_load(raw_value)
            except yaml.YAMLError:
                return False, template
            if isinstance(parsed, list):
                return True, parsed
            return False, template

        if isinstance(template, dict):
            try:
                parsed = yaml.safe_load(raw_value)
            except yaml.YAMLError:
                return False, template
            if isinstance(parsed, dict):
                return True, parsed
            return False, template

        if template is None:
            try:
                parsed = yaml.safe_load(raw_value)
            except yaml.YAMLError:
                return True, raw_value
            return True, parsed

        return True, raw_value
    
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
