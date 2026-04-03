"""
Configuration loader for Sentinel Firewall.
Loads YAML config with defaults and runtime overrides.
"""

import os
import yaml
import logging
from pathlib import Path
from copy import deepcopy

logger = logging.getLogger("sentinel.config")

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default_config.yaml"


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base dict."""
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


class Config:
    """Singleton configuration manager."""

    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load(self, user_config_path: str = None):
        """Load default config, then overlay user config if provided."""
        # Load defaults
        with open(DEFAULT_CONFIG_PATH, "r") as f:
            self._config = yaml.safe_load(f)

        # Overlay user config
        if user_config_path and os.path.exists(user_config_path):
            with open(user_config_path, "r") as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    self._config = deep_merge(self._config, user_config)
            logger.info(f"Loaded user config from {user_config_path}")
        else:
            logger.info("Using default configuration")

        return self

    def get(self, *keys, default=None):
        """Get a nested config value using dot-separated keys or varargs.

        Usage:
            config.get("dns_filter", "listen_port")
            config.get("ids", "enabled")
        """
        current = self._config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    @property
    def raw(self) -> dict:
        return deepcopy(self._config)

    def __repr__(self):
        return f"Config({list(self._config.keys())})"
