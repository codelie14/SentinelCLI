"""
SentinelCLI Configuration Manager
Manages mode (offline/online) and API keys
"""

import json
import os
from typing import Any, Dict, Optional

CONFIG_FILE = "sentinel_config.json"

DEFAULT_CONFIG = {
    "mode": "offline",
    "api_keys": {
        "virustotal": "",
        "otx": "",
    },
    "notifications": {
        "slack_webhook": "",
        "discord_webhook": "",
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "email_to": "",
    },
    "rest_api": {
        "host": "127.0.0.1",
        "port": 5000,
        "enabled": False,
    },
    "cloud_backup": {
        "endpoint_url": "",
        "enabled": False,
    },
    "geo_intel": {
        "high_risk_countries": ["CN", "RU", "KP", "IR", "SY"],
    },
    "notifications_threshold": "HIGH",  # LOW, MEDIUM, HIGH, CRITICAL
}


class SentinelConfig:
    """Persistent configuration for SentinelCLI"""

    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self._config: Dict[str, Any] = {}
        self.load()

    def load(self):
        """Load config from disk, merge with defaults"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                # Deep merge saved over defaults
                self._config = self._deep_merge(DEFAULT_CONFIG.copy(), saved)
            except (json.JSONDecodeError, IOError):
                self._config = DEFAULT_CONFIG.copy()
        else:
            self._config = DEFAULT_CONFIG.copy()

    def save(self):
        """Persist config to disk"""
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(self._config, f, indent=2)

    def get(self, *keys, default=None) -> Any:
        """Get a nested config value using dot-path keys"""
        val = self._config
        for key in keys:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                return default
            if val is None:
                return default
        return val

    def set(self, *keys_and_value):
        """Set a nested config value. Last arg is the value."""
        keys = keys_and_value[:-1]
        value = keys_and_value[-1]
        d = self._config
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value
        self.save()

    @property
    def mode(self) -> str:
        return self._config.get("mode", "offline")

    @mode.setter
    def mode(self, value: str):
        if value not in ("offline", "online"):
            raise ValueError("Mode must be 'offline' or 'online'")
        self._config["mode"] = value
        self.save()

    @property
    def is_online(self) -> bool:
        return self.mode == "online"

    def _deep_merge(self, base: dict, override: dict) -> dict:
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                base[k] = self._deep_merge(base[k], v)
            else:
                base[k] = v
        return base
