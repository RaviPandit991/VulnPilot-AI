"""Configuration loader for VulnPilot AI."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


class Settings:
    """Lightweight wrapper around the YAML config with dotted-key access."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Settings":
        config_path = Path(path) if path else _DEFAULT_CONFIG_PATH
        with open(config_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(data)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> Dict[str, Any]:
        return dict(self._data.get(name, {}))

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._data)


# Singleton-style accessor
_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings
