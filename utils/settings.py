"""Application settings management."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict

from . import paths

try:
    from . import encryption
except ImportError:  # pragma: no cover
    encryption = None  # type: ignore


@dataclass
class AppSettings:
    reduced_motion: bool = False
    telemetry_opt_in: bool = False
    api_keys: Dict[str, str] = field(default_factory=dict)
    lab_mode_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reduced_motion": self.reduced_motion,
            "telemetry_opt_in": self.telemetry_opt_in,
            "api_keys": self.api_keys,
            "lab_mode_enabled": self.lab_mode_enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppSettings":
        return cls(
            reduced_motion=bool(data.get("reduced_motion", False)),
            telemetry_opt_in=bool(data.get("telemetry_opt_in", False)),
            api_keys=dict(data.get("api_keys", {})),
            lab_mode_enabled=bool(data.get("lab_mode_enabled", False)),
        )


def load_settings() -> AppSettings:
    settings_path = paths.get_settings_path()
    if not settings_path.exists():
        return AppSettings()
    if encryption is None:
        raise RuntimeError(
            "cryptography is required to load settings. Install dependencies "
            "with 'python -m pip install -r requirements.txt' or run "
            "scripts\\install.bat first."
        )
    blob = settings_path.read_bytes()
    data = encryption.decrypt_json(blob)
    return AppSettings.from_dict(data)


def save_settings(settings: AppSettings) -> None:
    if encryption is None:
        raise RuntimeError(
            "cryptography is required to save settings. Install dependencies "
            "with 'python -m pip install -r requirements.txt' or run "
            "scripts\\install.bat first."
        )
    payload = settings.to_dict()
    blob = encryption.encrypt_json(payload)
    paths.get_settings_path().write_bytes(blob)
