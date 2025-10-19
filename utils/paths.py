"""Application path management for WHOIS Watching."""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "WHOIS_Watching"


def get_local_app_data() -> Path:
    """Return platform-appropriate local app data path."""
    base = os.getenv("LOCALAPPDATA")
    if base:
        return Path(base)
    # Fallback for non-Windows development environments
    home = Path.home()
    return home / ".local" / "share"


def get_app_storage() -> Path:
    """Return storage directory for encrypted logs and configs."""
    path = get_local_app_data() / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_log_path(filename: str) -> Path:
    return get_app_storage() / filename


def get_encrypted_log_path() -> Path:
    return get_log_path("secure_logs.enc")


def get_audit_log_path() -> Path:
    return get_log_path("lab_audit.enc")


def get_cache_path() -> Path:
    path = get_app_storage() / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_settings_path() -> Path:
    return get_log_path("settings.enc")


def get_manifest_template_path() -> Path:
    return Path(__file__).resolve().parent.parent / "compiled" / "build_manifest.template.json"
