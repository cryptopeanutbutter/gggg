"""Utility exports for WHOIS Watching."""
from __future__ import annotations

from . import paths
from .build_manifest import create_manifest
from .hashing import sha256_file, sha256_bytes, aggregate_hash
from .logging import logger, log_secure, log_audit
from .reporting import ReportExporter
from .settings import AppSettings, load_settings, save_settings

try:  # Optional during minimal test environments
    from .encryption import encrypt_json, decrypt_json, encrypt_text, decrypt_text
except ImportError:  # pragma: no cover - fallback for missing cryptography
    def _missing(*_args, **_kwargs):  # type: ignore
        raise RuntimeError("cryptography is required for encryption features")

    encrypt_json = decrypt_json = encrypt_text = decrypt_text = _missing  # type: ignore

__all__ = [
    "paths",
    "create_manifest",
    "encrypt_json",
    "decrypt_json",
    "encrypt_text",
    "decrypt_text",
    "sha256_file",
    "sha256_bytes",
    "aggregate_hash",
    "logger",
    "log_secure",
    "log_audit",
    "ReportExporter",
    "AppSettings",
    "load_settings",
    "save_settings",
]
