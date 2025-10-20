"""Structured logging utilities for WHOIS Watching."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from . import paths

try:  # Optional in minimal environments
    from . import encryption
except ImportError:  # pragma: no cover
    encryption = None  # type: ignore

_LOG_PATH = paths.get_log_path("app.log")

logger = logging.getLogger("whois_watching")
logger.setLevel(logging.INFO)

_handler = logging.FileHandler(_LOG_PATH, encoding="utf-8")
_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
_handler.setFormatter(_formatter)
logger.addHandler(_handler)


def log_secure(event: str, data: Dict[str, Any] | None = None) -> None:
    """Write encrypted logs for sensitive events."""
    if encryption is None:
        logger.warning("Secure logging requested but cryptography dependency is missing.")
        return
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": event,
        "data": data or {},
    }
    blob = encryption.encrypt_json(payload)
    encrypted_log = paths.get_encrypted_log_path()
    with encrypted_log.open("ab") as handle:
        handle.write(blob + b"\n")


def log_audit(entry: Dict[str, Any]) -> None:
    """Append lab-mode audit log entry."""
    if encryption is None:
        logger.warning("Audit logging requested but cryptography dependency is missing.")
        return
    entry = dict(entry)
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    blob = encryption.encrypt_json(entry)
    audit_path = paths.get_audit_log_path()
    with audit_path.open("ab") as handle:
        handle.write(blob + b"\n")


def serialize_for_manifest(data: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
