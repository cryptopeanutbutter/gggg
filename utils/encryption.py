"""Encryption helpers for WHOIS Watching."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Dict

from cryptography.fernet import Fernet

from . import paths

_KEY_FILE = paths.get_app_storage() / "key.bin"


def _load_or_create_key() -> bytes:
    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    _KEY_FILE.write_bytes(key)
    os.chmod(_KEY_FILE, 0o600)
    return key


def get_cipher() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt_json(data: Dict[str, Any]) -> bytes:
    cipher = get_cipher()
    payload = json.dumps(data).encode("utf-8")
    return cipher.encrypt(payload)


def decrypt_json(blob: bytes) -> Dict[str, Any]:
    cipher = get_cipher()
    payload = cipher.decrypt(blob)
    return json.loads(payload.decode("utf-8"))


def encrypt_file(data: bytes, path: Path) -> None:
    cipher = get_cipher()
    encrypted = cipher.encrypt(data)
    path.write_bytes(encrypted)
    os.chmod(path, 0o600)


def decrypt_file(path: Path) -> bytes:
    cipher = get_cipher()
    blob = path.read_bytes()
    return cipher.decrypt(blob)


def encrypt_text(text: str) -> str:
    cipher = get_cipher()
    encrypted = cipher.encrypt(text.encode("utf-8"))
    return base64.urlsafe_b64encode(encrypted).decode("ascii")


def decrypt_text(token: str) -> str:
    cipher = get_cipher()
    decrypted = cipher.decrypt(base64.urlsafe_b64decode(token))
    return decrypted.decode("utf-8")
