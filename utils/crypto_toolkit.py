"""End-user encryption utilities for WHOIS Watching."""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

_SALT_SIZE = 16
_ITERATIONS = 200_000


@dataclass
class EncryptionResult:
    """Result payload for encryption operations."""

    token: str
    salt: str

    def package(self) -> str:
        return f"{self.salt}:{self.token}"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValueError("Passphrase is required")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_text(passphrase: str, plaintext: str) -> EncryptionResult:
    """Encrypt plaintext with a human supplied passphrase."""

    if not plaintext:
        raise ValueError("No plaintext provided")
    salt = os.urandom(_SALT_SIZE)
    key = _derive_key(passphrase, salt)
    cipher = Fernet(key)
    token = cipher.encrypt(plaintext.encode("utf-8"))
    return EncryptionResult(
        token=base64.urlsafe_b64encode(token).decode("ascii"),
        salt=base64.urlsafe_b64encode(salt).decode("ascii"),
    )


def decrypt_text(passphrase: str, package: str) -> str:
    """Decrypt a package created by :func:`encrypt_text`."""

    if ":" not in package:
        raise ValueError("Encrypted payload is malformed")
    salt_b64, token_b64 = package.split(":", 1)
    salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
    token = base64.urlsafe_b64decode(token_b64.encode("ascii"))
    key = _derive_key(passphrase, salt)
    cipher = Fernet(key)
    decrypted = cipher.decrypt(token)
    return decrypted.decode("utf-8")


def encrypt_file(passphrase: str, source: Path, destination: Path) -> EncryptionResult:
    data = source.read_bytes()
    result = encrypt_text(passphrase, base64.urlsafe_b64encode(data).decode("ascii"))
    destination.write_text(result.package(), encoding="utf-8")
    return result


def decrypt_file(passphrase: str, source: Path, destination: Path) -> Tuple[str, Path]:
    package = source.read_text(encoding="utf-8")
    decoded = decrypt_text(passphrase, package)
    blob = base64.urlsafe_b64decode(decoded.encode("ascii"))
    destination.write_bytes(blob)
    return package, destination


def generate_passphrase(length: int = 16) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(alphabet[b % len(alphabet)] for b in os.urandom(length))
