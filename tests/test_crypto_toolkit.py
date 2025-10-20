from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from utils import crypto_toolkit


def test_encrypt_decrypt_roundtrip():
    package = crypto_toolkit.encrypt_text("hunter2", "secret")
    assert crypto_toolkit.decrypt_text("hunter2", package.package()) == "secret"


def test_file_encrypt_decrypt(tmp_path: Path):
    source = tmp_path / "sample.txt"
    source.write_text("confidential", encoding="utf-8")
    encrypted = tmp_path / "sample.txt.enc"
    crypto_toolkit.encrypt_file("passphrase", source, encrypted)
    restored = tmp_path / "restored.txt"
    crypto_toolkit.decrypt_file("passphrase", encrypted, restored)
    assert restored.read_text(encoding="utf-8") == "confidential"


def test_generate_passphrase_entropy():
    token = crypto_toolkit.generate_passphrase()
    assert len(token) == 16
    assert token != crypto_toolkit.generate_passphrase()
