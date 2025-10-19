"""Report export utilities for WHOIS Watching."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

try:
    from cryptography.fernet import Fernet
except ImportError:  # pragma: no cover
    Fernet = None  # type: ignore

from .hashing import sha256_bytes


class ReportExporter:
    def __init__(self, base_path: Path) -> None:
        self.base_path = base_path
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _build_metadata(self, tag: str) -> Dict[str, Any]:
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "tag": tag,
        }

    def export_summary(self, data: Dict[str, Any], tag: str = "summary") -> Path:
        payload = {"metadata": self._build_metadata(tag), "data": data}
        path = self.base_path / f"report_{tag}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def export_encrypted(self, data: Dict[str, Any], tag: str = "full") -> Path:
        if Fernet is None:
            raise RuntimeError("cryptography is required to export encrypted reports")
        payload = json.dumps({"metadata": self._build_metadata(tag), "data": data}).encode("utf-8")
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(payload)
        path = self.base_path / f"report_{tag}.enc"
        path.write_bytes(encrypted)
        checksum = sha256_bytes(encrypted)
        (self.base_path / f"report_{tag}.key").write_text(key.decode("ascii"), encoding="utf-8")
        (self.base_path / f"report_{tag}.sha256").write_text(checksum, encoding="utf-8")
        return path

    def export_html(self, data: Dict[str, Any], tag: str = "summary") -> Path:
        path = self.base_path / f"report_{tag}.html"
        style = (
            "<style>body{font-family:Segoe UI, sans-serif;background:#0b0320;color:#f5f5ff;padding:2rem;}"
            "h1{color:#9b5cff;}table{width:100%;border-collapse:collapse;}td,th{border:1px solid #4a2b6f;padding:0.5rem;}"
            "</style>"
        )
        content = [
            "<html><head><meta charset='utf-8'><title>WHOIS Watching Report</title>",
            style,
            "</head><body>",
            "<h1>WHOIS Watching Report</h1>",
            f"<p>Generated: {self._build_metadata(tag)['generated_at']}</p>",
            "<pre>" + json.dumps(data, indent=2) + "</pre>",
            "</body></html>",
        ]
        path.write_text("".join(content), encoding="utf-8")
        return path
