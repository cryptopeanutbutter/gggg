"""Build manifest utilities for install script interoperability."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def create_manifest(
    output_path: Path,
    *,
    version: str,
    build_id: str,
    python_version: str,
    dependencies: List[str],
    artifacts: Dict[str, str],
) -> None:
    payload = {
        "app": "WHOIS Watching",
        "version": version,
        "build_id": build_id,
        "python_version": python_version,
        "built_at": datetime.utcnow().isoformat() + "Z",
        "dependencies": dependencies,
        "artifacts": artifacts,
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
