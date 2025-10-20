"""Downloads folder correlation utilities."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

from utils.hashing import sha256_file


@dataclass
class DownloadCandidate:
    path: Path
    sha256: str


class DownloadCorrelator:
    def __init__(self, downloads_dir: Path | None = None) -> None:
        self.downloads_dir = downloads_dir or self._default_downloads()

    def _default_downloads(self) -> Path:
        base = Path(os.path.expanduser("~"))
        return base / "Downloads"

    def iter_candidates(self) -> Iterable[DownloadCandidate]:
        directory = self.downloads_dir
        if not directory.exists():
            return []
        for path in directory.glob("**/*"):
            if path.is_file():
                yield DownloadCandidate(path=path, sha256=sha256_file(path))

    def match_process(self, process_sha: str) -> List[DownloadCandidate]:
        matches: List[DownloadCandidate] = []
        for candidate in self.iter_candidates() or []:
            if candidate.sha256 == process_sha:
                matches.append(candidate)
        return matches

    def summary(self) -> List[Dict[str, str]]:
        return [
            {"path": str(candidate.path), "sha256": candidate.sha256}
            for candidate in self.iter_candidates() or []
        ]
