"""Scanner package."""
from __future__ import annotations

from .downloads import DownloadCorrelator, DownloadCandidate

try:  # Optional when requests is unavailable
    from .context import ContextLookup, ContextResult
except ImportError:  # pragma: no cover
    ContextLookup = ContextResult = None  # type: ignore

try:  # Optional when psutil is unavailable
    from .process_scanner import ProcessScanner, ProcessInfo
except ImportError:  # pragma: no cover
    ProcessScanner = ProcessInfo = None  # type: ignore

__all__ = [
    "ProcessScanner",
    "ProcessInfo",
    "DownloadCorrelator",
    "DownloadCandidate",
    "ContextLookup",
    "ContextResult",
]
