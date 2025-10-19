"""Process scanning utilities."""
from __future__ import annotations

import datetime as _dt
import json
import platform
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import psutil

from utils.hashing import sha256_file


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    username: str
    create_time: float
    exe: str
    cmdline: List[str]
    status: str
    integrity: str
    sha256: Optional[str] = None
    signed: Optional[bool] = None
    dlls: Optional[List[str]] = None
    connections: Optional[List[Dict[str, str]]] = None

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["create_time_iso"] = _dt.datetime.fromtimestamp(self.create_time).isoformat()
        return data


class ProcessScanner:
    def __init__(self, include_hash: bool = True) -> None:
        self.include_hash = include_hash

    def _safe_hash(self, path: str) -> Optional[str]:
        try:
            if path and Path(path).exists():
                return sha256_file(Path(path))
        except (OSError, PermissionError):
            return None
        return None

    def list_processes(self) -> Iterable[ProcessInfo]:
        for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "username", "create_time", "exe", "cmdline", "status"]):
            try:
                info = proc.info
                exe = info.get("exe") or ""
                dlls = []
                if hasattr(proc, "memory_maps"):
                    try:
                        dlls = [m.path for m in proc.memory_maps()[:20] if m.path]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        dlls = []
                conns = []
                try:
                    for conn in proc.connections(kind="inet"):
                        conns.append(
                            {
                                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                                "status": conn.status,
                            }
                        )
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    conns = []
                sha = self._safe_hash(exe) if self.include_hash else None
                cmdline = info.get("cmdline") or []
                if not isinstance(cmdline, (list, tuple)):
                    cmdline = [str(cmdline)] if cmdline else []

                yield ProcessInfo(
                    pid=info["pid"],
                    ppid=info.get("ppid", 0),
                    name=info.get("name", ""),
                    username=info.get("username", "unknown"),
                    create_time=info.get("create_time", 0.0) or 0.0,
                    exe=exe,
                    cmdline=list(cmdline),
                    status=info.get("status", ""),
                    integrity=self._detect_integrity(proc),
                    sha256=sha,
                    signed=self._stub_signature_check(exe),
                    dlls=dlls,
                    connections=conns,
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _detect_integrity(self, proc: psutil.Process) -> str:
        if platform.system() != "Windows":
            return "unknown"
        try:
            return "high" if proc.uids().real == 0 else "medium"
        except Exception:
            return "unknown"

    def _stub_signature_check(self, path: str) -> Optional[bool]:
        if not path:
            return None
        # Placeholder for Windows signature verification; real implementation uses win32 APIs.
        return None

    def export_snapshot(self, target: Path) -> Path:
        data = [proc.to_dict() for proc in self.list_processes()]
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return target
