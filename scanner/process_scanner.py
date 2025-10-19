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
    def __init__(
        self,
        include_hash: bool = True,
        include_modules: bool = False,
        include_connections: bool = True,
        max_connections: int = 12,
    ) -> None:
        self.include_hash = include_hash
        self.include_modules = include_modules
        self.include_connections = include_connections
        self.max_connections = max_connections
        self._hash_cache: Dict[str, Optional[str]] = {}

    def _safe_hash(self, path: str) -> Optional[str]:
        if not path:
            return None
        cached = self._hash_cache.get(path)
        if cached is not None:
            return cached
        try:
            if Path(path).exists():
                digest = sha256_file(Path(path))
                self._hash_cache[path] = digest
                return digest
        except (OSError, PermissionError):
            pass
        self._hash_cache[path] = None
        return None

    def list_processes(self, limit: Optional[int] = None) -> Iterable[ProcessInfo]:
        count = 0
        for proc in psutil.process_iter(
            attrs=["pid", "ppid", "name", "username", "create_time", "exe", "cmdline", "status"]
        ):
            try:
                info = proc.info
                exe = info.get("exe") or ""
                dlls: List[str] | None = None
                if self.include_modules and hasattr(proc, "memory_maps"):
                    try:
                        dlls = [m.path for m in proc.memory_maps()[:20] if m.path]
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, psutil.Error):
                        dlls = []
                conns: List[Dict[str, str]] | None = None
                if self.include_connections:
                    collected = []
                    try:
                        for conn in proc.connections(kind="inet"):
                            collected.append(
                                {
                                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                                    "status": conn.status,
                                }
                            )
                            if len(collected) >= self.max_connections:
                                break
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, psutil.Error, NotImplementedError):
                        collected = []
                    conns = collected
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
                count += 1
                if limit is not None and count >= max(0, limit):
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.Error):
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
