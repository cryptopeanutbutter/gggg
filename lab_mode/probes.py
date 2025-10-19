"""Non-destructive lab probes."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import List

from utils import logging as app_logging

from .manager import LabModeManager, LabModeError


@dataclass
class ProbeResult:
    target: str
    port: int
    status: str
    banner: str = ""


class ProbeExecutor:
    def __init__(self, manager: LabModeManager, timeout: float = 2.0) -> None:
        self.manager = manager
        self.timeout = timeout

    def tcp_probe(self, target: str, port: int) -> ProbeResult:
        self.manager.ensure_target_allowed(target)
        app_logging.log_audit({"event": "lab_tcp_probe", "target": target, "port": port})
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.connect((target, port))
                banner = self._safe_banner(sock)
                status = "open"
            except socket.timeout:
                status = "timeout"
                banner = ""
            except OSError:
                status = "closed"
                banner = ""
        return ProbeResult(target=target, port=port, status=status, banner=banner)

    def service_inventory(self, target: str, ports: List[int]) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        for port in ports:
            results.append(self.tcp_probe(target, port))
        return results

    def _safe_banner(self, sock: socket.socket) -> str:
        try:
            data = sock.recv(128)
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return ""
