"""WHOIS/IP context lookups (opt-in)."""
from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Dict, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

from utils import logging as app_logging

WHOIS_API = "https://rdap.arin.net/registry/ip/{}"


@dataclass
class ContextResult:
    query: str
    data: Dict[str, object]


class ContextLookup:
    def __init__(self, session: Optional[requests.Session] = None) -> None:
        if requests is None:
            raise RuntimeError("requests is required for WHOIS lookups")
        self.session = session or requests.Session()
        self.cache: Dict[str, ContextResult] = {}

    def lookup_ip(self, ip_address: str) -> ContextResult:
        if ip_address in self.cache:
            return self.cache[ip_address]
        app_logging.logger.info("Context lookup requested for %s", ip_address)
        response = self.session.get(WHOIS_API.format(ip_address), timeout=10)
        response.raise_for_status()
        data = response.json()
        result = ContextResult(query=ip_address, data=data)
        self.cache[ip_address] = result
        return result

    def reverse_dns(self, ip_address: str) -> Dict[str, str]:
        try:
            name, _, _ = socket.gethostbyaddr(ip_address)
            return {"ip": ip_address, "hostname": name}
        except socket.herror:
            return {"ip": ip_address, "hostname": "unknown"}

    def serialize(self, result: ContextResult) -> str:
        return json.dumps(result.data, indent=2)
