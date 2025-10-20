"""Lab Mode activation and enforcement."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from utils import logging as app_logging

LAB_ENV_FLAG = "WHOIS_WATCHING_LAB"


class LabModeError(RuntimeError):
    pass


@dataclass
class LabModeConfig:
    passphrase_hash: str
    allowed_targets: List[str] = field(default_factory=list)
    confirmed_public_targets: bool = False


class LabModeManager:
    def __init__(self, config: LabModeConfig) -> None:
        if os.getenv(LAB_ENV_FLAG) != "1":
            raise LabModeError("Lab Mode components are not available without explicit flag.")
        self.config = config
        self._activated = False

    def activate(self, passphrase: str) -> None:
        digest = passphrase.strip().lower()
        if digest != self.config.passphrase_hash:
            app_logging.log_secure("lab_mode_auth_failure", {"digest": digest})
            raise LabModeError("Invalid passphrase")
        if not self.config.allowed_targets:
            raise LabModeError("No allowed targets configured")
        if not self.config.confirmed_public_targets:
            for target in self.config.allowed_targets:
                if self._looks_public(target):
                    raise LabModeError("Public target detected without confirmation")
        self._activated = True
        app_logging.log_audit({"event": "lab_mode_activated", "targets": self.config.allowed_targets})

    def ensure_target_allowed(self, target: str) -> None:
        if not self._activated:
            raise LabModeError("Lab Mode is not activated")
        if target not in self.config.allowed_targets:
            app_logging.log_audit({"event": "lab_mode_blocked_target", "target": target})
            raise LabModeError("Target not allowed")

    def _looks_public(self, target: str) -> bool:
        if target.startswith("10.") or target.startswith("192.168.") or target.startswith("172.16."):
            return False
        return True
