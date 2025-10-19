"""WHOIS Watching UI theme assets."""
from __future__ import annotations

from pathlib import Path

GRADIENT_CSS = """
QWidget {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #200047,
        stop:0.5 #1a1045,
        stop:1 #05030f);
    color: #f8f3ff;
}
QPushButton {
    background-color: rgba(90, 54, 140, 180);
    border-radius: 6px;
    padding: 8px 14px;
    color: #ffffff;
    font-weight: 600;
}
QPushButton:hover {
    background-color: rgba(130, 80, 190, 200);
}
QPushButton:pressed {
    background-color: rgba(70, 30, 120, 200);
}
"""


ASSETS = {
    "logo_svg": Path("assets/logo.svg"),
    "starfield": Path("assets/starfield.svg"),
}
