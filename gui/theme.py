"""WHOIS Watching UI theme assets."""
from __future__ import annotations

from pathlib import Path

ROOT_CSS = """
#root {
    background: qradialgradient(cx:0.25, cy:0.2, radius:1.2,
        stop:0 #4b1d7a,
        stop:0.4 #2c1458,
        stop:1 #05030f);
    color: #E9E2FF;
    font-family: 'Segoe UI', 'Inter', sans-serif;
}
#title {
    font-size: 34px;
    font-weight: 700;
    letter-spacing: 1px;
}
#subtitle {
    font-size: 16px;
    color: rgba(210, 190, 255, 0.75);
    font-weight: 400;
}
#summary {
    font-size: 18px;
    font-weight: 600;
    color: rgba(240, 225, 255, 0.9);
}
#loading {
    font-style: italic;
    color: rgba(200, 180, 255, 0.8);
}
QFrame#panel {
    background-color: rgba(20, 8, 40, 0.78);
    border: 1px solid rgba(140, 90, 200, 0.35);
    border-radius: 22px;
}
QPushButton {
    background-color: rgba(115, 74, 190, 0.72);
    border-radius: 10px;
    padding: 10px 22px;
    color: #F6F1FF;
    font-weight: 600;
    border: 1px solid rgba(120, 90, 200, 0.45);
}
QPushButton:hover {
    background-color: rgba(150, 100, 220, 0.88);
}
QPushButton:pressed {
    background-color: rgba(90, 50, 160, 0.9);
}
QPushButton:disabled {
    background-color: rgba(90, 60, 130, 0.35);
    color: rgba(220, 200, 255, 0.4);
}
QStatusBar {
    background: rgba(8, 3, 18, 0.6);
    color: rgba(220, 205, 255, 0.8);
    border-top: 1px solid rgba(110, 70, 160, 0.4);
}
"""

TABLE_CSS = """
QTableWidget {
    background-color: rgba(16, 6, 30, 0.9);
    alternate-background-color: rgba(32, 14, 60, 0.85);
    border: 1px solid rgba(100, 70, 160, 0.4);
    border-radius: 12px;
    color: #F3EDFF;
    gridline-color: rgba(120, 90, 200, 0.3);
    selection-background-color: rgba(160, 110, 240, 0.5);
    selection-color: #ffffff;
}
QHeaderView::section {
    background-color: rgba(45, 20, 80, 0.9);
    color: rgba(235, 225, 255, 0.9);
    border: none;
    padding: 10px 6px;
    font-weight: 600;
}
QTableCornerButton::section {
    background-color: transparent;
    border: none;
}
"""


ASSETS = {
    "logo_svg": Path("assets/logo.svg"),
    "starfield": Path("assets/starfield.svg"),
}
