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
QPlainTextEdit, QLineEdit {
    background-color: rgba(22, 10, 38, 0.82);
    border: 1px solid rgba(130, 95, 200, 0.35);
    border-radius: 10px;
    padding: 8px 12px;
    color: rgba(240, 225, 255, 0.92);
    selection-background-color: rgba(180, 130, 250, 0.5);
    selection-color: #ffffff;
}
QPlainTextEdit[readOnly="true"] {
    background-color: rgba(18, 8, 32, 0.7);
}
QCheckBox {
    color: rgba(220, 205, 255, 0.85);
    spacing: 8px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid rgba(140, 100, 210, 0.6);
    background: rgba(26, 12, 44, 0.9);
}
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(170, 120, 255, 0.9), stop:1 rgba(120, 70, 200, 0.9));
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
QTreeWidget {
    background-color: rgba(16, 6, 30, 0.92);
    border: 1px solid rgba(110, 75, 180, 0.4);
    border-radius: 12px;
    color: rgba(240, 230, 255, 0.92);
    selection-background-color: rgba(170, 120, 250, 0.45);
    alternate-background-color: rgba(30, 12, 55, 0.85);
}
QTreeWidget::item {
    padding: 6px 8px;
}
QHeaderView::section:horizontal {
    background-color: rgba(45, 20, 80, 0.9);
    border: none;
    color: rgba(235, 225, 255, 0.9);
    padding: 8px 6px;
}
"""


ASSETS = {
    "logo_svg": Path("assets/logo.svg"),
    "starfield": Path("assets/starfield.svg"),
}
