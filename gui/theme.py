"""WHOIS Watching UI theme assets."""
from __future__ import annotations

from pathlib import Path

ROOT_CSS = """
#chrome {
    background: qradialgradient(cx:0.36, cy:0.25, radius:1.18,
        stop:0 rgba(110, 70, 200, 0.96),
        stop:0.45 rgba(60, 34, 110, 0.94),
        stop:0.8 rgba(20, 12, 45, 0.94),
        stop:1 rgba(6, 4, 18, 0.98));
    color: #E9E2FF;
    font-family: 'Segoe UI', 'Inter', sans-serif;
    border-radius: 26px;
}
#title {
    font-size: 34px;
    font-weight: 700;
    letter-spacing: 1px;
}
#subtitle {
    font-size: 16px;
    color: rgba(210, 190, 255, 0.78);
    font-weight: 400;
}
#summary {
    font-size: 18px;
    font-weight: 600;
    color: rgba(240, 225, 255, 0.9);
}
#loading {
    font-style: italic;
    color: rgba(200, 180, 255, 0.82);
}
QFrame#panel {
    background-color: rgba(18, 8, 38, 0.88);
    border: 1px solid rgba(150, 110, 230, 0.32);
    border-radius: 22px;
}
QPushButton {
    background-color: rgba(125, 84, 210, 0.78);
    border-radius: 12px;
    padding: 10px 26px;
    color: #F6F1FF;
    font-weight: 600;
    border: 1px solid rgba(150, 110, 220, 0.45);
}
QPushButton:hover {
    background-color: rgba(170, 120, 250, 0.88);
}
QPushButton:pressed {
    background-color: rgba(90, 50, 160, 0.92);
}
QPushButton:disabled {
    background-color: rgba(90, 60, 130, 0.35);
    color: rgba(220, 200, 255, 0.4);
}
QPlainTextEdit, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background-color: rgba(22, 10, 40, 0.84);
    border: 1px solid rgba(150, 110, 220, 0.32);
    border-radius: 12px;
    padding: 10px 14px;
    color: rgba(240, 230, 255, 0.94);
    selection-background-color: rgba(190, 140, 255, 0.5);
    selection-color: #ffffff;
}
QPlainTextEdit[readOnly="true"] {
    background-color: rgba(18, 8, 32, 0.78);
}
QComboBox QAbstractItemView {
    background-color: rgba(22, 10, 40, 0.94);
    border: 1px solid rgba(150, 110, 220, 0.32);
    selection-background-color: rgba(170, 120, 250, 0.45);
    color: rgba(240, 230, 255, 0.94);
}
QTextBrowser, QTextEdit {
    background-color: rgba(16, 6, 30, 0.88);
    border: 1px solid rgba(110, 80, 200, 0.35);
    border-radius: 12px;
    padding: 10px 14px;
    color: rgba(240, 230, 255, 0.94);
}
QTextBrowser#chatLog {
    background-color: rgba(12, 4, 24, 0.82);
    border: 1px solid rgba(160, 120, 255, 0.28);
}
QCheckBox {
    color: rgba(220, 205, 255, 0.85);
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 6px;
    border: 1px solid rgba(170, 130, 240, 0.55);
    background: rgba(26, 12, 44, 0.9);
}
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(190, 130, 255, 0.92), stop:1 rgba(130, 80, 220, 0.92));
}
QSlider#scanSlider::groove:horizontal {
    height: 8px;
    background: rgba(70, 40, 120, 0.65);
    border-radius: 4px;
}
QSlider#scanSlider::handle:horizontal {
    background: rgba(210, 180, 255, 0.9);
    border: 2px solid rgba(140, 90, 220, 0.85);
    width: 22px;
    margin: -7px 0;
    border-radius: 11px;
    box-shadow: 0 0 12px rgba(180, 120, 255, 0.65);
}
QSlider#scanSlider::handle:horizontal:hover {
    background: rgba(235, 210, 255, 0.95);
}
QSlider#scanSlider::sub-page:horizontal {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(160, 110, 240, 0.9), stop:1 rgba(120, 70, 210, 0.9));
    border-radius: 4px;
}
QSlider#scanSlider::add-page:horizontal {
    background: rgba(40, 18, 68, 0.7);
    border-radius: 4px;
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


NAVIGATION_CSS = """
QPushButton#navButton {
    background-color: transparent;
    border: 1px solid rgba(180, 140, 255, 0.0);
    border-radius: 14px;
    color: rgba(220, 205, 255, 0.82);
    padding: 12px 24px;
    font-weight: 600;
}
QPushButton#navButton:hover {
    background-color: rgba(120, 70, 210, 0.35);
}
QPushButton#navButton:checked {
    background-color: rgba(190, 140, 255, 0.38);
    color: #ffffff;
    border: 1px solid rgba(200, 160, 255, 0.6);
}
"""


TITLE_BAR_CSS = """
QFrame#titleBar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(38, 16, 68, 0.92), stop:1 rgba(14, 6, 26, 0.95));
    border-top-left-radius: 26px;
    border-top-right-radius: 26px;
}
QToolButton#windowControl {
    background: rgba(120, 70, 210, 0.35);
    border-radius: 12px;
    padding: 6px 10px;
    color: rgba(240, 230, 255, 0.92);
    border: 1px solid rgba(160, 110, 240, 0.3);
}
QToolButton#windowControl:hover {
    background: rgba(190, 130, 255, 0.5);
}
QToolButton#windowControl:pressed {
    background: rgba(90, 40, 160, 0.65);
}
QLabel#connectionIndicator {
    padding: 6px 16px;
    border-radius: 16px;
    font-weight: 600;
    border: 1px solid rgba(140, 100, 210, 0.45);
}
QLabel#connectionIndicator[state="offline"] {
    background: rgba(40, 16, 70, 0.82);
    color: rgba(200, 170, 240, 0.85);
}
QLabel#connectionIndicator[state="warning"] {
    background: rgba(120, 70, 30, 0.85);
    color: rgba(250, 220, 190, 0.92);
    border: 1px solid rgba(255, 200, 150, 0.6);
}
QLabel#connectionIndicator[state="online"] {
    background: rgba(48, 24, 96, 0.92);
    color: rgba(220, 210, 255, 0.98);
    border: 1px solid rgba(180, 150, 255, 0.72);
    box-shadow: 0 0 18px rgba(150, 110, 255, 0.55);
}
"""


PROCESS_MENU_CSS = """
QMenu#processMenu {
    background: rgba(30, 12, 60, 0.96);
    border: 1px solid rgba(190, 150, 255, 0.45);
    border-radius: 16px;
    padding: 12px;
}
QMenu#processMenu::item {
    padding: 10px 18px;
    border-radius: 10px;
    background-color: transparent;
    color: rgba(235, 225, 255, 0.86);
}
QMenu#processMenu::item:selected {
    background: rgba(150, 100, 230, 0.45);
    color: #ffffff;
}
QMenu#processMenu::separator {
    height: 1px;
    background: rgba(160, 110, 240, 0.4);
    margin: 6px 4px;
}
"""


DIALOG_CSS = """
QFrame#dialogFrame {
    background: rgba(18, 8, 36, 0.95);
    border: 1px solid rgba(170, 130, 250, 0.4);
    border-radius: 24px;
    color: rgba(240, 230, 255, 0.94);
}
QLabel#dialogTitle {
    font-size: 22px;
    font-weight: 600;
}
QLabel#dialogSubtitle {
    color: rgba(210, 195, 250, 0.75);
}
"""


ASSETS = {
    "logo_svg": Path("assets/logo.svg"),
    "starfield": Path("assets/starfield.svg"),
}
