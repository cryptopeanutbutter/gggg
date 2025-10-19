"""PyQt5 main window for WHOIS Watching."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from PyQt5 import QtCore, QtGui, QtWidgets

from heuristics.engine import HeuristicEngine, HeuristicSignal
from scanner.process_scanner import ProcessScanner, ProcessInfo
from scanner.downloads import DownloadCorrelator
from utils import reporting, settings
from . import theme


class AnimatedButton(QtWidgets.QPushButton):
    clickedRipple = QtCore.pyqtSignal()

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        super().mousePressEvent(event)
        self.clickedRipple.emit()


class ProcessTable(QtWidgets.QTableWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        headers = [
            "PID",
            "Name",
            "User",
            "Integrity",
            "Confidence",
            "Probable Cause",
        ]
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

    def update_rows(self, rows: List[Dict[str, str]]) -> None:
        self.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for col_index, key in enumerate(["pid", "name", "user", "integrity", "confidence", "cause"]):
                item = QtWidgets.QTableWidgetItem(str(row.get(key, "")))
                item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
                self.setItem(row_index, col_index, item)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("WHOIS Watching")
        self.setMinimumSize(1200, 720)
        self.settings = settings.load_settings()
        self.heuristics = HeuristicEngine()
        self.scanner = ProcessScanner()
        self.correlator = DownloadCorrelator()
        self.reporter = reporting.ReportExporter(Path.home() / "WHOIS_Watching" / "reports")

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)
        central.setStyleSheet(theme.GRADIENT_CSS)

        header = QtWidgets.QLabel("WHOIS Watching – Defensive Process Intelligence")
        header.setAlignment(QtCore.Qt.AlignCenter)
        header.setStyleSheet("font-size: 24px; font-weight: 600; letter-spacing: 1px;")
        layout.addWidget(header)

        self.table = ProcessTable()
        layout.addWidget(self.table)

        button_row = QtWidgets.QHBoxLayout()
        self.refresh_btn = AnimatedButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_data)
        button_row.addWidget(self.refresh_btn)

        self.export_btn = AnimatedButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        button_row.addWidget(self.export_btn)

        self.settings_btn = AnimatedButton("Settings")
        self.settings_btn.clicked.connect(self.toggle_settings)
        button_row.addWidget(self.settings_btn)

        button_row.addStretch()
        layout.addLayout(button_row)

        self.status_bar = self.statusBar()
        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(8000)
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start()
        self.refresh_data()

    def _build_rows(self, processes: List[ProcessInfo]) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for process in processes:
            signals = self._signals_for_process(process)
            confidence, cause = self.heuristics.evaluate(signals)
            rows.append(
                {
                    "pid": str(process.pid),
                    "name": process.name,
                    "user": process.username,
                    "integrity": process.integrity,
                    "confidence": f"{confidence}%",
                    "cause": cause,
                }
            )
        return rows

    def _signals_for_process(self, process: ProcessInfo) -> List[HeuristicSignal]:
        signals: List[HeuristicSignal] = []
        if process.signed is False or process.signed is None:
            signals.append(
                HeuristicSignal(
                    name="unsigned_binary",
                    weight=1.0,
                    score=0.6,
                    rationale="Signature unavailable",
                )
            )
        if process.cmdline and any(arg.lower().startswith("http") for arg in process.cmdline):
            signals.append(
                HeuristicSignal(
                    name="suspicious_command",
                    weight=1.0,
                    score=0.7,
                    rationale="Command line launches remote resource",
                )
            )
        if process.connections:
            signals.append(
                HeuristicSignal(
                    name="network_activity",
                    weight=1.1,
                    score=min(1.0, 0.5 + len(process.connections) * 0.1),
                    rationale=f"Active network endpoints: {len(process.connections)}",
                )
            )
        return signals

    def refresh_data(self) -> None:
        processes = list(self.scanner.list_processes())
        rows = self._build_rows(processes)
        self.table.update_rows(rows)
        self.status_bar.showMessage(f"Loaded {len(rows)} processes", 5000)

    def export_report(self) -> None:
        processes = [proc.to_dict() for proc in self.scanner.list_processes()]
        downloads = self.correlator.summary()
        data = {"processes": processes, "downloads": downloads}
        summary_path = self.reporter.export_summary(data, tag="ui")
        encrypted_path = self.reporter.export_encrypted(data, tag="ui")
        self.status_bar.showMessage(f"Report saved to {summary_path} and {encrypted_path}", 10000)

    def toggle_settings(self) -> None:
        self.settings.reduced_motion = not self.settings.reduced_motion
        settings.save_settings(self.settings)
        state = "enabled" if self.settings.reduced_motion else "disabled"
        self.status_bar.showMessage(f"Reduced motion {state}", 5000)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:  # noqa: N802
        self.timer.stop()
        super().closeEvent(event)
