"""PyQt5 main window for WHOIS Watching."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence

from PyQt5 import QtCore, QtGui, QtWidgets

from heuristics.engine import HeuristicEngine, HeuristicSignal
from scanner.process_scanner import ProcessScanner, ProcessInfo
from scanner.downloads import DownloadCorrelator
from utils import reporting, settings
from utils.hashing import DehashMatch, MultiDehasher
from . import theme


class AnimatedButton(QtWidgets.QPushButton):
    clickedRipple = QtCore.pyqtSignal()

    def __init__(self, text: str, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(text, parent)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self._glow = QtWidgets.QGraphicsDropShadowEffect(self)
        self._glow.setBlurRadius(8)
        self._glow.setOffset(0)
        self._glow.setColor(QtGui.QColor(150, 90, 255, 90))
        self.setGraphicsEffect(self._glow)
        self._pulse = QtCore.QVariantAnimation(
            self,
            startValue=0.0,
            endValue=1.0,
            duration=260,
        )
        self._pulse.valueChanged.connect(self._update_pulse)
        self._pulse.setEasingCurve(QtCore.QEasingCurve.InOutQuad)

    def enterEvent(self, event: QtCore.QEvent) -> None:  # noqa: N802
        self._pulse.setDirection(QtCore.QAbstractAnimation.Forward)
        self._pulse.start()
        super().enterEvent(event)

    def leaveEvent(self, event: QtCore.QEvent) -> None:  # noqa: N802
        self._pulse.setDirection(QtCore.QAbstractAnimation.Backward)
        self._pulse.start()
        super().leaveEvent(event)

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        super().mousePressEvent(event)
        self.clickedRipple.emit()

    def _update_pulse(self, value: float) -> None:
        color = QtGui.QColor(150, 90, 255)
        color.setAlphaF(0.35 + value * 0.4)
        self._glow.setColor(color)
        self._glow.setBlurRadius(8 + value * 12)


class PanelFrame(QtWidgets.QFrame):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 18)
        shadow.setColor(QtGui.QColor(12, 4, 24, 180))
        self.setGraphicsEffect(shadow)


class ProcessRefreshWorker(QtCore.QObject):
    finished = QtCore.pyqtSignal()
    results_ready = QtCore.pyqtSignal(list)
    error = QtCore.pyqtSignal(str)

    def __init__(self, scanner: ProcessScanner) -> None:
        super().__init__()
        self._scanner = scanner

    @QtCore.pyqtSlot()
    def run(self) -> None:
        try:
            processes = list(self._scanner.list_processes())
            self.results_ready.emit(processes)
        except Exception as exc:  # pragma: no cover - defensive logging path
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


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
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setShowGrid(False)
        self.setStyleSheet(theme.TABLE_CSS)
        self.setMouseTracking(True)

    def update_rows(self, rows: List[Dict[str, str]]) -> None:
        self.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for col_index, key in enumerate(["pid", "name", "user", "integrity", "confidence", "cause"]):
                item = QtWidgets.QTableWidgetItem(str(row.get(key, "")))
                item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
                self.setItem(row_index, col_index, item)


class DehashPanel(PanelFrame):
    status_message = QtCore.pyqtSignal(str, int)

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")

        self._dehasher = MultiDehasher()
        default_wordlist = Path(__file__).resolve().parent.parent / "data" / "dehash_samples.txt"
        if default_wordlist.exists():
            self._dehasher.load_wordlist(default_wordlist, source="default_samples")

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(30, 26, 30, 30)
        layout.setSpacing(16)

        title = QtWidgets.QLabel("Educational Multi Dehasher")
        title.setObjectName("subtitle")
        layout.addWidget(title)

        description = QtWidgets.QLabel(
            "Decode known hashes using approved wordlists to aid defensive investigations. "
            "Outputs are for lab and training insight only."
        )
        description.setWordWrap(True)
        description.setObjectName("summary")
        layout.addWidget(description)

        self.hash_input = QtWidgets.QPlainTextEdit()
        self.hash_input.setPlaceholderText("Paste hashed values (one per line)")
        self.hash_input.setFixedHeight(110)
        layout.addWidget(self.hash_input)

        controls_row = QtWidgets.QHBoxLayout()
        controls_row.setSpacing(12)

        self.algorithms: Dict[str, QtWidgets.QCheckBox] = {}
        for label in ("MD5", "SHA1", "SHA256"):
            checkbox = QtWidgets.QCheckBox(label)
            checkbox.setChecked(True)
            controls_row.addWidget(checkbox)
            self.algorithms[label.lower()] = checkbox

        controls_row.addStretch()

        self.candidate_input = QtWidgets.QLineEdit()
        self.candidate_input.setPlaceholderText("Add candidate plaintext")
        self.candidate_input.setFixedWidth(240)
        controls_row.addWidget(self.candidate_input)

        add_candidate_btn = AnimatedButton("Add")
        add_candidate_btn.clicked.connect(self.add_candidate)
        controls_row.addWidget(add_candidate_btn)

        load_button = AnimatedButton("Load Wordlist")
        load_button.clicked.connect(self.load_wordlist)
        controls_row.addWidget(load_button)

        layout.addLayout(controls_row)

        action_row = QtWidgets.QHBoxLayout()
        action_row.setSpacing(12)

        self.dehash_button = AnimatedButton("Resolve Hashes")
        self.dehash_button.clicked.connect(self.dehash)
        action_row.addWidget(self.dehash_button)

        self.clear_button = AnimatedButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        action_row.addWidget(self.clear_button)

        action_row.addStretch()
        layout.addLayout(action_row)

        self.results = QtWidgets.QTreeWidget()
        self.results.setColumnCount(4)
        self.results.setHeaderLabels(["Hash", "Algorithm", "Plaintext", "Source"])
        self.results.setRootIsDecorated(False)
        self.results.setAlternatingRowColors(True)
        layout.addWidget(self.results)

        self.status_label = QtWidgets.QLabel("")
        self.status_label.setObjectName("loading")
        layout.addWidget(self.status_label)

    def add_candidate(self) -> None:
        value = self.candidate_input.text().strip()
        if not value:
            self.status_label.setText("Enter a candidate value to add.")
            return
        added = self._dehasher.add_candidates([value], source="session")
        self.candidate_input.clear()
        if added:
            self.status_label.setText(f"Added {added} candidate for educational checks.")
            self.status_message.emit("Candidate stored for dehashing", 4000)
        else:
            self.status_label.setText("Candidate already known or empty.")

    def load_wordlist(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Wordlist", str(Path.home()), "Text Files (*.txt)"
        )
        if not path:
            return
        added = self._dehasher.load_wordlist(Path(path))
        self.status_label.setText(f"Loaded {added} candidates from {Path(path).name}.")
        if added:
            self.status_message.emit(f"Loaded {added} dehash candidates", 5000)

    def _selected_algorithms(self) -> Sequence[str]:
        selected = [name for name, checkbox in self.algorithms.items() if checkbox.isChecked()]
        return selected or list(self.algorithms.keys())

    def dehash(self) -> None:
        hashes = [line.strip() for line in self.hash_input.toPlainText().splitlines() if line.strip()]
        if not hashes:
            self.status_label.setText("Provide at least one hash to resolve.")
            return
        algorithms = self._selected_algorithms()
        matches = self._dehasher.dehash_many(hashes, algorithms)
        self.results.clear()
        rows = 0
        for digest, entries in matches.items():
            for entry in entries:
                item = QtWidgets.QTreeWidgetItem([digest, entry.algorithm.upper(), entry.plaintext, entry.source])
                self.results.addTopLevelItem(item)
                rows += 1
        if rows:
            self.status_label.setText(f"Resolved {rows} combinations across {len(matches)} hashes.")
            self.status_message.emit("Dehashing complete", 5000)
        else:
            self.status_label.setText("No matches found with current candidates.")

    def clear_results(self) -> None:
        self.results.clear()
        self.status_label.clear()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("WHOIS Watching")
        self.setMinimumSize(1200, 720)
        self.settings = settings.load_settings()
        self.heuristics = HeuristicEngine()
        self.scanner = ProcessScanner(include_hash=True, include_modules=False, include_connections=True)
        self.correlator = DownloadCorrelator()
        self.reporter = reporting.ReportExporter(Path.home() / "WHOIS_Watching" / "reports")
        self._refresh_thread: Optional[QtCore.QThread] = None
        self._refresh_worker: Optional[ProcessRefreshWorker] = None
        self._refresh_in_progress = False

        central = QtWidgets.QWidget()
        central.setObjectName("root")
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(24)
        central.setStyleSheet(theme.ROOT_CSS)

        header_row = QtWidgets.QHBoxLayout()
        header_row.setSpacing(18)
        logo = QtWidgets.QLabel()
        icon = QtGui.QIcon(str(theme.ASSETS["logo_svg"]))
        logo.setPixmap(icon.pixmap(64, 64))
        header_row.addWidget(logo, alignment=QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)

        title_block = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("WHOIS Watching")
        title.setObjectName("title")
        subtitle = QtWidgets.QLabel("Defensive process intelligence and WHOIS context at a glance")
        subtitle.setObjectName("subtitle")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        header_row.addLayout(title_block)
        header_row.addStretch()
        layout.addLayout(header_row)

        panel = PanelFrame()
        panel_layout = QtWidgets.QVBoxLayout(panel)
        panel_layout.setContentsMargins(30, 28, 30, 30)
        panel_layout.setSpacing(20)

        self.summary_label = QtWidgets.QLabel("Preparing telemetry…")
        self.summary_label.setObjectName("summary")
        panel_layout.addWidget(self.summary_label)

        self.table = ProcessTable()
        panel_layout.addWidget(self.table, stretch=1)

        controls_row = QtWidgets.QHBoxLayout()
        controls_row.setSpacing(14)
        self.refresh_btn = AnimatedButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_data)
        controls_row.addWidget(self.refresh_btn)

        self.export_btn = AnimatedButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        controls_row.addWidget(self.export_btn)

        self.settings_btn = AnimatedButton("Reduced Motion")
        self.settings_btn.clicked.connect(self.toggle_settings)
        controls_row.addWidget(self.settings_btn)

        controls_row.addStretch()
        self.loading_label = QtWidgets.QLabel()
        self.loading_label.setObjectName("loading")
        self.loading_label.setVisible(False)
        controls_row.addWidget(self.loading_label)

        panel_layout.addLayout(controls_row)
        layout.addWidget(panel, stretch=1)

        self.dehash_panel = DehashPanel(self)
        self.dehash_panel.status_message.connect(self._show_status)
        layout.addWidget(self.dehash_panel)

        self.status_bar = self.statusBar()
        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(12000)
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start()
        self.refresh_data()

    @QtCore.pyqtSlot(str, int)
    def _show_status(self, message: str, duration: int) -> None:
        self.status_bar.showMessage(message, duration)

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
        if self._refresh_in_progress:
            return
        self._refresh_in_progress = True
        self.refresh_btn.setEnabled(False)
        self.loading_label.setText("Scanning…")
        self.loading_label.setVisible(True)

        self._refresh_thread = QtCore.QThread(self)
        self._refresh_worker = ProcessRefreshWorker(self.scanner)
        self._refresh_worker.moveToThread(self._refresh_thread)
        self._refresh_thread.started.connect(self._refresh_worker.run)
        self._refresh_worker.results_ready.connect(self._handle_refresh_results)
        self._refresh_worker.error.connect(self._handle_refresh_error)
        self._refresh_worker.finished.connect(self._refresh_thread.quit)
        self._refresh_worker.finished.connect(self._refresh_worker.deleteLater)
        self._refresh_thread.finished.connect(self._refresh_thread.deleteLater)
        self._refresh_thread.finished.connect(self._refresh_finished)
        self._refresh_thread.start()

    def _handle_refresh_results(self, processes: List[ProcessInfo]) -> None:
        rows = self._build_rows(processes)
        self.table.update_rows(rows)
        self.summary_label.setText(f"Monitoring {len(rows)} live processes")
        self.status_bar.showMessage(f"Loaded {len(rows)} processes", 5000)
        self.loading_label.clear()
        self.loading_label.setVisible(False)

    def _handle_refresh_error(self, message: str) -> None:
        self.loading_label.setText("Refresh failed")
        self.status_bar.showMessage(f"Refresh error: {message}", 8000)

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
        if self._refresh_thread and self._refresh_thread.isRunning():
            self._refresh_thread.requestInterruption()
            self._refresh_thread.quit()
            self._refresh_thread.wait(2000)
        self._refresh_thread = None
        super().closeEvent(event)

    def _refresh_finished(self) -> None:
        self._refresh_in_progress = False
        self.refresh_btn.setEnabled(True)
        self._refresh_thread = None
        self._refresh_worker = None
        if not self.loading_label.text():
            self.loading_label.setVisible(False)
