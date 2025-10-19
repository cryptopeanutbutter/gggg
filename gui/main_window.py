"""PyQt5 main window for WHOIS Watching."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from PyQt5 import QtCore, QtGui, QtWidgets

from heuristics.engine import HeuristicEngine, HeuristicSignal
from scanner.downloads import DownloadCandidate, DownloadCorrelator
from scanner.process_scanner import ProcessInfo, ProcessScanner
from utils import reporting, settings
from utils.hashing import MultiDehasher
from . import theme


class AnimatedButton(QtWidgets.QPushButton):
    clickedRipple = QtCore.pyqtSignal()

    def __init__(self, text: str, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(text, parent)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self._glow = QtWidgets.QGraphicsDropShadowEffect(self)
        self._glow.setBlurRadius(9)
        self._glow.setOffset(0)
        self._glow.setColor(QtGui.QColor(150, 90, 255, 120))
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
        self._glow.setBlurRadius(9 + value * 14)


class PanelFrame(QtWidgets.QFrame):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(42)
        shadow.setOffset(0, 18)
        shadow.setColor(QtGui.QColor(12, 4, 24, 180))
        self.setGraphicsEffect(shadow)


class GradientFrame(QtWidgets.QFrame):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        self.setObjectName("chrome")

    def paintEvent(self, event: QtGui.QPaintEvent) -> None:  # noqa: N802
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        rect = self.rect()
        radius = max(rect.width(), rect.height()) * 0.75
        gradient = QtGui.QRadialGradient(rect.center(), radius)
        gradient.setColorAt(0.0, QtGui.QColor(118, 82, 220, 245))
        gradient.setColorAt(0.42, QtGui.QColor(70, 40, 150, 240))
        gradient.setColorAt(0.82, QtGui.QColor(24, 12, 48, 240))
        gradient.setColorAt(1.0, QtGui.QColor(6, 4, 18, 248))
        painter.fillRect(rect, gradient)
        super().paintEvent(event)


class TitleBar(QtWidgets.QFrame):
    minimize_requested = QtCore.pyqtSignal()
    close_requested = QtCore.pyqtSignal()

    def __init__(self, parent: QtWidgets.QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("titleBar")
        self._drag_offset: Optional[QtCore.QPoint] = None

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(26, 18, 26, 14)
        layout.setSpacing(18)

        logo = QtWidgets.QLabel()
        icon = QtGui.QIcon(str(theme.ASSETS["logo_svg"]))
        logo.setPixmap(icon.pixmap(44, 44))
        layout.addWidget(logo, alignment=QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

        title_block = QtWidgets.QVBoxLayout()
        title_block.setSpacing(2)
        title = QtWidgets.QLabel("WHOIS Watching")
        title.setObjectName("title")
        subtitle = QtWidgets.QLabel("Defensive telemetry cockpit")
        subtitle.setObjectName("subtitle")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        layout.addLayout(title_block, stretch=1)

        self.minimize_btn = QtWidgets.QToolButton()
        self.minimize_btn.setText("–")
        self.minimize_btn.setObjectName("windowControl")
        self.minimize_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.minimize_btn.clicked.connect(self.minimize_requested)
        layout.addWidget(self.minimize_btn)

        self.close_btn = QtWidgets.QToolButton()
        self.close_btn.setText("✕")
        self.close_btn.setObjectName("windowControl")
        self.close_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.close_btn.clicked.connect(self.close_requested)
        layout.addWidget(self.close_btn)

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        if event.button() == QtCore.Qt.LeftButton:
            self._drag_offset = event.globalPos() - self.window().frameGeometry().topLeft()
            event.accept()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        if self._drag_offset is not None and event.buttons() & QtCore.Qt.LeftButton:
            self.window().move(event.globalPos() - self._drag_offset)
            event.accept()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        if event.button() == QtCore.Qt.LeftButton:
            self._drag_offset = None
        super().mouseReleaseEvent(event)


class NavigationButton(AnimatedButton):
    def __init__(self, text: str, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setObjectName("navButton")
        self.setGraphicsEffect(None)


class NavigationBar(QtWidgets.QFrame):
    page_selected = QtCore.pyqtSignal(int)

    def __init__(self, labels: Sequence[str], parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(32, 8, 32, 8)
        layout.setSpacing(12)
        self.setStyleSheet(theme.NAVIGATION_CSS)
        self._buttons: List[NavigationButton] = []
        for index, label in enumerate(labels):
            button = NavigationButton(label)
            button.clicked.connect(lambda _checked, idx=index: self.page_selected.emit(idx))
            self._buttons.append(button)
            layout.addWidget(button)
        layout.addStretch(1)

    def set_current(self, index: int) -> None:
        for idx, button in enumerate(self._buttons):
            button.setChecked(idx == index)


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
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

    def update_rows(self, rows: List[Dict[str, str]]) -> None:
        self.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for col_index, key in enumerate(["pid", "name", "user", "integrity", "confidence", "cause"]):
                item = QtWidgets.QTableWidgetItem(str(row.get(key, "")))
                item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
                self.setItem(row_index, col_index, item)
        if rows:
            self.selectRow(0)


class ProcessContextMenu(QtWidgets.QMenu):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("processMenu")
        self.setStyleSheet(theme.PROCESS_MENU_CSS)
        self.view_overview_action = self.addAction("View Live Overview")
        self.copy_command_action = self.addAction("Copy Command Line")
        self.addSeparator()
        self.open_folder_action = self.addAction("Reveal Executable Location")
        self.check_downloads_action = self.addAction("Open Download Correlations")


class DialogFrame(QtWidgets.QFrame):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("dialogFrame")
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(36)
        shadow.setOffset(0, 16)
        shadow.setColor(QtGui.QColor(14, 6, 28, 180))
        self.setGraphicsEffect(shadow)


class ProcessOverviewDialog(QtWidgets.QDialog):
    def __init__(
        self,
        process: ProcessInfo,
        confidence: float,
        cause: str,
        signals: Sequence[HeuristicSignal],
        downloads: Sequence[DownloadCandidate],
        parent: Optional[QtWidgets.QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.Dialog)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        self.setModal(True)
        self.setStyleSheet(theme.DIALOG_CSS + theme.TABLE_CSS)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        frame = DialogFrame()
        frame_layout = QtWidgets.QVBoxLayout(frame)
        frame_layout.setContentsMargins(28, 28, 28, 28)
        frame_layout.setSpacing(18)

        title = QtWidgets.QLabel(f"Process Overview — {process.name} (PID {process.pid})")
        title.setObjectName("dialogTitle")
        frame_layout.addWidget(title)

        subtitle = QtWidgets.QLabel(
            "Confidence {0:.0f}% · {1}".format(confidence, cause or "No strong signals detected")
        )
        subtitle.setObjectName("dialogSubtitle")
        frame_layout.addWidget(subtitle)

        grid = QtWidgets.QFormLayout()
        grid.setSpacing(10)
        grid.addRow("Executable", QtWidgets.QLabel(process.exe or "Unknown"))
        grid.addRow("User", QtWidgets.QLabel(process.username))
        grid.addRow("Integrity", QtWidgets.QLabel(process.integrity))
        grid.addRow("Started", QtWidgets.QLabel(_dt.datetime.fromtimestamp(process.create_time).isoformat()))
        grid.addRow("Status", QtWidgets.QLabel(process.status))
        grid.addRow("SHA256", QtWidgets.QLabel(process.sha256 or "Unavailable"))
        cmdline = " ".join(process.cmdline) if process.cmdline else "(no command line)"
        cmdline_label = QtWidgets.QLabel(cmdline)
        cmdline_label.setWordWrap(True)
        grid.addRow("Command", cmdline_label)
        frame_layout.addLayout(grid)

        if signals:
            signals_label = QtWidgets.QLabel("Signal Highlights")
            signals_label.setObjectName("subtitle")
            frame_layout.addWidget(signals_label)
            signal_list = QtWidgets.QTreeWidget()
            signal_list.setColumnCount(3)
            signal_list.setHeaderLabels(["Name", "Weight", "Rationale"])
            signal_list.setRootIsDecorated(False)
            signal_list.setAlternatingRowColors(True)
            for signal in signals:
                signal_list.addTopLevelItem(
                    QtWidgets.QTreeWidgetItem(
                        [signal.name.replace("_", " ").title(), f"{signal.weight:.1f}", signal.rationale]
                    )
                )
            frame_layout.addWidget(signal_list)

        downloads = list(downloads)
        if downloads:
            downloads_label = QtWidgets.QLabel("Matching Downloads")
            downloads_label.setObjectName("subtitle")
            frame_layout.addWidget(downloads_label)
            download_tree = QtWidgets.QTreeWidget()
            download_tree.setColumnCount(2)
            download_tree.setHeaderLabels(["Path", "SHA256"])
            download_tree.setRootIsDecorated(False)
            download_tree.setAlternatingRowColors(True)
            for candidate in downloads:
                download_tree.addTopLevelItem(
                    QtWidgets.QTreeWidgetItem([str(candidate.path), candidate.sha256])
                )
            frame_layout.addWidget(download_tree)

        close_btn = AnimatedButton("Close")
        close_btn.clicked.connect(self.accept)
        frame_layout.addWidget(close_btn, alignment=QtCore.Qt.AlignRight)

        layout.addWidget(frame)
        self.resize(720, 520)


class ProcessPage(PanelFrame):
    refresh_requested = QtCore.pyqtSignal()
    export_requested = QtCore.pyqtSignal()
    reduced_motion_requested = QtCore.pyqtSignal()

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(36, 34, 36, 36)
        layout.setSpacing(22)

        self.summary_label = QtWidgets.QLabel("Preparing telemetry…")
        self.summary_label.setObjectName("summary")
        layout.addWidget(self.summary_label)

        self.network_label = QtWidgets.QLabel("")
        self.network_label.setObjectName("subtitle")
        self.network_label.setVisible(False)
        layout.addWidget(self.network_label)

        self.table = ProcessTable()
        layout.addWidget(self.table, stretch=1)

        controls_row = QtWidgets.QHBoxLayout()
        controls_row.setSpacing(14)
        self.refresh_btn = AnimatedButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_requested)
        controls_row.addWidget(self.refresh_btn)

        self.export_btn = AnimatedButton("Export Report")
        self.export_btn.clicked.connect(self.export_requested)
        controls_row.addWidget(self.export_btn)

        self.settings_btn = AnimatedButton("Reduced Motion")
        self.settings_btn.clicked.connect(self.reduced_motion_requested)
        controls_row.addWidget(self.settings_btn)

        controls_row.addStretch(1)
        self.loading_label = QtWidgets.QLabel("")
        self.loading_label.setObjectName("loading")
        self.loading_label.setVisible(False)
        controls_row.addWidget(self.loading_label)
        layout.addLayout(controls_row)

    def set_summary(self, text: str) -> None:
        self.summary_label.setText(text)

    def set_network_summary(self, text: str | None) -> None:
        if text:
            self.network_label.setText(text)
            self.network_label.setVisible(True)
        else:
            self.network_label.clear()
            self.network_label.setVisible(False)

    def set_refresh_state(self, active: bool, message: str | None = None) -> None:
        self.refresh_btn.setEnabled(not active)
        if active:
            self.loading_label.setText(message or "Refreshing…")
            self.loading_label.setVisible(True)
        else:
            self.loading_label.clear()
            self.loading_label.setVisible(False)

    def update_rows(self, rows: List[Dict[str, str]]) -> None:
        self.table.update_rows(rows)


class DehashPage(PanelFrame):
    status_message = QtCore.pyqtSignal(str, int)

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self._dehasher = MultiDehasher()
        self._default_wordlist = Path(__file__).resolve().parent.parent / "data" / "dehash_samples.txt"
        self._candidate_count = 0
        if self._default_wordlist.exists():
            self._candidate_count += self._dehasher.load_wordlist(self._default_wordlist, source="default_samples")

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(34, 34, 34, 34)
        layout.setSpacing(18)

        title = QtWidgets.QLabel("Educational Multi Dehasher")
        title.setObjectName("subtitle")
        layout.addWidget(title)

        description = QtWidgets.QLabel(
            "Paste a hash, click decode, and WHOIS Watching will try all sanctioned algorithms "
            "against approved training wordlists. Use for defensive analysis only."
        )
        description.setWordWrap(True)
        description.setObjectName("summary")
        layout.addWidget(description)

        self.candidate_label = QtWidgets.QLabel(self._candidate_summary())
        self.candidate_label.setObjectName("subtitle")
        layout.addWidget(self.candidate_label)

        quick_row = QtWidgets.QHBoxLayout()
        quick_row.setSpacing(12)
        self.quick_hash_input = QtWidgets.QLineEdit()
        self.quick_hash_input.setPlaceholderText("Quick decode — paste a single hash value")
        quick_row.addWidget(self.quick_hash_input)
        self.quick_decode_btn = AnimatedButton("Decode")
        self.quick_decode_btn.clicked.connect(self.decode_single)
        quick_row.addWidget(self.quick_decode_btn)
        layout.addLayout(quick_row)

        self.quick_result = QtWidgets.QLabel("Ready for quick decode.")
        self.quick_result.setObjectName("loading")
        layout.addWidget(self.quick_result)

        self.hash_input = QtWidgets.QPlainTextEdit()
        self.hash_input.setPlaceholderText("Bulk decode — one hash per line")
        self.hash_input.setFixedHeight(120)
        layout.addWidget(self.hash_input)

        controls_row = QtWidgets.QHBoxLayout()
        controls_row.setSpacing(12)

        self.dehash_button = AnimatedButton("Decode Hashes")
        self.dehash_button.clicked.connect(self.dehash_many)
        controls_row.addWidget(self.dehash_button)

        self.clear_button = AnimatedButton("Clear")
        self.clear_button.clicked.connect(self.clear_results)
        controls_row.addWidget(self.clear_button)

        controls_row.addStretch(1)

        self.candidate_input = QtWidgets.QLineEdit()
        self.candidate_input.setPlaceholderText("Add candidate plaintext for training")
        controls_row.addWidget(self.candidate_input)

        add_candidate_btn = AnimatedButton("Add")
        add_candidate_btn.clicked.connect(self.add_candidate)
        controls_row.addWidget(add_candidate_btn)

        load_button = AnimatedButton("Load Wordlist")
        load_button.clicked.connect(self.load_wordlist)
        controls_row.addWidget(load_button)

        layout.addLayout(controls_row)

        self.results = QtWidgets.QTreeWidget()
        self.results.setColumnCount(4)
        self.results.setHeaderLabels(["Hash", "Algorithm", "Plaintext", "Source"])
        self.results.setRootIsDecorated(False)
        self.results.setAlternatingRowColors(True)
        layout.addWidget(self.results)

        self.status_label = QtWidgets.QLabel("Ready.")
        self.status_label.setObjectName("loading")
        layout.addWidget(self.status_label)

    def _candidate_summary(self) -> str:
        return f"Active candidate pool: {self._candidate_count} entries"

    def decode_single(self) -> None:
        digest = self.quick_hash_input.text().strip()
        if not digest:
            self.quick_result.setText("Provide a hash to decode.")
            return
        matches = self._dehasher.dehash_many([digest])
        entries = matches.get(digest.lower(), [])
        if entries:
            top = entries[0]
            self.quick_result.setText(
                f"{digest} → {top.plaintext} ({top.algorithm.upper()}) from {top.source}"
            )
            self.status_message.emit("Quick decode resolved", 4000)
        else:
            self.quick_result.setText("No match found in approved candidates.")
            self.status_message.emit("Quick decode unmatched", 4000)

    def add_candidate(self) -> None:
        value = self.candidate_input.text().strip()
        if not value:
            self.status_label.setText("Enter a candidate value to add.")
            return
        added = self._dehasher.add_candidates([value], source="session")
        self.candidate_input.clear()
        if added:
            self._candidate_count += added
            self.candidate_label.setText(self._candidate_summary())
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
        self._candidate_count += added
        self.candidate_label.setText(self._candidate_summary())
        self.status_label.setText(f"Loaded {added} candidates from {Path(path).name}.")
        if added:
            self.status_message.emit(f"Loaded {added} dehash candidates", 5000)

    def dehash_many(self) -> None:
        hashes = [line.strip() for line in self.hash_input.toPlainText().splitlines() if line.strip()]
        if not hashes:
            self.status_label.setText("Provide at least one hash to resolve.")
            return
        matches = self._dehasher.dehash_many(hashes)
        self.results.clear()
        rows = 0
        for digest, entries in matches.items():
            for entry in entries:
                item = QtWidgets.QTreeWidgetItem([digest, entry.algorithm.upper(), entry.plaintext, entry.source])
                self.results.addTopLevelItem(item)
                rows += 1
        if rows:
            self.status_label.setText(f"Resolved {rows} combinations across {len(matches)} hashes.")
            self.status_message.emit("Bulk dehash complete", 5000)
        else:
            self.status_label.setText("No matches found with current candidates.")
            self.status_message.emit("No matches found", 4000)

    def clear_results(self) -> None:
        self.results.clear()
        self.status_label.setText("Ready.")
        self.quick_result.setText("Ready for quick decode.")


class DownloadsPage(PanelFrame):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(34, 34, 34, 34)
        layout.setSpacing(18)

        title = QtWidgets.QLabel("Download Correlations")
        title.setObjectName("subtitle")
        layout.addWidget(title)

        self.summary_label = QtWidgets.QLabel("Awaiting telemetry refresh.")
        self.summary_label.setObjectName("loading")
        layout.addWidget(self.summary_label)

        self.matches_tree = QtWidgets.QTreeWidget()
        self.matches_tree.setColumnCount(4)
        self.matches_tree.setHeaderLabels(["Process", "PID", "Download", "SHA256"])
        self.matches_tree.setRootIsDecorated(False)
        self.matches_tree.setAlternatingRowColors(True)
        layout.addWidget(self.matches_tree, stretch=2)

        downloads_label = QtWidgets.QLabel("Available Download Inventory")
        downloads_label.setObjectName("subtitle")
        layout.addWidget(downloads_label)

        self.downloads_tree = QtWidgets.QTreeWidget()
        self.downloads_tree.setColumnCount(2)
        self.downloads_tree.setHeaderLabels(["Path", "SHA256"])
        self.downloads_tree.setRootIsDecorated(False)
        self.downloads_tree.setAlternatingRowColors(True)
        layout.addWidget(self.downloads_tree, stretch=1)

    def update_data(
        self,
        download_summary: Sequence[Dict[str, str]],
        matches: Sequence[Dict[str, str]],
    ) -> None:
        match_count = len(matches)
        download_count = len(download_summary)
        self.summary_label.setText(
            f"{match_count} correlated processes · {download_count} staged downloads scanned"
        )
        self.matches_tree.clear()
        for match in matches:
            self.matches_tree.addTopLevelItem(
                QtWidgets.QTreeWidgetItem(
                    [match.get("process", ""), match.get("pid", ""), match.get("path", ""), match.get("sha256", "")]
                )
            )
        self.downloads_tree.clear()
        for item in download_summary:
            self.downloads_tree.addTopLevelItem(
                QtWidgets.QTreeWidgetItem([item.get("path", ""), item.get("sha256", "")])
            )


class LabSummaryPage(PanelFrame):
    open_docs_requested = QtCore.pyqtSignal()

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(36, 36, 36, 36)
        layout.setSpacing(18)

        title = QtWidgets.QLabel("Lab Mode & Controlled Probes")
        title.setObjectName("subtitle")
        layout.addWidget(title)

        description = QtWidgets.QLabel(
            "Lab Mode is intentionally gated. Activate it from Settings with a passphrase and explicit allowed "
            "targets before launching any non-destructive probes. Ensure operations stay in an isolated lab network."
        )
        description.setWordWrap(True)
        description.setObjectName("summary")
        layout.addWidget(description)

        guidance = QtWidgets.QLabel(
            "Refer to the README for lab setup blueprints, audit requirements, and the API for authorising each probe."
        )
        guidance.setWordWrap(True)
        layout.addWidget(guidance)

        docs_btn = AnimatedButton("Open Lab Mode Guidance")
        docs_btn.clicked.connect(self.open_docs_requested)
        layout.addWidget(docs_btn, alignment=QtCore.Qt.AlignLeft)

        spacer = QtWidgets.QLabel(
            "Lab tooling lives under lab_mode/ and never runs unless explicitly enabled with passphrase checks."
        )
        spacer.setWordWrap(True)
        spacer.setObjectName("loading")
        layout.addWidget(spacer)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowMinimizeButtonHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        self.setMinimumSize(1280, 780)

        self.settings = settings.load_settings()
        self.heuristics = HeuristicEngine()
        self.scanner = ProcessScanner(include_hash=True, include_modules=False, include_connections=True)
        self.correlator = DownloadCorrelator()
        self.reporter = reporting.ReportExporter(Path.home() / "WHOIS_Watching" / "reports")

        self._refresh_thread: Optional[QtCore.QThread] = None
        self._refresh_worker: Optional[ProcessRefreshWorker] = None
        self._refresh_in_progress = False
        self._latest_processes: List[ProcessInfo] = []
        self._process_lookup: Dict[int, ProcessInfo] = {}
        self._download_summary: List[Dict[str, str]] = []
        self._last_refresh: Optional[_dt.datetime] = None

        wrapper = QtWidgets.QWidget()
        wrapper.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        wrapper.setStyleSheet("background: transparent;")
        wrapper_layout = QtWidgets.QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(28, 28, 28, 28)
        wrapper_layout.setSpacing(0)

        chrome = GradientFrame()
        chrome.setStyleSheet(theme.ROOT_CSS + theme.TITLE_BAR_CSS + theme.NAVIGATION_CSS + theme.TABLE_CSS)
        chrome_layout = QtWidgets.QVBoxLayout(chrome)
        chrome_layout.setContentsMargins(0, 0, 0, 0)
        chrome_layout.setSpacing(0)

        self.title_bar = TitleBar(self)
        self.title_bar.minimize_requested.connect(self.showMinimized)
        self.title_bar.close_requested.connect(self.close)
        chrome_layout.addWidget(self.title_bar)

        content = QtWidgets.QWidget()
        content_layout = QtWidgets.QVBoxLayout(content)
        content_layout.setContentsMargins(32, 28, 32, 24)
        content_layout.setSpacing(22)

        self.navigation = NavigationBar(["Process Intel", "Dehasher", "Downloads", "Lab Mode"])
        self.navigation.page_selected.connect(self._activate_page)
        content_layout.addWidget(self.navigation)

        self.pages = QtWidgets.QStackedWidget()
        content_layout.addWidget(self.pages, stretch=1)

        self.process_page = ProcessPage()
        self.dehash_page = DehashPage()
        self.downloads_page = DownloadsPage()
        self.lab_page = LabSummaryPage()

        self.pages.addWidget(self.process_page)
        self.pages.addWidget(self.dehash_page)
        self.pages.addWidget(self.downloads_page)
        self.pages.addWidget(self.lab_page)

        self.navigation.set_current(0)

        chrome_layout.addWidget(content)
        wrapper_layout.addWidget(chrome)
        self.setCentralWidget(wrapper)

        shadow = QtWidgets.QGraphicsDropShadowEffect(chrome)
        shadow.setBlurRadius(60)
        shadow.setOffset(0, 26)
        shadow.setColor(QtGui.QColor(18, 6, 40, 220))
        chrome.setGraphicsEffect(shadow)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready.")

        self.process_page.table.customContextMenuRequested.connect(self._show_process_menu)
        self.process_page.refresh_requested.connect(self.refresh_data)
        self.process_page.export_requested.connect(self.export_report)
        self.process_page.reduced_motion_requested.connect(self.toggle_settings)

        self.dehash_page.status_message.connect(self._show_status)
        self.lab_page.open_docs_requested.connect(self._open_lab_docs)

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(12000)
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start()

        self.refresh_data()

    @QtCore.pyqtSlot(str, int)
    def _show_status(self, message: str, duration: int) -> None:
        self.status_bar.showMessage(message, duration)

    def _activate_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        self.navigation.set_current(index)

    def _build_rows(self, processes: Iterable[ProcessInfo]) -> List[Dict[str, str]]:
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
                    "confidence": f"{confidence:.0f}%",
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
        self.process_page.set_refresh_state(True, "Scanning active processes…")

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
        self._latest_processes = processes
        self._process_lookup = {process.pid: process for process in processes}
        rows = self._build_rows(processes)
        self.process_page.update_rows(rows)
        self.process_page.set_summary(f"Monitoring {len(rows)} live processes")
        endpoint_count = sum(len(process.connections or []) for process in processes)
        endpoint_text = (
            f"Observed {endpoint_count} active network endpoints" if endpoint_count else "No active network connections"
        )
        self.process_page.set_network_summary(endpoint_text)
        self._last_refresh = _dt.datetime.now()
        self.status_bar.showMessage(f"Loaded {len(rows)} processes", 5000)
        self._update_downloads(processes)

    def _handle_refresh_error(self, message: str) -> None:
        self.process_page.set_refresh_state(False, None)
        self.status_bar.showMessage(f"Refresh error: {message}", 8000)

    def _update_downloads(self, processes: Sequence[ProcessInfo]) -> None:
        candidates = list(self.correlator.iter_candidates() or [])
        self._download_summary = [{"path": str(c.path), "sha256": c.sha256} for c in candidates]
        by_hash: Dict[str, List[DownloadCandidate]] = {}
        for candidate in candidates:
            by_hash.setdefault(candidate.sha256, []).append(candidate)
        matches: List[Dict[str, str]] = []
        for process in processes:
            if process.sha256 and process.sha256 in by_hash:
                for candidate in by_hash[process.sha256]:
                    matches.append(
                        {
                            "process": process.name,
                            "pid": str(process.pid),
                            "path": str(candidate.path),
                            "sha256": candidate.sha256,
                        }
                    )
        self.downloads_page.update_data(self._download_summary, matches)

    def export_report(self) -> None:
        processes = self._latest_processes or list(self.scanner.list_processes())
        data = {
            "processes": [proc.to_dict() for proc in processes],
            "downloads": self._download_summary,
        }
        summary_path = self.reporter.export_summary(data, tag="ui")
        encrypted_path = self.reporter.export_encrypted(data, tag="ui")
        self.status_bar.showMessage(
            f"Report saved to {summary_path} and {encrypted_path}", 10000
        )

    def toggle_settings(self) -> None:
        self.settings.reduced_motion = not self.settings.reduced_motion
        settings.save_settings(self.settings)
        state = "enabled" if self.settings.reduced_motion else "disabled"
        self.status_bar.showMessage(f"Reduced motion {state}", 5000)

    def _show_process_menu(self, position: QtCore.QPoint) -> None:
        index = self.process_page.table.indexAt(position)
        if not index.isValid():
            return
        pid_item = self.process_page.table.item(index.row(), 0)
        if pid_item is None:
            return
        try:
            pid = int(pid_item.text())
        except ValueError:
            return
        process = self._process_lookup.get(pid)
        if not process:
            return

        menu = ProcessContextMenu(self.process_page.table)
        global_pos = self.process_page.table.viewport().mapToGlobal(position)
        action = menu.exec_(global_pos)
        if action == menu.view_overview_action:
            self._show_process_overview(process)
        elif action == menu.copy_command_action:
            self._copy_process_command(process)
        elif action == menu.open_folder_action:
            self._reveal_process(process)
        elif action == menu.check_downloads_action:
            self._activate_page(2)
            self.status_bar.showMessage("Opened download correlations", 5000)

    def _copy_process_command(self, process: ProcessInfo) -> None:
        cmdline = " ".join(process.cmdline) if process.cmdline else process.exe or ""
        QtWidgets.QApplication.clipboard().setText(cmdline)
        self.status_bar.showMessage("Command line copied to clipboard", 4000)

    def _reveal_process(self, process: ProcessInfo) -> None:
        if not process.exe:
            self.status_bar.showMessage("Executable path unavailable", 5000)
            return
        url = QtCore.QUrl.fromLocalFile(process.exe)
        QtGui.QDesktopServices.openUrl(url)
        self.status_bar.showMessage("Opened executable location", 5000)

    def _show_process_overview(self, process: ProcessInfo) -> None:
        signals = self._signals_for_process(process)
        confidence, cause = self.heuristics.evaluate(signals)
        downloads: List[DownloadCandidate] = []
        if process.sha256:
            for candidate in self.correlator.match_process(process.sha256):
                downloads.append(candidate)
        dialog = ProcessOverviewDialog(process, confidence, cause, signals, downloads, self)
        dialog.exec_()

    def _open_lab_docs(self) -> None:
        readme_path = Path("README.md").resolve()
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(readme_path)))
        self.status_bar.showMessage("Opened README for lab guidance", 6000)

    def _refresh_finished(self) -> None:
        self._refresh_in_progress = False
        self.process_page.set_refresh_state(False)
        self._refresh_thread = None
        self._refresh_worker = None

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:  # noqa: N802
        self.timer.stop()
        if self._refresh_thread and self._refresh_thread.isRunning():
            self._refresh_thread.requestInterruption()
            self._refresh_thread.quit()
            self._refresh_thread.wait(2000)
        self._refresh_thread = None
        super().closeEvent(event)
