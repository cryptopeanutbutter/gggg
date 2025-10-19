"""PyQt5 main window for WHOIS Watching."""
from __future__ import annotations

import datetime as _dt
import html
import secrets
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from PyQt5 import QtCore, QtGui, QtWidgets

from heuristics.engine import HeuristicEngine, HeuristicSignal
from scanner.downloads import DownloadCandidate, DownloadCorrelator
from scanner.process_scanner import ProcessInfo, ProcessScanner
from utils import reporting, settings, paths
from utils.crypto_toolkit import (
    decrypt_file as toolkit_decrypt_file,
    decrypt_text as toolkit_decrypt_text,
    encrypt_file as toolkit_encrypt_file,
    encrypt_text as toolkit_encrypt_text,
    generate_passphrase,
)
from utils.hashing import MultiDehasher
from utils.tor_chat import ChatEvent, TorChatManager
from . import theme


class AnimatedButton(QtWidgets.QPushButton):
    clickedRipple = QtCore.pyqtSignal()

    def __init__(
        self,
        text: str,
        parent: Optional[QtWidgets.QWidget] = None,
        *,
        glow: bool = True,
    ) -> None:
        super().__init__(text, parent)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self._glow: Optional[QtWidgets.QGraphicsDropShadowEffect] = None
        self._pulse: Optional[QtCore.QVariantAnimation] = None
        if glow:
            self._create_glow()

    def _create_glow(self) -> None:
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

    def _has_glow(self) -> bool:
        return self._glow is not None and self.graphicsEffect() is self._glow

    def enterEvent(self, event: QtCore.QEvent) -> None:  # noqa: N802
        if self._pulse is not None and self._has_glow():
            self._pulse.setDirection(QtCore.QAbstractAnimation.Forward)
            self._pulse.start()
        super().enterEvent(event)

    def leaveEvent(self, event: QtCore.QEvent) -> None:  # noqa: N802
        if self._pulse is not None and self._has_glow():
            self._pulse.setDirection(QtCore.QAbstractAnimation.Backward)
            self._pulse.start()
        super().leaveEvent(event)

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        super().mousePressEvent(event)
        self.clickedRipple.emit()

    def _update_pulse(self, value: float) -> None:
        if not self._has_glow():
            return
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
        super().__init__(text, parent, glow=False)
        self.setCheckable(True)
        self.setObjectName("navButton")


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


class EncryptionPage(PanelFrame):
    status_message = QtCore.pyqtSignal(str, int)

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(34, 34, 34, 34)
        layout.setSpacing(18)

        title = QtWidgets.QLabel("Encryption Toolkit")
        title.setObjectName("subtitle")
        layout.addWidget(title)

        summary = QtWidgets.QLabel(
            "Generate a shared passphrase, protect investigator notes, or decrypt received payloads. "
            "All content stays local and leverages PBKDF2-hardened keys."
        )
        summary.setWordWrap(True)
        summary.setObjectName("summary")
        layout.addWidget(summary)

        passphrase_row = QtWidgets.QHBoxLayout()
        passphrase_row.setSpacing(10)
        self.passphrase_input = QtWidgets.QLineEdit()
        self.passphrase_input.setPlaceholderText("Shared passphrase")
        passphrase_row.addWidget(self.passphrase_input)
        self.generate_btn = AnimatedButton("Generate")
        self.generate_btn.clicked.connect(self._generate_passphrase)
        passphrase_row.addWidget(self.generate_btn)
        layout.addLayout(passphrase_row)

        text_row = QtWidgets.QHBoxLayout()
        text_row.setSpacing(16)

        left = QtWidgets.QVBoxLayout()
        left.setSpacing(8)
        left_label = QtWidgets.QLabel("Plaintext")
        left_label.setObjectName("subtitle")
        left.addWidget(left_label)
        self.plaintext_edit = QtWidgets.QPlainTextEdit()
        self.plaintext_edit.setPlaceholderText("Paste analyst notes to encrypt")
        left.addWidget(self.plaintext_edit)
        encrypt_btn = AnimatedButton("Encrypt Text")
        encrypt_btn.clicked.connect(self._encrypt_text)
        left.addWidget(encrypt_btn, alignment=QtCore.Qt.AlignRight)
        text_row.addLayout(left, stretch=1)

        right = QtWidgets.QVBoxLayout()
        right.setSpacing(8)
        right_label = QtWidgets.QLabel("Encrypted Package")
        right_label.setObjectName("subtitle")
        right.addWidget(right_label)
        self.encrypted_edit = QtWidgets.QPlainTextEdit()
        self.encrypted_edit.setReadOnly(True)
        self.encrypted_edit.setPlaceholderText("Ciphertext payload appears here")
        right.addWidget(self.encrypted_edit)
        actions = QtWidgets.QHBoxLayout()
        actions.setSpacing(10)
        decrypt_btn = AnimatedButton("Decrypt Text")
        decrypt_btn.clicked.connect(self._decrypt_text)
        actions.addWidget(decrypt_btn)
        copy_btn = AnimatedButton("Copy Token")
        copy_btn.clicked.connect(self._copy_token)
        actions.addWidget(copy_btn)
        actions.addStretch(1)
        right.addLayout(actions)
        text_row.addLayout(right, stretch=1)

        layout.addLayout(text_row)

        separator = QtWidgets.QFrame()
        separator.setFrameShape(QtWidgets.QFrame.HLine)
        separator.setFrameShadow(QtWidgets.QFrame.Sunken)
        layout.addWidget(separator)

        file_row = QtWidgets.QHBoxLayout()
        file_row.setSpacing(12)
        encrypt_file_btn = AnimatedButton("Encrypt File…")
        encrypt_file_btn.clicked.connect(self._encrypt_file)
        file_row.addWidget(encrypt_file_btn)
        decrypt_file_btn = AnimatedButton("Decrypt File…")
        decrypt_file_btn.clicked.connect(self._decrypt_file)
        file_row.addWidget(decrypt_file_btn)
        file_row.addStretch(1)
        layout.addLayout(file_row)

        self.status_label = QtWidgets.QLabel("Toolkit idle.")
        self.status_label.setObjectName("loading")
        layout.addWidget(self.status_label)

    def _generate_passphrase(self) -> None:
        token = generate_passphrase()
        self.passphrase_input.setText(token)
        self.status_label.setText("Generated a fresh session passphrase")
        self.status_message.emit("Passphrase generated", 4000)

    def _encrypt_text(self) -> None:
        passphrase = self.passphrase_input.text().strip()
        plaintext = self.plaintext_edit.toPlainText()
        try:
            package = toolkit_encrypt_text(passphrase, plaintext)
        except Exception as exc:  # pragma: no cover - runtime guard
            self.status_label.setText(str(exc))
            self.status_message.emit(str(exc), 5000)
            return
        self.encrypted_edit.setPlainText(package.package())
        self.status_label.setText("Text encrypted locally")
        self.status_message.emit("Text encrypted", 5000)

    def _decrypt_text(self) -> None:
        passphrase = self.passphrase_input.text().strip()
        payload = self.encrypted_edit.toPlainText().strip()
        try:
            plaintext = toolkit_decrypt_text(passphrase, payload)
        except Exception as exc:
            self.status_label.setText(str(exc))
            self.status_message.emit(str(exc), 5000)
            return
        self.plaintext_edit.setPlainText(plaintext)
        self.status_label.setText("Decryption successful")
        self.status_message.emit("Decrypted text", 5000)

    def _copy_token(self) -> None:
        token = self.encrypted_edit.toPlainText().strip()
        if not token:
            self.status_label.setText("No encrypted payload to copy")
            return
        QtWidgets.QApplication.clipboard().setText(token)
        self.status_label.setText("Encrypted token copied to clipboard")
        self.status_message.emit("Token copied", 4000)

    def _encrypt_file(self) -> None:
        passphrase = self.passphrase_input.text().strip()
        if not passphrase:
            self.status_label.setText("Provide a passphrase before encrypting a file")
            return
        source, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if not source:
            return
        destination, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save encrypted file",
            f"{source}.enc",
        )
        if not destination:
            return
        try:
            toolkit_encrypt_file(passphrase, Path(source), Path(destination))
        except Exception as exc:
            self.status_label.setText(str(exc))
            self.status_message.emit(str(exc), 5000)
            return
        self.status_label.setText(f"Encrypted file stored at {destination}")
        self.status_message.emit("File encrypted", 6000)

    def _decrypt_file(self) -> None:
        passphrase = self.passphrase_input.text().strip()
        if not passphrase:
            self.status_label.setText("Provide a passphrase before decrypting a file")
            return
        source, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select encrypted file")
        if not source:
            return
        default_dest = str(Path(source).with_suffix(""))
        destination, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Restore decrypted file",
            default_dest,
        )
        if not destination:
            return
        try:
            toolkit_decrypt_file(passphrase, Path(source), Path(destination))
        except Exception as exc:
            self.status_label.setText(str(exc))
            self.status_message.emit(str(exc), 5000)
            return
        self.status_label.setText(f"File restored to {destination}")
        self.status_message.emit("File decrypted", 6000)


class ChatLog(QtWidgets.QTextBrowser):
    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setObjectName("chatLog")

    def append_entry(self, text: str) -> None:
        self.append(text)


class TorChatPage(PanelFrame):
    status_message = QtCore.pyqtSignal(str, int)
    start_host_requested = QtCore.pyqtSignal(dict)
    join_requested = QtCore.pyqtSignal(dict)
    stop_requested = QtCore.pyqtSignal()
    send_message_requested = QtCore.pyqtSignal(str)
    send_file_requested = QtCore.pyqtSignal()

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self._hosting = False
        self._connected = False

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(34, 34, 34, 34)
        layout.setSpacing(18)

        title = QtWidgets.QLabel("Secure Tor Chat")
        title.setObjectName("subtitle")
        layout.addWidget(title)

        summary = QtWidgets.QLabel(
            "Host or join a Tor-mediated chat with other WHOIS Watching operators. Sessions require "
            "a shared passphrase and user approval before any file is saved to disk."
        )
        summary.setWordWrap(True)
        summary.setObjectName("summary")
        layout.addWidget(summary)

        mode_row = QtWidgets.QHBoxLayout()
        mode_row.setSpacing(10)
        mode_row.addWidget(QtWidgets.QLabel("Mode"))
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["Host Session", "Join Session"])
        self.mode_combo.currentIndexChanged.connect(self._mode_changed)
        mode_row.addWidget(self.mode_combo)
        mode_row.addStretch(1)
        layout.addLayout(mode_row)

        self.mode_stack = QtWidgets.QStackedWidget()
        layout.addWidget(self.mode_stack)

        host_widget = QtWidgets.QWidget()
        host_layout = QtWidgets.QFormLayout(host_widget)
        host_layout.setSpacing(10)
        self.host_port = QtWidgets.QSpinBox()
        self.host_port.setRange(0, 65535)
        self.host_port.setValue(5155)
        self.host_port.setSpecialValueText("Auto")
        host_layout.addRow("Local Port", self.host_port)
        self.host_session = QtWidgets.QLineEdit(self._generate_session())
        host_layout.addRow("Session Passphrase", self.host_session)
        self.regen_btn = AnimatedButton("Regenerate")
        self.regen_btn.clicked.connect(self._regenerate_session)
        host_layout.addRow("", self.regen_btn)
        self.control_port = QtWidgets.QSpinBox()
        self.control_port.setRange(0, 65535)
        self.control_port.setValue(9051)
        self.control_port.setSpecialValueText("Disabled")
        host_layout.addRow("Tor Control Port", self.control_port)
        self.control_password = QtWidgets.QLineEdit()
        self.control_password.setPlaceholderText("Optional control password")
        host_layout.addRow("Control Password", self.control_password)
        self.host_button = AnimatedButton("Start Hosting")
        self.host_button.clicked.connect(self._toggle_host)
        host_layout.addRow("", self.host_button)
        self.host_info = QtWidgets.QLabel("Waiting to start hosting")
        self.host_info.setObjectName("loading")
        host_layout.addRow("Status", self.host_info)
        self.mode_stack.addWidget(host_widget)

        join_widget = QtWidgets.QWidget()
        join_layout = QtWidgets.QFormLayout(join_widget)
        join_layout.setSpacing(10)
        self.join_address = QtWidgets.QLineEdit()
        self.join_address.setPlaceholderText("Peer onion address or IP")
        join_layout.addRow("Peer Address", self.join_address)
        self.join_port = QtWidgets.QSpinBox()
        self.join_port.setRange(1, 65535)
        self.join_port.setValue(5155)
        join_layout.addRow("Peer Port", self.join_port)
        self.join_session = QtWidgets.QLineEdit()
        self.join_session.setPlaceholderText("Session passphrase from host")
        join_layout.addRow("Session Passphrase", self.join_session)
        self.use_socks = QtWidgets.QCheckBox("Use Tor SOCKS proxy (recommended)")
        self.use_socks.setChecked(True)
        join_layout.addRow("Transport", self.use_socks)
        socks_row = QtWidgets.QHBoxLayout()
        socks_row.setSpacing(6)
        socks_row.addWidget(QtWidgets.QLabel("Host"))
        self.socks_host = QtWidgets.QLineEdit("127.0.0.1")
        socks_row.addWidget(self.socks_host)
        socks_row.addWidget(QtWidgets.QLabel("Port"))
        self.socks_port = QtWidgets.QSpinBox()
        self.socks_port.setRange(1, 65535)
        self.socks_port.setValue(9050)
        socks_row.addWidget(self.socks_port)
        join_layout.addRow("SOCKS", socks_row)
        self.join_button = AnimatedButton("Connect")
        self.join_button.clicked.connect(self._connect)
        join_layout.addRow("", self.join_button)
        self.join_info = QtWidgets.QLabel("Not connected")
        self.join_info.setObjectName("loading")
        join_layout.addRow("Status", self.join_info)
        self.mode_stack.addWidget(join_widget)

        self.chat_log = ChatLog()
        layout.addWidget(self.chat_log, stretch=2)

        entry_row = QtWidgets.QHBoxLayout()
        entry_row.setSpacing(10)
        self.message_input = QtWidgets.QLineEdit()
        self.message_input.setPlaceholderText("Type secure message")
        self.message_input.returnPressed.connect(self._send_message)
        entry_row.addWidget(self.message_input, stretch=1)
        self.send_btn = AnimatedButton("Send")
        self.send_btn.clicked.connect(self._send_message)
        entry_row.addWidget(self.send_btn)
        self.file_btn = AnimatedButton("Send File")
        self.file_btn.clicked.connect(self._send_file)
        entry_row.addWidget(self.file_btn)
        layout.addLayout(entry_row)

        self.status_label = QtWidgets.QLabel("Tor chat idle")
        self.status_label.setObjectName("loading")
        layout.addWidget(self.status_label)

        self._mode_changed(0)
        self._update_controls()

    def _generate_session(self) -> str:
        return secrets.token_urlsafe(12)

    def _regenerate_session(self) -> None:
        token = self._generate_session()
        self.host_session.setText(token)
        self.status_label.setText("Generated a new session passphrase")

    def _mode_changed(self, index: int) -> None:
        self.mode_stack.setCurrentIndex(index)
        self._update_controls()

    def _toggle_host(self) -> None:
        if self._hosting:
            self.stop_requested.emit()
            self._hosting = False
            self.status_label.setText("Hosting stopped")
        else:
            handshake = self.host_session.text().strip() or self._generate_session()
            self.host_session.setText(handshake)
            payload = {
                "port": self.host_port.value(),
                "handshake": handshake,
                "control_port": self.control_port.value() or None,
                "control_password": self.control_password.text() or None,
            }
            self.start_host_requested.emit(payload)
            self._hosting = True
            self.status_label.setText("Starting host…")
        self._update_controls()

    def _connect(self) -> None:
        if self._connected:
            self.stop_requested.emit()
            return
        host = self.join_address.text().strip()
        handshake = self.join_session.text().strip()
        if not host or not handshake:
            self.status_label.setText("Enter peer address and session passphrase")
            return
        payload = {
            "host": host,
            "port": self.join_port.value(),
            "handshake": handshake,
        }
        if self.use_socks.isChecked():
            payload["socks_host"] = self.socks_host.text().strip() or "127.0.0.1"
            payload["socks_port"] = self.socks_port.value()
        self.join_requested.emit(payload)
        self.status_label.setText("Connecting…")

    def _send_message(self) -> None:
        text = self.message_input.text()
        if not text.strip():
            return
        self.send_message_requested.emit(text)
        self.chat_log.append_entry(f"<b>You:</b> {html.escape(text)}")
        self.message_input.clear()

    def _send_file(self) -> None:
        self.send_file_requested.emit()

    def _update_controls(self) -> None:
        self.host_button.setText("Stop Hosting" if self._hosting else "Start Hosting")
        self.join_button.setText("Disconnect" if self._connected else "Connect")
        self.message_input.setEnabled(self._connected)
        self.send_btn.setEnabled(self._connected)
        self.file_btn.setEnabled(self._connected)

    def set_host_details(self, address: str, onion: Optional[str]) -> None:
        if onion:
            self.host_info.setText(f"Hidden service: {onion}")
        else:
            self.host_info.setText(f"Listening on {address}")

    def set_hosting_active(self, active: bool) -> None:
        self._hosting = active
        self._update_controls()

    def set_connected(self, connected: bool) -> None:
        self._connected = connected
        if connected:
            self.join_info.setText("Connected to peer")
        else:
            self.join_info.setText("Not connected")
        self._update_controls()

    def show_status(self, text: str) -> None:
        self.status_label.setText(text)
        self.status_message.emit(text, 5000)

    def append_peer_message(self, text: str) -> None:
        self.chat_log.append_entry(f"<b>Peer:</b> {html.escape(text)}")

    def prompt_file_offer(self, name: str, size: int) -> bool:
        dialog = FileOfferDialog(name, size, self)
        return dialog.exec_() == QtWidgets.QDialog.Accepted


class FileOfferDialog(QtWidgets.QDialog):
    def __init__(self, name: str, size: int, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.Dialog)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        self.setModal(True)
        self.setStyleSheet(theme.DIALOG_CSS)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        frame = DialogFrame()
        frame_layout = QtWidgets.QVBoxLayout(frame)
        frame_layout.setContentsMargins(26, 26, 26, 26)
        frame_layout.setSpacing(14)

        title = QtWidgets.QLabel("Incoming File Offer")
        title.setObjectName("dialogTitle")
        frame_layout.addWidget(title)

        details = QtWidgets.QLabel(f"{name} • {size / 1024:.1f} KiB")
        details.setObjectName("dialogSubtitle")
        frame_layout.addWidget(details)

        body = QtWidgets.QLabel(
            "Accepting stores the transfer in your downloads folder; rejecting discards it."
        )
        body.setWordWrap(True)
        frame_layout.addWidget(body)

        button_row = QtWidgets.QHBoxLayout()
        button_row.setSpacing(12)
        reject_btn = AnimatedButton("Reject")
        reject_btn.clicked.connect(self.reject)
        button_row.addWidget(reject_btn)
        accept_btn = AnimatedButton("Accept")
        accept_btn.clicked.connect(self.accept)
        button_row.addWidget(accept_btn)
        frame_layout.addLayout(button_row)

        layout.addWidget(frame)

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

        self.navigation = NavigationBar(
            ["Process Intel", "Dehasher", "Encryption", "Downloads", "Lab Mode", "Secure Chat"]
        )
        self.navigation.page_selected.connect(self._activate_page)
        content_layout.addWidget(self.navigation)

        self.pages = QtWidgets.QStackedWidget()
        content_layout.addWidget(self.pages, stretch=1)

        self.process_page = ProcessPage()
        self.dehash_page = DehashPage()
        self.encryption_page = EncryptionPage()
        self.downloads_page = DownloadsPage()
        self.lab_page = LabSummaryPage()
        self.chat_page = TorChatPage()

        self.pages.addWidget(self.process_page)
        self.pages.addWidget(self.dehash_page)
        self.pages.addWidget(self.encryption_page)
        self.pages.addWidget(self.downloads_page)
        self.pages.addWidget(self.lab_page)
        self.pages.addWidget(self.chat_page)

        self.chat_manager = TorChatManager(paths.get_downloads_directory())

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
        self.encryption_page.status_message.connect(self._show_status)
        self.lab_page.open_docs_requested.connect(self._open_lab_docs)
        self.chat_page.status_message.connect(self._show_status)
        self.chat_page.start_host_requested.connect(self._start_chat_host)
        self.chat_page.join_requested.connect(self._join_chat_session)
        self.chat_page.stop_requested.connect(self._stop_chat_session)
        self.chat_page.send_message_requested.connect(self._send_chat_message)
        self.chat_page.send_file_requested.connect(self._choose_chat_file)

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(12000)
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start()

        self.chat_timer = QtCore.QTimer(self)
        self.chat_timer.setInterval(400)
        self.chat_timer.timeout.connect(self._drain_chat_events)
        self.chat_timer.start()

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
            self._activate_page(3)
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

    def _start_chat_host(self, config: Dict[str, object]) -> None:
        handshake = str(config.get("handshake", ""))
        port = int(config.get("port", 0))
        control_port = config.get("control_port")
        if isinstance(control_port, int) and control_port <= 0:
            control_port = None
        control_password = config.get("control_password") or None
        try:
            self.chat_manager.start_host(
                port=port,
                handshake=handshake,
                control_port=control_port if isinstance(control_port, int) else None,
                control_password=str(control_password) if control_password else None,
            )
            self.chat_page.set_hosting_active(True)
            self.chat_page.show_status("Hosting secure session — awaiting peer")
        except Exception as exc:  # pragma: no cover - defensive runtime
            self.chat_page.show_status(f"Chat host error: {exc}")
            self.chat_page.set_hosting_active(False)

    def _join_chat_session(self, config: Dict[str, object]) -> None:
        try:
            self.chat_manager.connect(
                host=str(config.get("host", "")),
                port=int(config.get("port", 0)),
                handshake=str(config.get("handshake", "")),
                socks_host=config.get("socks_host"),
                socks_port=int(config.get("socks_port", 0)) if config.get("socks_port") else None,
            )
        except Exception as exc:  # pragma: no cover - defensive runtime
            self.chat_page.show_status(f"Chat connect error: {exc}")
            self.chat_page.set_connected(False)

    def _stop_chat_session(self) -> None:
        self.chat_manager.stop()
        self.chat_page.set_connected(False)
        self.chat_page.set_hosting_active(False)
        self.chat_page.show_status("Secure chat session closed")

    def _send_chat_message(self, text: str) -> None:
        self.chat_manager.send_message(text)

    def _choose_chat_file(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to share")
        if not path:
            return
        self.chat_manager.send_file(Path(path))
        self.chat_page.show_status(f"Offering {Path(path).name} to peer")

    def _drain_chat_events(self) -> None:
        events = self.chat_manager.poll_events()
        for event in events:
            if event.type == "hosting":
                address = event.payload.get("address", "127.0.0.1")
                onion = event.payload.get("onion")
                self.chat_page.set_host_details(address, onion)
                self.chat_page.show_status("Host ready — share the session passphrase securely")
            elif event.type == "connected":
                self.chat_page.set_connected(True)
                self.chat_page.show_status("Secure tunnel established")
            elif event.type == "disconnected":
                self.chat_page.set_connected(False)
                self.chat_page.show_status("Peer disconnected")
            elif event.type == "message":
                text = str(event.payload.get("text", ""))
                if text:
                    self.chat_page.append_peer_message(text)
            elif event.type == "file_offer":
                name = str(event.payload.get("name", "transfer.bin"))
                size = int(event.payload.get("size", 0))
                offer_id = str(event.payload.get("offer_id"))
                accept = self.chat_page.prompt_file_offer(name, size)
                self.chat_manager.respond_to_offer(offer_id, accept)
                if accept:
                    self.chat_page.show_status(f"Accepting {name}")
                else:
                    self.chat_page.show_status(f"Declined {name}")
            elif event.type == "file_saved":
                path = event.payload.get("path")
                if path:
                    self.chat_page.show_status(f"Saved transfer to {path}")
            elif event.type == "status":
                if event.message:
                    self.chat_page.show_status(event.message)
            elif event.type == "error":
                message = event.message or "Chat error"
                self.chat_page.show_status(message)

    def _refresh_finished(self) -> None:
        self._refresh_in_progress = False
        self.process_page.set_refresh_state(False)
        self._refresh_thread = None
        self._refresh_worker = None

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:  # noqa: N802
        self.timer.stop()
        self.chat_timer.stop()
        self.chat_manager.stop()
        if self._refresh_thread and self._refresh_thread.isRunning():
            self._refresh_thread.requestInterruption()
            self._refresh_thread.quit()
            self._refresh_thread.wait(2000)
        self._refresh_thread = None
        super().closeEvent(event)
