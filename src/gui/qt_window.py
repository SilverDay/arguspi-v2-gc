"""Qt-based GUI implementation for ArgusPI v2"""
# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

import sys
import logging
from pathlib import Path
from typing import Optional, Callable, Dict, Any

try:
    from PySide6.QtCore import Qt, QObject, Signal  # type: ignore[import]
    from PySide6.QtGui import QCloseEvent  # type: ignore[import]
    from PySide6.QtWidgets import (
        QApplication,
        QMainWindow,
        QWidget,
        QLabel,
        QListWidget,
        QListWidgetItem,
        QPushButton,
        QTextEdit,
        QProgressBar,
        QVBoxLayout,
        QHBoxLayout,
        QMessageBox,
    )  # type: ignore[import]
except ImportError as exc:  # pragma: no cover - optional dependency
    raise RuntimeError(
        "PySide6 is required for the Qt GUI backend. Install it with 'pip install PySide6'."
    ) from exc

from usb.detector import USBDeviceInfo

logger = logging.getLogger(__name__)


class _QtEventBridge(QObject):
    """Bridge class that exposes Qt signals for cross-thread updates."""

    usb_connected = Signal(object)
    usb_disconnected = Signal(object)
    progress_update = Signal(dict)
    scan_complete = Signal(object)
    scan_error = Signal(str)
    threat_detected = Signal(dict)


class QtMainWindow(QMainWindow):
    """Qt implementation of the ArgusPI GUI with the same callback surface."""

    def __init__(self, config, scan_engine):
        super().__init__()

        self.config = config
        self.scan_engine = scan_engine
        self.on_scan_request: Optional[Callable[[str], None]] = None
        self.on_stop_request: Optional[Callable[[], None]] = None
        self.running = False
        self.scan_in_progress = False
        self.current_scan_info: Optional[Dict[str, Any]] = None

        # USB device cache (path -> USBDeviceInfo)
        self.connected_devices: Dict[str, USBDeviceInfo] = {}
        self._device_items: Dict[str, QListWidgetItem] = {}

        # Ensure QApplication exists
        self.app = QApplication.instance()
        if self.app is None:
            self.app = QApplication(sys.argv or ["arguspi"])

        # Event bridge to marshal calls from worker threads into the Qt event loop
        self._bridge = _QtEventBridge()
        self._bridge.usb_connected.connect(self._handle_usb_connected_ui)
        self._bridge.usb_disconnected.connect(self._handle_usb_disconnected_ui)
        self._bridge.progress_update.connect(self._handle_scan_progress_ui)
        self._bridge.scan_complete.connect(self._handle_scan_complete_ui)
        self._bridge.scan_error.connect(self._handle_scan_error_ui)
        self._bridge.threat_detected.connect(self._handle_threat_detected_ui)

        self._setup_ui()
        self._apply_theme()

    # ------------------------------------------------------------------
    # Public API expected by the application core
    # ------------------------------------------------------------------
    def run(self):
        """Start the Qt event loop."""
        logger.info("Launching Qt GUI window")
        self.running = True
        self.show()
        assert self.app is not None
        self.app.exec()
        self.running = False

    def on_usb_connected(self, device_info: USBDeviceInfo):
        self._bridge.usb_connected.emit(device_info)

    def on_usb_disconnected(self, device_info: USBDeviceInfo):
        self._bridge.usb_disconnected.emit(device_info)

    def update_scan_progress(self, progress_info: Dict[str, Any]):
        if progress_info is None:
            progress_info = {}
        self._bridge.progress_update.emit(progress_info)

    def on_scan_complete(self, scan_result):
        self._bridge.scan_complete.emit(scan_result)

    def on_scan_error(self, error_message: str):
        self._bridge.scan_error.emit(error_message)

    def on_threat_detected(self, threat_info: Dict[str, Any]):
        self._bridge.threat_detected.emit(threat_info or {})

    # ------------------------------------------------------------------
    # Qt UI setup helpers
    # ------------------------------------------------------------------
    def _setup_ui(self):
        station_name = self.config.get('station.name', 'ArgusPI Scanner')
        station_location = self.config.get('station.location', '')

        self.setWindowTitle(f"{self.config.get('app.name', 'ArgusPI')} - {station_name}")
        self.setMinimumSize(900, 600)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        header = QLabel(f"<h2>{station_name}</h2>")
        header.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        main_layout.addWidget(header)

        if station_location:
            sub_header = QLabel(f"Location: {station_location}")
            sub_header.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            main_layout.addWidget(sub_header)

        info_label = QLabel("Connected USB Devices")
        info_label.setStyleSheet("font-weight: bold;")
        main_layout.addWidget(info_label)

        device_layout = QHBoxLayout()
        main_layout.addLayout(device_layout)

        self.device_list = QListWidget()
        self.device_list.setSelectionMode(QListWidget.SingleSelection)
        device_layout.addWidget(self.device_list, 2)

        control_panel = QVBoxLayout()
        device_layout.addLayout(control_panel, 1)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self._request_scan)
        control_panel.addWidget(self.scan_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self._stop_scan)
        self.stop_button.setEnabled(False)
        control_panel.addWidget(self.stop_button)

        control_panel.addStretch(1)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusLabel")
        main_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        log_label = QLabel("Activity Log")
        log_label.setStyleSheet("font-weight: bold;")
        main_layout.addWidget(log_label)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        main_layout.addWidget(self.log_view, 1)

        footer = QLabel(f"Version {self.config.get('app.version', '2.0.0')}")
        footer.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        footer.setObjectName("footerLabel")
        main_layout.addWidget(footer)

    def _apply_theme(self):
        theme = (self.config.get('gui.theme') or 'light').lower()
        if theme == 'dark':
            self.setStyleSheet(
                "QWidget { background-color: #1e1e1e; color: #f0f0f0; }"
                "QPushButton { background-color: #3a3a3a; border: 1px solid #555; padding: 6px; }"
                "QPushButton:disabled { background-color: #2a2a2a; color: #888; }"
                "QListWidget { background-color: #252526; }"
                "QTextEdit { background-color: #252526; }"
                "QProgressBar { border: 1px solid #555; background-color: #2a2a2a; }"
                "QProgressBar::chunk { background-color: #0e639c; }"
            )

    # ------------------------------------------------------------------
    # Slots handling signals emitted by the bridge
    # ------------------------------------------------------------------
    def _handle_usb_connected_ui(self, device_info: USBDeviceInfo):
        if not device_info:
            return

        device_path = device_info.device_path
        self.connected_devices[device_path] = device_info

        item = self._device_items.get(device_path)
        if item is None:
            item = QListWidgetItem(self._device_display_text(device_info))
            item.setData(Qt.UserRole, device_path)
            self.device_list.addItem(item)
            self._device_items[device_path] = item
        else:
            item.setText(self._device_display_text(device_info))

        self._log(f"USB connected: {self._device_display_text(device_info)}")
        if not self.scan_in_progress:
            self.status_label.setText("USB device connected. Select a device and click Start Scan.")

    def _handle_usb_disconnected_ui(self, device_info: USBDeviceInfo):
        if not device_info:
            return

        device_path = device_info.device_path
        if device_path in self.connected_devices:
            del self.connected_devices[device_path]

        item = self._device_items.pop(device_path, None)
        if item is not None:
            index = self.device_list.row(item)
            self.device_list.takeItem(index)

        self._log(f"USB disconnected: {self._device_display_text(device_info)}")

        if self.scan_in_progress and self.device_list.count() == 0:
            self._log("All devices removed; stopping scan if running.")
            self._stop_scan()

    def _handle_scan_progress_ui(self, progress_info: Dict[str, Any]):
        if not progress_info:
            return

        phase = progress_info.get('phase', '')
        total = progress_info.get('total_files', 0) or 0
        scanned = progress_info.get('scanned_files', 0) or 0
        current_file = progress_info.get('current_file', '')
        threats = progress_info.get('threats_found', 0) or 0

        if total > 0:
            self.progress_bar.setRange(0, 100)
            percentage = int((scanned / total) * 100)
            self.progress_bar.setValue(max(0, min(100, percentage)))
        else:
            self.progress_bar.setRange(0, 0)  # Indeterminate

        if phase == 'scanning':
            if current_file:
                name = Path(current_file).name
                self.status_label.setText(f"Scanning {name} ({scanned}/{total} files) - Threats: {threats}")
            else:
                self.status_label.setText(f"Scanning files ({scanned}/{total}) - Threats: {threats}")
        else:
            self.status_label.setText("Preparing scan...")

        self.scan_in_progress = True
        self.stop_button.setEnabled(True)
        self.scan_button.setEnabled(False)

        self.current_scan_info = progress_info

    def _handle_scan_complete_ui(self, scan_result):
        self.scan_in_progress = False
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100 if getattr(scan_result, 'completed', False) else 0)
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        status = 'Completed' if getattr(scan_result, 'completed', False) else 'Stopped'
        threats = getattr(scan_result, 'infected_files', 0)
        scanned_files = getattr(scan_result, 'scanned_files', 0)
        device_path = getattr(scan_result, 'device_path', '')
        scan_time = getattr(scan_result, 'scan_time', 0.0)

        self.status_label.setText(f"Scan {status.lower()} - {scanned_files} files, {threats} threats")
        self._log(
            f"Scan {status.lower()} for {device_path or 'device'}: "
            f"{scanned_files} files, {threats} threats, {scan_time:.2f}s"
        )

        if getattr(scan_result, 'threats', None):
            for threat in scan_result.threats:
                file_name = Path(threat.get('file', 'unknown')).name
                threat_name = threat.get('threat', 'Unknown threat')
                engine = threat.get('engine', '')
                suffix = f" via {engine}" if engine else ''
                self._log(f"Threat detected: {file_name} - {threat_name}{suffix}")

        if getattr(scan_result, 'errors', None):
            for error in scan_result.errors:
                self._log(f"Error: {error.get('message', 'Unknown error')}")

        self.current_scan_info = {
            'scanned_files': scanned_files,
            'threats_found': threats,
            'status': status,
            'threats': getattr(scan_result, 'threats', []),
            'scan_time': scan_time,
            'device_path': device_path,
        }

    def _handle_threat_detected_ui(self, threat_info: Dict[str, Any]):
        if not threat_info:
            return

        file_path = threat_info.get('file', 'unknown')
        threat_name = threat_info.get('threat', 'Potential threat')
        engine = threat_info.get('engine', 'engine')
        quarantine = threat_info.get('quarantine')

        message_parts = [f"Threat detected by {engine}: {threat_name}", f"File: {file_path}"]
        if quarantine:
            message_parts.append("File was quarantined")

        message = "\n".join(message_parts)
        self.status_label.setText(message)
        self._log(message)

        record = {key: value for key, value in threat_info.items() if key != 'scan_result'}
        if not isinstance(self.current_scan_info, dict) or self.current_scan_info is None:
            self.current_scan_info = {}
        threats = self.current_scan_info.setdefault('threats', [])
        threats.append(record)
        self.current_scan_info['threats_found'] = len(threats)

        if self.config.get('gui.mode', 'simple').lower() == 'expert':
            QMessageBox.warning(self, "Threat Detected", message)

    def _handle_scan_error_ui(self, error_message: str):
        self.scan_in_progress = False
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        self.status_label.setText("Scan error occurred")
        self._log(f"Scan error: {error_message}")
        QMessageBox.critical(self, "Scan Error", error_message)

        self.current_scan_info = {
            'scanned_files': 0,
            'threats_found': 0,
            'status': 'Error',
            'error': error_message,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _request_scan(self):
        if self.scan_in_progress:
            QMessageBox.information(self, "Scan In Progress", "A scan is already running.")
            return

        item = self.device_list.currentItem()
        if not item:
            QMessageBox.information(self, "Select Device", "Please select a USB device to scan.")
            return

        device_path = item.data(Qt.UserRole)
        device_info = self.connected_devices.get(device_path)
        mount_point = getattr(device_info, 'mount_point', None) if device_info else None
        target_path = mount_point or device_path

        if not target_path:
            QMessageBox.warning(self, "Device Error", "Selected device is not mounted.")
            return

        if self.on_scan_request:
            self._log(f"Starting scan for {target_path}")
            self.scan_in_progress = True
            self.progress_bar.setRange(0, 0)
            self.scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText(f"Starting scan for {target_path}")
            self.on_scan_request(target_path)
        else:
            QMessageBox.warning(self, "Scanner Unavailable", "Scan request handler is not configured.")

    def _stop_scan(self):
        if self.scan_in_progress and self.on_stop_request:
            self._log("Stop scan requested by user")
            self.on_stop_request()
        self.scan_in_progress = False
        self.stop_button.setEnabled(False)
        self.scan_button.setEnabled(True)
        self.status_label.setText("Scan stopped")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

    def _device_display_text(self, device_info: USBDeviceInfo) -> str:
        label = device_info.label or "Unnamed"
        mount = device_info.mount_point or "(not mounted)"
        fs = device_info.filesystem or "Unknown FS"
        size = device_info._format_size() if hasattr(device_info, '_format_size') else ""
        return f"{label} — {device_info.device_path} — {mount} — {fs} {size}"

    def _log(self, message: str):
        logger.info(message)
        self.log_view.append(message)

    def closeEvent(self, event: QCloseEvent):  # noqa: N802 - Qt naming convention
        self.running = False
        if self.scan_in_progress and self.on_stop_request:
            try:
                self.on_stop_request()
            except Exception as exc:  # pragma: no cover - guard against shutdown errors
                logger.error(f"Error during stop request on close: {exc}")
        super().closeEvent(event)
