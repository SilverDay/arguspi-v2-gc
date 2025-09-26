"""
Main ArgusPI v2 Application
"""

import time
import threading
from pathlib import Path
from typing import Optional, Union, Dict, Any
import logging

from config.manager import Config
from usb.detector import USBDetector, USBDeviceMetadata
from scanner.engine import ScanEngine
from gui.main_window import MainWindow
from gui.kiosk_window import KioskWindow
from siem import SIEMClient
from security import QuarantineManager, DeviceReputationStore, USBDeviceRuleManager

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class ArgusApplication:
    """Main application class for ArgusPI v2"""
    
    def __init__(self, config_file: Optional[str] = None, kiosk_mode: bool = False):
        self.config = Config(config_file)
        self.kiosk_mode = kiosk_mode
        self.usb_detector: Optional[USBDetector] = None
        self.scan_engine: Optional[ScanEngine] = None
        self.gui: Optional[Any] = None
        self.siem_client: Optional[SIEMClient] = None
        self.running = False
        self.quarantine_manager: Optional[QuarantineManager] = None
        self.reputation_store: Optional[DeviceReputationStore] = None
        self.rules_manager: Optional[USBDeviceRuleManager] = None
        self.require_operator_ack = bool(
            self.config.get('security.notifications.require_operator_ack', True)
        )
        
        # Override config if kiosk mode is enabled via command line
        if self.kiosk_mode:
            self.config.set('kiosk.enabled', True)
        
        station_name = self.config.get('station.name', 'ArgusPI Scanner')
        logger.info(f"Starting {self.config.get('app.name')} v{self.config.get('app.version')} - {station_name}")
        if self.kiosk_mode:
            logger.info("Kiosk mode enabled")
    
    def initialize(self):
        """Initialize all application components"""
        logger.info("Initializing application components...")
        
        # Initialize security adjuncts
        self.quarantine_manager = QuarantineManager(self.config)
        self.reputation_store = DeviceReputationStore(self.config)
        self.rules_manager = USBDeviceRuleManager(self.config)

        # Initialize SIEM client
        self.siem_client = SIEMClient(self.config)
        
        # Initialize USB detector
        self.usb_detector = USBDetector(self.config)
        if self.usb_detector:
            self.usb_detector.rules_manager = self.rules_manager
            self.usb_detector.reputation_store = self.reputation_store
        
        # Initialize scan engine
        self.scan_engine = ScanEngine(self.config)
        if self.scan_engine:
            self.scan_engine.on_threat_detected = self._handle_threat_detected
        
        # Initialize GUI based on configured backend
        gui_backend = (self.config.get('gui.backend', 'console') or 'console').lower()

        if self.config.get('kiosk.enabled', False):
            logger.info("Initializing Kiosk Mode GUI")
            self.gui = KioskWindow(self.config, self.scan_engine)
        elif gui_backend == 'qt':
            try:
                from gui.qt_window import QtMainWindow

                logger.info("Initializing Qt GUI backend")
                self.gui = QtMainWindow(self.config, self.scan_engine)
            except Exception as exc:
                logger.error(
                    "Failed to initialize Qt GUI backend (%s). Falling back to console GUI.",
                    exc,
                    exc_info=True
                )
                self.gui = MainWindow(self.config, self.scan_engine)
        else:
            if gui_backend not in {'console', 'qt'}:
                logger.warning("Unknown GUI backend '%s'. Falling back to console mode.", gui_backend)
            logger.info("Initializing Console GUI")
            self.gui = MainWindow(self.config, self.scan_engine)
            
        self.gui.on_scan_request = self._handle_scan_request
        self.gui.on_stop_request = self._handle_stop_request
        
        # Set up USB callbacks AFTER GUI is initialized
        self.usb_detector.on_device_connected = self._handle_usb_connected
        self.usb_detector.on_device_disconnected = self._handle_usb_disconnected
        self.usb_detector.on_device_metadata = self._handle_usb_metadata
        self.usb_detector.on_device_warning = self._handle_usb_warning
        
        logger.info("Application components initialized")
    
    def run(self):
        """Run the main application"""
        try:
            self.initialize()
            self.running = True

            if not self.usb_detector or not self.scan_engine or not self.gui:
                raise RuntimeError("Application components failed to initialize")

            usb_detector = self.usb_detector
            gui = self.gui
            
            # Do an initial USB scan synchronously to populate devices
            logger.debug("Performing initial USB device scan...")
            usb_detector._scan_existing_devices()
            
            # Start USB detection in background thread
            usb_thread = threading.Thread(target=usb_detector.start_monitoring, daemon=True)
            usb_thread.start()
            
            logger.info("Application started successfully")
            
            # Start GUI main loop
            gui.run()
            
        except Exception as e:
            logger.error(f"Application failed to start: {e}", exc_info=True)
            raise
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Shutdown application gracefully"""
        logger.info("Shutting down application...")
        self.running = False
        
        if self.siem_client:
            self.siem_client.shutdown()
        
        if self.usb_detector:
            self.usb_detector.stop_monitoring()
        
        if self.scan_engine:
            self.scan_engine.stop_scan()

        if self.reputation_store:
            self.reputation_store.close()
        
        logger.info("Application shutdown complete")
    
    def _handle_usb_connected(self, device_info):
        """Handle USB device connection"""
        logger.debug(f"Application: USB device connected callback - {device_info}")
        
        # Send SIEM event
        if self.siem_client:
            self.siem_client.send_event('usb_connected', {
                'device_info': str(device_info),
                'action': 'usb_connected'
            }, 'info')
        
        if self.gui:
            self.gui.on_usb_connected(device_info)
        else:
            logger.warning("GUI not available for USB connected event")
    
    def _handle_usb_disconnected(self, device_info):
        """Handle USB device disconnection"""
        logger.debug(f"Application: USB device disconnected callback - {device_info}")
        
        # Send SIEM event
        if self.siem_client:
            self.siem_client.send_event('usb_disconnected', {
                'device_info': str(device_info),
                'action': 'usb_disconnected'
            }, 'info')
        
        if self.gui:
            self.gui.on_usb_disconnected(device_info)
        else:
            logger.warning("GUI not available for USB disconnected event")

    def _handle_usb_metadata(self, metadata: USBDeviceMetadata):
        logger.debug("Application received USB metadata: %s", metadata.summary())

        if self.siem_client:
            self.siem_client.send_event(
                'usb_metadata',
                {
                    'metadata': metadata.to_dict(),
                    'action': 'usb_metadata',
                },
                'info',
            )

        gui = self.gui
        handler = getattr(gui, "on_usb_metadata", None) if gui else None
        if callable(handler):
            try:
                handler(metadata)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.debug("GUI metadata handler error: %s", exc, exc_info=True)

    def _handle_usb_warning(self, metadata: USBDeviceMetadata):
        warning_payload = metadata.to_dict()

        if self.siem_client:
            self.siem_client.send_event(
                'usb_warning',
                {
                    'metadata': warning_payload,
                    'action': 'usb_warning',
                },
                'warning',
            )

        gui = self.gui
        handler = getattr(gui, "on_usb_warning", None) if gui else None
        if callable(handler):
            try:
                handler(metadata)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.debug("GUI warning handler error: %s", exc, exc_info=True)

    def _handle_threat_detected(self, threat_info: Dict[str, Any]):
        file_path = threat_info.get('file')
        threat_name = threat_info.get('threat') or 'Unknown threat'
        engine = threat_info.get('engine') or 'unknown'
        device_path = threat_info.get('device_path')
        logger.warning(
            "Threat detected by %s: %s (device=%s, file=%s)",
            engine,
            threat_name,
            device_path,
            file_path,
        )

        quarantine_payload: Optional[Dict[str, Any]] = None
        manager = self.quarantine_manager
        if manager and getattr(manager, 'enabled', False) and file_path:
            try:
                record = manager.quarantine(
                    file_path,
                    threat_name=threat_name,
                    engine=engine,
                    metadata=threat_info.get('metadata'),
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.error("Failed to quarantine %s: %s", file_path, exc, exc_info=True)
            else:
                if record:
                    quarantine_payload = record.to_dict() if hasattr(record, 'to_dict') else None
                    if quarantine_payload:
                        scan_result_obj = threat_info.get('scan_result')
                        adder = getattr(scan_result_obj, 'add_quarantined_file', None)
                        if callable(adder):
                            try:
                                adder(quarantine_payload)
                            except Exception:  # pragma: no cover - defensive logging
                                logger.debug("Unable to attach quarantine record to scan result", exc_info=True)

        if self.siem_client:
            event_payload = {
                'device_path': device_path,
                'file': file_path,
                'threat': threat_name,
                'engine': engine,
                'quarantine': quarantine_payload,
                'action': 'threat_detected',
            }
            self.siem_client.send_event('threat_detected', event_payload, 'critical')

        gui = self.gui
        handler = getattr(gui, 'on_threat_detected', None) if gui else None
        if callable(handler):
            try:
                handler({**threat_info, 'quarantine': quarantine_payload})
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.debug("GUI threat handler error: %s", exc, exc_info=True)
    
    def _handle_scan_request(self, device_path):
        """Handle scan request from GUI"""
        logger.info(f"Scan requested for device: {device_path}")

        if not self.scan_engine or not self.gui:
            logger.error("Scan requested before components were initialized")
            return

        scan_engine = self.scan_engine
        gui = self.gui
        
        # Send SIEM event for scan start
        if self.siem_client:
            self.siem_client.send_event('scan_start', {
                'device_path': device_path,
                'action': 'scan_initiated'
            }, 'info')
        
        def scan_worker():
            try:
                scan_engine.scan_device(
                    device_path,
                    progress_callback=gui.update_scan_progress,
                    completion_callback=self._handle_scan_complete
                )
            except Exception as e:
                logger.error(f"Scan failed: {e}", exc_info=True)
                # Send SIEM event for scan error
                if self.siem_client:
                    self.siem_client.send_event('system_errors', {
                        'error_message': str(e),
                        'component': 'scan_engine',
                        'device_path': device_path,
                        'action': 'scan_error'
                    }, 'error')
                gui.on_scan_error(str(e))
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=scan_worker, daemon=True)
        scan_thread.start()
    
    def _handle_stop_request(self):
        """Handle stop scan request from GUI"""
        logger.info("Scan stop requested")
        if self.scan_engine:
            self.scan_engine.stop_scan()
    
    def _handle_scan_complete(self, scan_result):
        """Handle scan completion with SIEM integration"""
        # Send SIEM events
        if self.siem_client:
            # Send scan complete event
            priority = 'high' if scan_result.infected_files > 0 else 'info'
            device_path = getattr(scan_result, 'device_path', None) or 'unknown'
            quarantine_count = len(getattr(scan_result, 'quarantined_files', []) or [])
            self.siem_client.send_event('scan_complete', {
                'device_path': device_path,
                'scanned_files': scan_result.scanned_files,
                'threats_found': scan_result.infected_files,
                'scan_time_seconds': scan_result.scan_time,
                'quarantined_files': quarantine_count,
                'action': 'scan_completed'
            }, priority)
            
            # Send threats found event if threats detected
            if scan_result.infected_files > 0:
                quarantined_listing = getattr(scan_result, 'quarantined_files', []) or []
                self.siem_client.send_event('threats_found', {
                    'device_path': device_path,
                    'threat_count': scan_result.infected_files,
                    'threats': [str(threat) for threat in scan_result.threats],
                    'quarantined_files': quarantined_listing,
                    'action': 'threats_detected'
                }, 'critical')
        
        # Forward to GUI
        if self.gui:
            self.gui.on_scan_complete(scan_result)
