"""
Main ArgusPI v2 Application
"""

import time
import threading
from pathlib import Path
from typing import Optional, Union
import logging

from config.manager import Config
from usb.detector import USBDetector
from scanner.engine import ScanEngine
from gui.main_window import MainWindow
from gui.kiosk_window import KioskWindow
from siem import SIEMClient

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class ArgusApplication:
    """Main application class for ArgusPI v2"""
    
    def __init__(self, config_file: Optional[str] = None, kiosk_mode: bool = False):
        self.config = Config(config_file)
        self.kiosk_mode = kiosk_mode
        self.usb_detector: Optional[USBDetector] = None
        self.scan_engine: Optional[ScanEngine] = None
        self.gui: Optional[Union[MainWindow, KioskWindow]] = None
        self.siem_client: Optional[SIEMClient] = None
        self.running = False
        
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
        
        # Initialize SIEM client
        self.siem_client = SIEMClient(self.config)
        
        # Initialize USB detector
        self.usb_detector = USBDetector(self.config)
        
        # Initialize scan engine
        self.scan_engine = ScanEngine(self.config)
        
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
            self.siem_client.send_event('scan_complete', {
                'device_path': device_path,
                'scanned_files': scan_result.scanned_files,
                'threats_found': scan_result.infected_files,
                'scan_time_seconds': scan_result.scan_time,
                'action': 'scan_completed'
            }, priority)
            
            # Send threats found event if threats detected
            if scan_result.infected_files > 0:
                self.siem_client.send_event('threats_found', {
                    'device_path': device_path,
                    'threat_count': scan_result.infected_files,
                    'threats': [str(threat) for threat in scan_result.threats],
                    'action': 'threats_detected'
                }, 'critical')
        
        # Forward to GUI
        if self.gui:
            self.gui.on_scan_complete(scan_result)