"""
Main ArgusPI v2 Application
"""

import time
import threading
from pathlib import Path
from typing import Optional
import logging

from config.manager import Config
from usb.detector import USBDetector
from scanner.engine import ScanEngine
from gui.main_window import MainWindow

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class ArgusApplication:
    """Main application class for ArgusPI v2"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = Config(config_file)
        self.usb_detector = None
        self.scan_engine = None
        self.gui = None
        self.running = False
        
        logger.info(f"Starting {self.config.get('app.name')} v{self.config.get('app.version')}")
    
    def initialize(self):
        """Initialize all application components"""
        logger.info("Initializing application components...")
        
        # Initialize USB detector
        self.usb_detector = USBDetector(self.config)
        
        # Initialize scan engine
        self.scan_engine = ScanEngine(self.config)
        
        # Initialize GUI
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
            
            # Do an initial USB scan synchronously to populate devices
            logger.debug("Performing initial USB device scan...")
            self.usb_detector._scan_existing_devices()
            
            # Start USB detection in background thread
            usb_thread = threading.Thread(target=self.usb_detector.start_monitoring, daemon=True)
            usb_thread.start()
            
            logger.info("Application started successfully")
            
            # Start GUI main loop
            self.gui.run()
            
        except Exception as e:
            logger.error(f"Application failed to start: {e}", exc_info=True)
            raise
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Shutdown application gracefully"""
        logger.info("Shutting down application...")
        self.running = False
        
        if self.usb_detector:
            self.usb_detector.stop_monitoring()
        
        if self.scan_engine:
            self.scan_engine.stop_scan()
        
        logger.info("Application shutdown complete")
    
    def _handle_usb_connected(self, device_info):
        """Handle USB device connection"""
        logger.debug(f"Application: USB device connected callback - {device_info}")
        if self.gui:
            self.gui.on_usb_connected(device_info)
        else:
            logger.warning("GUI not available for USB connected event")
    
    def _handle_usb_disconnected(self, device_info):
        """Handle USB device disconnection"""
        logger.debug(f"Application: USB device disconnected callback - {device_info}")
        if self.gui:
            self.gui.on_usb_disconnected(device_info)
        else:
            logger.warning("GUI not available for USB disconnected event")
    
    def _handle_scan_request(self, device_path):
        """Handle scan request from GUI"""
        logger.info(f"Scan requested for device: {device_path}")
        
        def scan_worker():
            try:
                self.scan_engine.scan_device(
                    device_path,
                    progress_callback=self.gui.update_scan_progress,
                    completion_callback=self.gui.on_scan_complete
                )
            except Exception as e:
                logger.error(f"Scan failed: {e}", exc_info=True)
                self.gui.on_scan_error(str(e))
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=scan_worker, daemon=True)
        scan_thread.start()
    
    def _handle_stop_request(self):
        """Handle stop scan request from GUI"""
        logger.info("Scan stop requested")
        if self.scan_engine:
            self.scan_engine.stop_scan()