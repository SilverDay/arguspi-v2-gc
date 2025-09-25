"""
Kiosk Mode GUI window for ArgusPI v2
Provides a simplified, full-screen interface for public use
"""

import time
import threading
import os
from typing import Optional, Callable, Dict, Any, List
from pathlib import Path
import logging

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class KioskWindow:
    """Kiosk mode window - simplified full-screen interface for public use"""
    
    def __init__(self, config, scan_engine):
        self.config = config
        self.scan_engine = scan_engine
        self.running = False
        
        # Callbacks
        self.on_scan_request: Optional[Callable] = None
        self.on_stop_request: Optional[Callable] = None
        
        # Kiosk state
        self.connected_devices = []
        self.current_scan_result = None
        self.scan_in_progress = False
        self.waiting_for_usb = True
        self.auto_scan_enabled = config.get('kiosk.auto_scan', True)
        
        logger.info("Kiosk GUI initialized")
    
    def run(self):
        """Run the kiosk mode interface"""
        self.running = True
        logger.info("Starting ArgusPI v2 Kiosk Mode")
        
        # Hide cursor and clear screen for full-screen experience
        self._setup_kiosk_display()
        
        try:
            # Show welcome screen
            if self.config.get('kiosk.show_welcome', True):
                self._show_kiosk_welcome()
            
            # Main kiosk loop
            while self.running:
                try:
                    if self.waiting_for_usb and not self.scan_in_progress:
                        self._show_waiting_screen()
                    elif self.scan_in_progress:
                        self._show_scanning_screen()
                    elif self.current_scan_result:
                        self._show_results_screen()
                    else:
                        self._show_waiting_screen()
                    
                    time.sleep(1)  # Update display every second
                    
                except KeyboardInterrupt:
                    if not self.config.get('kiosk.prevent_exit', True):
                        logger.info("Kiosk mode interrupted by user")
                        break
                    else:
                        logger.info("Exit attempt blocked in kiosk mode")
                        continue
                        
        except Exception as e:
            logger.error(f"Kiosk GUI error: {e}", exc_info=True)
        finally:
            self._cleanup_kiosk_display()
            self.running = False
    
    def _setup_kiosk_display(self):
        """Setup the display for kiosk mode"""
        try:
            # Clear screen
            os.system('clear')
            
            # Hide cursor
            print('\033[?25l', end='', flush=True)
            
            # Set terminal to raw mode to prevent system shortcuts
            if self.config.get('kiosk.prevent_exit', True):
                os.system('stty -echo -icanon')
                
        except Exception as e:
            logger.warning(f"Could not setup kiosk display: {e}")
    
    def _cleanup_kiosk_display(self):
        """Cleanup kiosk display settings"""
        try:
            # Show cursor
            print('\033[?25h', end='', flush=True)
            
            # Restore terminal settings
            os.system('stty echo icanon')
            
        except Exception as e:
            logger.warning(f"Could not cleanup kiosk display: {e}")
    
    def _show_kiosk_welcome(self):
        """Show kiosk welcome screen"""
        self._clear_screen()
        
        print("=" * 80)
        print()
        print(f"        {self.config.get('app.name', 'ArgusPI v2')} - KIOSK MODE")
        print(f"        Version {self.config.get('app.version', '2.0.0')}")
        print("        USB Virus Scanner for Public Use")
        print()
        print("=" * 80)
        print()
        print("    Welcome! This system will automatically scan your USB device")
        print("    for viruses and malware when you plug it in.")
        print()
        print("    Please insert your USB device to begin scanning...")
        print()
        print("=" * 80)
        
        time.sleep(3)  # Show welcome for 3 seconds
    
    def _show_waiting_screen(self):
        """Show waiting for USB device screen"""
        self._clear_screen()
        
        # Create a simple animated waiting display
        animation_chars = ['|', '/', '-', '\\']
        char = animation_chars[int(time.time()) % len(animation_chars)]
        
        print("\n" * 8)
        print("    " + "=" * 60)
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 15 + "USB VIRUS SCANNER" + " " * 25 + "|")
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 10 + f"Please insert your USB device {char}" + " " * 15 + "|")
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 8 + "The device will be scanned automatically" + " " * 9 + "|")
        print("    |" + " " * 58 + "|")
        print("    " + "=" * 60)
        print("\n" * 8)
        
        # Show connected device count if any
        if self.connected_devices:
            print(f"    Connected devices: {len(self.connected_devices)}")
    
    def _show_scanning_screen(self):
        """Show scanning in progress screen"""
        self._clear_screen()
        
        print("\n" * 6)
        print("    " + "=" * 60)
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 18 + "SCANNING IN PROGRESS" + " " * 20 + "|")
        print("    |" + " " * 58 + "|")
        
        if hasattr(self, 'scan_progress_info') and self.scan_progress_info:
            info = self.scan_progress_info
            total = info.get('total_files', 0)
            scanned = info.get('scanned_files', 0)
            threats = info.get('threats_found', 0)
            
            if total > 0:
                percentage = (scanned / total) * 100
                progress_bar = self._create_progress_bar(percentage, 40)
                progress_text = f"Progress: {scanned}/{total} files ({percentage:.1f}%)"
                threats_text = f"Threats found: {threats}"
                
                print(f"    |{' ' * 9}{progress_bar}{' ' * 9}|")
                print(f"    |{' ' * 8}{progress_text}{' ' * (50 - len(progress_text))}|")
                print(f"    |{' ' * 8}{threats_text}{' ' * (50 - len(threats_text))}|")
            else:
                print("    |" + " " * 20 + "Preparing scan..." + " " * 19 + "|")
        else:
            print("    |" + " " * 20 + "Initializing..." + " " * 21 + "|")
        
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 10 + "Please wait while scanning completes" + " " * 12 + "|")
        print("    |" + " " * 58 + "|")
        print("    " + "=" * 60)
        print("\n" * 6)
    
    def _show_results_screen(self):
        """Show scan results screen"""
        if not self.current_scan_result:
            return
            
        self._clear_screen()
        
        result = self.current_scan_result
        threats_found = result.get('threats_found', 0)
        status = result.get('status', 'Unknown')
        
        print("\n" * 4)
        print("    " + "=" * 60)
        print("    |" + " " * 58 + "|")
        
        if threats_found == 0:
            print("    |" + " " * 20 + "✓ SCAN COMPLETE - CLEAN" + " " * 17 + "|")
            print("    |" + " " * 58 + "|")
            print("    |" + " " * 15 + "No threats detected!" + " " * 24 + "|")
        else:
            print("    |" + " " * 18 + "⚠ THREATS DETECTED!" + " " * 19 + "|")
            print("    |" + " " * 58 + "|")
            threat_count_text = f"Found {threats_found} potential threat(s)"
            print(f"    |{' ' * 15}{threat_count_text}{' ' * (43 - len(threat_count_text))}|")
        
        print("    |" + " " * 58 + "|")
        
        scanned_text = f"Files scanned: {result.get('scanned_files', 0)}"
        scan_time_text = f"Scan time: {result.get('scan_time', 0):.1f} seconds"
        
        print(f"    |{' ' * 8}{scanned_text}{' ' * (50 - len(scanned_text))}|")
        print(f"    |{' ' * 8}{scan_time_text}{' ' * (50 - len(scan_time_text))}|")
        print("    |" + " " * 58 + "|")
        
        # Show threat details if any
        threats = result.get('threats', [])
        if threats and len(threats) <= 3:  # Show up to 3 threats
            print("    |" + " " * 20 + "Threat Details:" + " " * 24 + "|")
            for threat in threats[:3]:
                threat_name = threat.get('threat', 'Unknown')[:35]
                threat_display = f"- {threat_name}"
                print(f"    |{' ' * 8}{threat_display}{' ' * (50 - len(threat_display))}|")
        elif len(threats) > 3:
            threat_summary = f"({len(threats)} threats found)"
            print(f"    |{' ' * 15}{threat_summary}{' ' * (43 - len(threat_summary))}|")
        
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 8 + "Remove USB device to scan another" + " " * 17 + "|")
        print("    |" + " " * 58 + "|")
        print("    " + "=" * 60)
        print("\n" * 4)
    
    def _create_progress_bar(self, percentage: float, width: int = 40) -> str:
        """Create a text-based progress bar"""
        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)
        return f"[{bar}]"
    
    def _clear_screen(self):
        """Clear the screen"""
        os.system('clear')
    
    def on_usb_connected(self, device_info):
        """Handle USB device connection in kiosk mode"""
        if device_info not in self.connected_devices:
            self.connected_devices.append(device_info)
        
        logger.info(f"Kiosk: USB device connected: {device_info}")
        
        # Auto-start scan if enabled and not already scanning
        if self.auto_scan_enabled and not self.scan_in_progress and device_info.mount_point:
            self.waiting_for_usb = False
            self._start_auto_scan(device_info)
    
    def on_usb_disconnected(self, device_info):
        """Handle USB device disconnection in kiosk mode"""
        if device_info in self.connected_devices:
            self.connected_devices.remove(device_info)
        
        logger.info(f"Kiosk: USB device disconnected: {device_info}")
        
        # Reset kiosk state for next user
        self.current_scan_result = None
        self.scan_in_progress = False
        self.waiting_for_usb = True
        
        # Clear any scan progress info
        if hasattr(self, 'scan_progress_info'):
            self.scan_progress_info = None
    
    def _start_auto_scan(self, device_info):
        """Start automatic scan of connected device"""
        if not device_info.mount_point:
            logger.warning(f"Cannot scan device {device_info}: no mount point")
            return
        
        logger.info(f"Starting auto-scan of device: {device_info.mount_point}")
        self.scan_in_progress = True
        
        if self.on_scan_request:
            self.on_scan_request(device_info.mount_point)
    
    def update_scan_progress(self, progress_info: Dict[str, Any]):
        """Update scan progress display"""
        if not progress_info:
            return
        
        self.scan_progress_info = progress_info
        
        # Log progress occasionally
        if progress_info.get('phase') == 'scanning':
            scanned = progress_info.get('scanned_files', 0)
            total = progress_info.get('total_files', 0)
            if scanned % 50 == 0:  # Log every 50 files
                logger.debug(f"Scan progress: {scanned}/{total} files")
    
    def on_scan_complete(self, scan_result):
        """Handle scan completion in kiosk mode"""
        self.scan_in_progress = False
        
        logger.info(f"Kiosk scan completed: {scan_result.scanned_files} files, {scan_result.infected_files} threats")
        
        # Store results for display
        self.current_scan_result = {
            'scanned_files': scan_result.scanned_files,
            'threats_found': scan_result.infected_files,
            'status': 'Completed' if scan_result.completed else 'Stopped',
            'threats': scan_result.threats,
            'scan_time': scan_result.scan_time
        }
        
        # Clear progress info
        if hasattr(self, 'scan_progress_info'):
            self.scan_progress_info = None
    
    def on_scan_error(self, error_message: str):
        """Handle scan error in kiosk mode"""
        self.scan_in_progress = False
        logger.error(f"Kiosk scan error: {error_message}")
        
        # Show error in results
        self.current_scan_result = {
            'scanned_files': 0,
            'threats_found': 0,
            'status': f'Error: {error_message}',
            'threats': [],
            'scan_time': 0
        }