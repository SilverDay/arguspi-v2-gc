"""
Main GUI window for ArgusPI v2
"""

import time
import threading
from typing import Optional, Callable, Dict, Any
from pathlib import Path
import logging

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class MainWindow:
    """Main application window - console-based implementation"""
    
    def __init__(self, config, scan_engine):
        self.config = config
        self.scan_engine = scan_engine
        self.running = False
        
        # Station information
        self.station_name = config.get('station.name', 'ArgusPI Scanner')
        self.station_location = config.get('station.location', '')
        
        # Callbacks
        self.on_scan_request: Optional[Callable] = None
        self.on_stop_request: Optional[Callable] = None
        
        # GUI state
        self.connected_devices = []
        self.current_scan_info = None
        self.scan_in_progress = False
        self._progress_line_active = False
        
        logger.info(f"GUI initialized in console mode for station: {self.station_name}")
    
    def _read_input(self, prompt: str = "") -> Optional[str]:
        """Read user input while handling EOF gracefully."""
        try:
            return input(prompt)
        except EOFError:
            logger.warning("Input stream closed; exiting console interface")
            self.running = False
            return None

    def run(self):
        """Run the main GUI loop - console version"""
        self.running = True
        logger.info("Starting ArgusPI v2 Console Interface")
        self._show_welcome()
        
        try:
            while self.running:
                self._show_main_menu()
                choice = self._read_input("Select option: ")
                if choice is None:
                    break
                choice = choice.strip()
                
                if choice == '1':
                    self._scan_menu()
                elif choice == '2':
                    self._show_devices()
                elif choice == '3':
                    self._show_scan_results()
                elif choice == '4':
                    self._show_settings()
                elif choice == 'q' or choice == 'quit':
                    self.running = False
                else:
                    print("Invalid option. Please try again.")
                    
        except KeyboardInterrupt:
            logger.info("GUI interrupted by user")
        except Exception as e:
            logger.error(f"GUI error: {e}", exc_info=True)
        finally:
            self.running = False
    
    def _show_welcome(self):
        """Show welcome screen"""
        print("=" * 60)
        print(f"    {self.station_name}")
        if self.station_location:
            print(f"    Location: {self.station_location}")
        print(f"    {self.config.get('app.name', 'ArgusPI v2')}")
        print(f"    Version {self.config.get('app.version', '2.0.0')}")
        print("    USB Virus Scanner for Raspberry Pi")
        print("=" * 60)
        print()
    
    def _show_main_menu(self):
        """Show main menu options"""
        print("\n" + "-" * 40)
        print("MAIN MENU")
        print("-" * 40)
        print("1. Scan USB Device")
        print("2. Show Connected Devices")
        print("3. View Scan Results")
        print("4. Settings")
        print("q. Quit")
        print("-" * 40)
    
    def _scan_menu(self):
        """Show scan options"""
        if not self.connected_devices:
            print("\nNo USB devices connected.")
            if self._read_input("Press Enter to continue...") is None:
                return
            return
            
        print("\nConnected USB Devices:")
        for i, device in enumerate(self.connected_devices, 1):
            print(f"{i}. {device}")
        
        try:
            choice = self._read_input("Select device to scan (number): ")
            if choice is None:
                return
            choice = choice.strip()
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(self.connected_devices):
                    device_info = self.connected_devices[index]
                    self._start_scan(device_info)
                else:
                    print("Invalid selection.")
            else:
                print("Please enter a valid number.")
        except ValueError:
            print("Invalid input.")
        
        if self._read_input("Press Enter to continue...") is None:
            return
    
    def _start_scan(self, device_info):
        """Start scanning a device"""
        if self.scan_in_progress:
            print("Scan already in progress!")
            return
            
        self._progress_line_active = False
        print(f"\nStarting scan of: {device_info}")
        
        if self.on_scan_request:
            device_path = getattr(device_info, 'mount_point', str(device_info))
            if device_path:
                self.scan_in_progress = True
                self.on_scan_request(device_path)
            else:
                print("Error: Device not properly mounted")
    
    def _show_devices(self):
        """Show connected USB devices"""
        print("\n" + "-" * 40)
        print("CONNECTED USB DEVICES")
        print("-" * 40)
        
        logger.debug(f"GUI: Current connected devices count: {len(self.connected_devices)}")
        
        if not self.connected_devices:
            print("No USB devices connected.")
        else:
            for i, device in enumerate(self.connected_devices, 1):
                print(f"{i}. {device}")
                
        self._read_input("\nPress Enter to continue...")
    
    def _show_scan_results(self):
        """Show recent scan results"""
        print("\n" + "-" * 40)
        print("SCAN RESULTS")
        print("-" * 40)
        
        if self.current_scan_info:
            info = self.current_scan_info
            print(f"Last scan results:")
            print(f"  Files scanned: {info.get('scanned_files', 0)}")
            print(f"  Threats found: {info.get('threats_found', 0)}")
            print(f"  Status: {info.get('status', 'Unknown')}")
            device_path = info.get('device_path')
            if device_path:
                print(f"  Device: {device_path}")
            
            if info.get('threats'):
                print("\nThreats detected:")
                for threat in info['threats']:
                    print(f"  - {threat['file']}: {threat['threat']}")
        else:
            print("No scan results available.")
            
        self._read_input("\nPress Enter to continue...")
    
    def _show_settings(self):
        """Show current settings"""
        print("\n" + "-" * 40)
        print("SETTINGS")
        print("-" * 40)
        
        print(f"Scan types: {', '.join(self.config.get('scanner.scan_types', []))}")
        print(f"Auto-detect USB: {self.config.get('usb.auto_detect', True)}")
        print(f"Read-only mode: {self.config.get('usb.read_only', True)}")
        print(f"Log level: {self.config.get('logging.level', 'INFO')}")
        
        self._read_input("\nPress Enter to continue...")
    
    def on_usb_connected(self, device_info):
        """Handle USB device connection"""
        logger.debug(f"GUI: USB device connected callback - {device_info}")
        
        # Add to connected devices list if not already present
        if device_info not in self.connected_devices:
            self.connected_devices.append(device_info)
            logger.debug(f"GUI: Added device to connected list. Total devices: {len(self.connected_devices)}")
        else:
            logger.debug("GUI: Device already in connected list")
            
        if self.running and not self.scan_in_progress:
            print(f"\n[USB] Device connected: {device_info}")
            print("Press Enter to return to menu...")
    
    def on_usb_disconnected(self, device_info):
        """Handle USB device disconnection"""
        logger.info(f"GUI: USB device disconnected - {device_info}")
        
        # Remove from connected devices list
        if device_info in self.connected_devices:
            self.connected_devices.remove(device_info)
            
        if self.running:
            print(f"\n[USB] Device disconnected: {device_info}")
            print("Press Enter to return to menu...")
    
    def update_scan_progress(self, progress_info: Dict[str, Any]):
        """Update scan progress display"""
        if not progress_info:
            return
            
        phase = progress_info.get('phase', '')
        
        if phase == 'scanning':
            total = progress_info.get('total_files', 0)
            scanned = progress_info.get('scanned_files', 0)
            current_file = progress_info.get('current_file', '')
            threats = progress_info.get('threats_found', 0)
            
            if total > 0:
                percentage = (scanned / total) * 100
                prefix = '\n' if not self._progress_line_active else '\r'
                print(f"{prefix}Scanning: {scanned}/{total} ({percentage:.1f}%) - Threats: {threats}", end='', flush=True)
                self._progress_line_active = True
            
            # Store current scan info
            self.current_scan_info = progress_info
        else:
            self._progress_line_active = False
    
    def on_threat_detected(self, threat_info: Dict[str, Any]):
        """Display immediate notification when a threat is detected."""
        if not threat_info:
            return

        file_path = threat_info.get('file', 'unknown')
        threat_name = threat_info.get('threat', 'Potential threat')
        engine = threat_info.get('engine', 'engine')
        quarantine = threat_info.get('quarantine')

        alert_message = f"\n[ALERT] Threat detected by {engine}: {threat_name} (file: {file_path})"
        if quarantine:
            alert_message += " [quarantined]"
        print(alert_message)

        logger.warning("GUI alert: %s", alert_message.strip())

        threat_record = {key: value for key, value in threat_info.items() if key != 'scan_result'}

        if not isinstance(self.current_scan_info, dict):
            self.current_scan_info = {}
        threats_list = self.current_scan_info.setdefault('threats', [])
        threats_list.append(threat_record)
        self.current_scan_info['threats_found'] = len(threats_list)

    def on_scan_complete(self, scan_result):
        """Handle scan completion"""
        self.scan_in_progress = False

        if self._progress_line_active:
            print()
            self._progress_line_active = False
        
        print("\n\nScan completed!")
        print(f"Files scanned: {scan_result.scanned_files}")
        if hasattr(scan_result, 'clamav_files_scanned'):
            print(f"ClamAV files scanned: {scan_result.clamav_files_scanned}")
        print(f"Threats found: {scan_result.infected_files}")
        print(f"Scan time: {scan_result.scan_time:.2f} seconds")
        if getattr(scan_result, 'device_path', ''):
            print(f"Device path: {scan_result.device_path}")
        
        if scan_result.threats:
            print("\nThreats detected:")
            for threat in scan_result.threats:
                print(f"  - {threat['file']}: {threat['threat']}")
        
        if scan_result.errors:
            print(f"\nErrors encountered: {len(scan_result.errors)}")
        
        # Store results
        self.current_scan_info = {
            'scanned_files': scan_result.scanned_files,
            'threats_found': scan_result.infected_files,
            'status': 'Completed' if scan_result.completed else 'Stopped',
            'threats': scan_result.threats,
            'scan_time': scan_result.scan_time,
            'device_path': getattr(scan_result, 'device_path', ''),
            'clamav_files_scanned': getattr(scan_result, 'clamav_files_scanned', 0)
        }
        
        self._read_input("\nPress Enter to continue...")
    
    def on_scan_error(self, error_message: str):
        """Handle scan error"""
        self.scan_in_progress = False
        print(f"\n\nScan error: {error_message}")
        
        self.current_scan_info = {
            'scanned_files': 0,
            'threats_found': 0,
            'status': 'Error',
            'error': error_message
        }
        
        self._read_input("Press Enter to continue...")
