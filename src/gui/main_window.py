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
        
        # Callbacks
        self.on_scan_request: Optional[Callable] = None
        self.on_stop_request: Optional[Callable] = None
        
        # GUI state
        self.connected_devices = []
        self.current_scan_info = None
        self.scan_in_progress = False
        
        logger.info("GUI initialized in console mode")
    
    def run(self):
        """Run the main GUI loop - console version"""
        self.running = True
        logger.info("Starting ArgusPI v2 Console Interface")
        self._show_welcome()
        
        try:
            while self.running:
                self._show_main_menu()
                choice = input("Select option: ").strip()
                
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
            input("Press Enter to continue...")
            return
            
        print("\nConnected USB Devices:")
        for i, device in enumerate(self.connected_devices, 1):
            print(f"{i}. {device}")
        
        try:
            choice = input("Select device to scan (number): ").strip()
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
        
        input("Press Enter to continue...")
    
    def _start_scan(self, device_info):
        """Start scanning a device"""
        if self.scan_in_progress:
            print("Scan already in progress!")
            return
            
        print(f"\nStarting scan of: {device_info}")
        
        if self.on_scan_request:
            device_path = getattr(device_info, 'mount_point', str(device_info))
            if device_path:
                self.on_scan_request(device_path)
            else:
                print("Error: Device not properly mounted")
    
    def _show_devices(self):
        """Show connected USB devices"""
        print("\n" + "-" * 40)
        print("CONNECTED USB DEVICES")
        print("-" * 40)
        
        if not self.connected_devices:
            print("No USB devices connected.")
        else:
            for i, device in enumerate(self.connected_devices, 1):
                print(f"{i}. {device}")
                
        input("\nPress Enter to continue...")
    
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
            
            if info.get('threats'):
                print("\nThreats detected:")
                for threat in info['threats']:
                    print(f"  - {threat['file']}: {threat['threat']}")
        else:
            print("No scan results available.")
            
        input("\nPress Enter to continue...")
    
    def _show_settings(self):
        """Show current settings"""
        print("\n" + "-" * 40)
        print("SETTINGS")
        print("-" * 40)
        
        print(f"Scan types: {', '.join(self.config.get('scanner.scan_types', []))}")
        print(f"Auto-detect USB: {self.config.get('usb.auto_detect', True)}")
        print(f"Read-only mode: {self.config.get('usb.read_only', True)}")
        print(f"Log level: {self.config.get('logging.level', 'INFO')}")
        
        input("\nPress Enter to continue...")
    
    def on_usb_connected(self, device_info):
        """Handle USB device connection"""
        logger.info(f"GUI: USB device connected - {device_info}")
        
        # Add to connected devices list if not already present
        if device_info not in self.connected_devices:
            self.connected_devices.append(device_info)
            
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
                print(f"\\rScanning: {scanned}/{total} ({percentage:.1f}%) - Threats: {threats}", end='', flush=True)
            
            # Store current scan info
            self.current_scan_info = progress_info
    
    def on_scan_complete(self, scan_result):
        """Handle scan completion"""
        self.scan_in_progress = False
        
        print(f"\\n\\nScan completed!")
        print(f"Files scanned: {scan_result.scanned_files}")
        print(f"Threats found: {scan_result.infected_files}")
        print(f"Scan time: {scan_result.scan_time:.2f} seconds")
        
        if scan_result.threats:
            print("\\nThreats detected:")
            for threat in scan_result.threats:
                print(f"  - {threat['file']}: {threat['threat']}")
        
        if scan_result.errors:
            print(f"\\nErrors encountered: {len(scan_result.errors)}")
        
        # Store results
        self.current_scan_info = {
            'scanned_files': scan_result.scanned_files,
            'threats_found': scan_result.infected_files,
            'status': 'Completed' if scan_result.completed else 'Stopped',
            'threats': scan_result.threats,
            'scan_time': scan_result.scan_time
        }
        
        input("\\nPress Enter to continue...")
    
    def on_scan_error(self, error_message: str):
        """Handle scan error"""
        self.scan_in_progress = False
        print(f"\\n\\nScan error: {error_message}")
        
        self.current_scan_info = {
            'scanned_files': 0,
            'threats_found': 0,
            'status': 'Error',
            'error': error_message
        }
        
        input("Press Enter to continue...")