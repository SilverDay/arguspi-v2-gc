"""
Kiosk Mode GUI window for ArgusPI v2
Provides a simplified, full-screen graphical interface for public use using tkinter
"""

import time
import threading
import tkinter as tk
from tkinter import ttk, font
from typing import Optional, Callable, Dict, Any, List
from pathlib import Path
import logging

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class KioskGUI:
    """Graphical kiosk mode window - simplified full-screen interface for public use"""
    
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
        
        # Kiosk state
        self.connected_devices = []
        self.current_scan_result = None
        self.scan_in_progress = False
        self.waiting_for_usb = True
        self.scanned_device = None  # Track which device was scanned
        self.auto_scan_enabled = config.get('kiosk.auto_scan', True)
        
        # GUI elements
        self.root = None
        self.main_frame = None
        self.info_label = None
        self.progress_bar = None
        self.progress_label = None
        self.stats_frame = None
        self.elapsed_time_label = None
        self.files_scanned_label = None
        self.threats_found_label = None
        
        # Animation state
        self.animation_chars = ['|', '/', '-', '\\']
        self.animation_index = 0
        self.start_time = None
        
        logger.info(f"Kiosk GUI initialized for station: {self.station_name}")
        
    def _create_gui(self):
        """Create the main GUI elements"""
        # Create main window
        self.root = tk.Tk()
        self.root.title(f"{self.config.get('app.name', 'ArgusPI v2')} - Kiosk Mode")
        self.root.configure(bg='#f0f0f0')
        
        # Setup for full screen if enabled
        if self.config.get('gui.fullscreen', True):
            self.root.attributes('-fullscreen', True)
            self.root.bind('<Escape>', self._on_escape)
        else:
            # For development, use a reasonable window size
            self.root.geometry('800x600')
            
        # Disable window closing if exit prevention is enabled
        if self.config.get('kiosk.prevent_exit', True):
            self.root.protocol("WM_DELETE_WINDOW", self._prevent_close)
        
        # Main container frame
        self.main_frame = tk.Frame(self.root, bg='#f0f0f0')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title area
        title_frame = tk.Frame(self.main_frame, bg='#2c3e50', relief=tk.RAISED, bd=2)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Station name and title
        title_font = font.Font(family="Helvetica", size=24, weight="bold")
        station_label = tk.Label(title_frame, text=self.station_name, 
                                font=title_font, fg='white', bg='#2c3e50')
        station_label.pack(pady=10)
        
        subtitle_font = font.Font(family="Helvetica", size=16)
        subtitle_label = tk.Label(title_frame, text="USB Virus Scanner", 
                                 font=subtitle_font, fg='#ecf0f1', bg='#2c3e50')
        subtitle_label.pack(pady=(0, 10))
        
        if self.station_location:
            location_font = font.Font(family="Helvetica", size=12)
            location_label = tk.Label(title_frame, text=f"Location: {self.station_location}", 
                                     font=location_font, fg='#bdc3c7', bg='#2c3e50')
            location_label.pack(pady=(0, 10))
        
        # Status area
        self.status_frame = tk.Frame(self.main_frame, bg='#f0f0f0')
        self.status_frame.pack(fill=tk.BOTH, expand=True)
        
        # Information area
        info_frame = tk.Frame(self.status_frame, bg='white', relief=tk.SUNKEN, bd=2)
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        info_font = font.Font(family="Helvetica", size=18, weight="bold")
        self.info_label = tk.Label(info_frame, text="Please insert your USB device to begin scanning...", 
                                  font=info_font, fg='#2c3e50', bg='white', wraplength=700)
        self.info_label.pack(pady=20)
        
        # Progress area
        self.progress_frame = tk.Frame(self.status_frame, bg='#f0f0f0')
        self.progress_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Progress bar
        progress_label_font = font.Font(family="Helvetica", size=14)
        self.progress_label = tk.Label(self.progress_frame, text="Progress: 0%", 
                                      font=progress_label_font, fg='#2c3e50', bg='#f0f0f0')
        self.progress_label.pack(pady=(0, 10))
        
        # Use a themed progress bar
        self.progress_bar = ttk.Progressbar(self.progress_frame, length=600, mode='determinate')
        self.progress_bar.pack(pady=(0, 10))
        
        # Statistics area
        self.stats_frame = tk.Frame(self.status_frame, bg='#ecf0f1', relief=tk.GROOVE, bd=2)
        self.stats_frame.pack(fill=tk.X)
        
        stats_font = font.Font(family="Helvetica", size=14)
        
        # Create a 2x2 grid for statistics
        stats_grid = tk.Frame(self.stats_frame, bg='#ecf0f1')
        stats_grid.pack(pady=20)
        
        # Elapsed time
        tk.Label(stats_grid, text="Elapsed Time:", font=stats_font, 
                fg='#2c3e50', bg='#ecf0f1').grid(row=0, column=0, sticky='e', padx=(0, 10), pady=5)
        self.elapsed_time_label = tk.Label(stats_grid, text="0:00", font=stats_font, 
                                          fg='#27ae60', bg='#ecf0f1')
        self.elapsed_time_label.grid(row=0, column=1, sticky='w', pady=5)
        
        # Files scanned
        tk.Label(stats_grid, text="Files Scanned:", font=stats_font, 
                fg='#2c3e50', bg='#ecf0f1').grid(row=0, column=2, sticky='e', padx=(20, 10), pady=5)
        self.files_scanned_label = tk.Label(stats_grid, text="0", font=stats_font, 
                                           fg='#3498db', bg='#ecf0f1')
        self.files_scanned_label.grid(row=0, column=3, sticky='w', pady=5)
        
        # Threats found
        tk.Label(stats_grid, text="Threats Found:", font=stats_font, 
                fg='#2c3e50', bg='#ecf0f1').grid(row=1, column=0, sticky='e', padx=(0, 10), pady=5)
        self.threats_found_label = tk.Label(stats_grid, text="0", font=stats_font, 
                                           fg='#e74c3c', bg='#ecf0f1')
        self.threats_found_label.grid(row=1, column=1, sticky='w', pady=5)
        
        # Total files
        tk.Label(stats_grid, text="Total Files:", font=stats_font, 
                fg='#2c3e50', bg='#ecf0f1').grid(row=1, column=2, sticky='e', padx=(20, 10), pady=5)
        self.total_files_label = tk.Label(stats_grid, text="0", font=stats_font, 
                                         fg='#7f8c8d', bg='#ecf0f1')
        self.total_files_label.grid(row=1, column=3, sticky='w', pady=5)
        
        # Start the GUI update loop
        self._update_display()
        
    def _on_escape(self, event):
        """Handle escape key press"""
        if not self.config.get('kiosk.prevent_exit', True):
            self.running = False
            self.root.quit()
        else:
            logger.info("Exit attempt blocked in kiosk mode")
            
    def _prevent_close(self):
        """Prevent window closing in kiosk mode"""
        logger.info("Window close attempt blocked in kiosk mode")
        
    def _update_display(self):
        """Update the display - called periodically"""
        if not self.running:
            return
            
        try:
            if self.waiting_for_usb and not self.scan_in_progress:
                self._show_waiting_state()
            elif self.scan_in_progress:
                self._show_scanning_state()
            elif self.current_scan_result:
                self._show_results_state()
            else:
                self._show_waiting_state()
                
            # Update animation
            self.animation_index = (self.animation_index + 1) % len(self.animation_chars)
            
            # Schedule next update
            if self.root:
                self.root.after(1000, self._update_display)
                
        except tk.TclError:
            # Window was destroyed
            pass
        except Exception as e:
            logger.error(f"GUI update error: {e}", exc_info=True)
            
    def _show_waiting_state(self):
        """Show waiting for USB device state"""
        char = self.animation_chars[self.animation_index]
        self.info_label.configure(
            text=f"Please insert your USB device to begin scanning... {char}",
            fg='#2c3e50'
        )
        
        # Reset progress
        self.progress_bar['value'] = 0
        self.progress_label.configure(text="Progress: 0%")
        
        # Reset statistics
        self.elapsed_time_label.configure(text="0:00")
        self.files_scanned_label.configure(text="0")
        self.threats_found_label.configure(text="0")
        self.total_files_label.configure(text="0")
        
        # Show connection status
        removable_devices = [d for d in self.connected_devices if not self._is_system_device(d)]
        if removable_devices:
            status_text = f"Removable devices detected: {len(removable_devices)}"
        else:
            status_text = "No removable devices detected"
            
        # You could add a status label here if needed
        
    def _show_scanning_state(self):
        """Show scanning in progress state"""
        self.info_label.configure(
            text="Scanning in progress... Please wait while your USB device is scanned.",
            fg='#e67e22'
        )
        
        # Update progress if we have scan info
        if hasattr(self, 'scan_progress_info') and self.scan_progress_info:
            info = self.scan_progress_info
            total = info.get('total_files', 0)
            scanned = info.get('scanned_files', 0)
            threats = info.get('threats_found', 0)
            
            if total > 0:
                percentage = (scanned / total) * 100
                self.progress_bar['value'] = percentage
                self.progress_label.configure(text=f"Progress: {scanned}/{total} files ({percentage:.1f}%)")
            else:
                # Indeterminate progress when preparing
                if not hasattr(self, '_indeterminate_started'):
                    self.progress_bar.configure(mode='indeterminate')
                    self.progress_bar.start(10)
                    self._indeterminate_started = True
                self.progress_label.configure(text="Preparing scan...")
                
            # Update statistics
            self.files_scanned_label.configure(text=str(scanned))
            self.threats_found_label.configure(text=str(threats))
            self.total_files_label.configure(text=str(total))
        else:
            # No scan info yet - show indeterminate progress
            if not hasattr(self, '_indeterminate_started'):
                self.progress_bar.configure(mode='indeterminate')
                self.progress_bar.start(10)
                self._indeterminate_started = True
            self.progress_label.configure(text="Initializing...")
            
        # Update elapsed time
        if self.start_time:
            elapsed = time.time() - self.start_time
            minutes, seconds = divmod(int(elapsed), 60)
            self.elapsed_time_label.configure(text=f"{minutes}:{seconds:02d}")
            
    def _show_results_state(self):
        """Show scan results state"""
        if not self.current_scan_result:
            return
            
        result = self.current_scan_result
        threats_found = result.get('threats_found', 0)
        status = result.get('status', 'Unknown')
        
        # Stop indeterminate progress if running
        if hasattr(self, '_indeterminate_started'):
            self.progress_bar.stop()
            self.progress_bar.configure(mode='determinate')
            delattr(self, '_indeterminate_started')
            
        # Handle error states
        if status.startswith('Error:'):
            self.info_label.configure(
                text=f"❌ SCAN ERROR: {status[7:]}\n\nPlease try again with another device.",
                fg='#e74c3c'
            )
            self.progress_bar['value'] = 0
            self.progress_label.configure(text="Error occurred")
            
        elif threats_found == 0:
            self.info_label.configure(
                text="✓ SCAN COMPLETE - CLEAN\n\nNo threats detected! Your USB device appears to be safe.\n\nRemove USB device to scan another.",
                fg='#27ae60'
            )
            self.progress_bar['value'] = 100
            self.progress_label.configure(text="Scan completed successfully")
            
        else:
            self.info_label.configure(
                text=f"⚠ THREATS DETECTED!\n\nFound {threats_found} potential threat(s) on your USB device.\n\nRemove USB device to scan another.",
                fg='#e74c3c'
            )
            self.progress_bar['value'] = 100
            self.progress_label.configure(text="Scan completed - threats found")
            
        # Update final statistics
        if not status.startswith('Error:'):
            self.files_scanned_label.configure(text=str(result.get('scanned_files', 0)))
            self.threats_found_label.configure(text=str(threats_found))
            self.total_files_label.configure(text=str(result.get('scanned_files', 0)))
            
            # Show final scan time
            scan_time = result.get('scan_time', 0)
            minutes, seconds = divmod(int(scan_time), 60)
            self.elapsed_time_label.configure(text=f"{minutes}:{seconds:02d}")
    
    def run(self):
        """Run the kiosk mode interface"""
        self.running = True
        logger.info("Starting ArgusPI v2 Kiosk Mode - GUI Version")
        
        try:
            # Create the GUI
            self._create_gui()
            
            # Show welcome if configured
            if self.config.get('kiosk.show_welcome', True):
                self._show_welcome_screen()
            
            # Start the tkinter main loop
            self.root.mainloop()
            
        except Exception as e:
            logger.error(f"Kiosk GUI error: {e}", exc_info=True)
        finally:
            self.running = False
            if self.root:
                try:
                    self.root.quit()
                    self.root.destroy()
                except tk.TclError:
                    pass
                    
    def _show_welcome_screen(self):
        """Show welcome screen briefly"""
        def show_welcome():
            if self.info_label:
                welcome_text = (f"Welcome to {self.station_name}!\n\n"
                               f"{self.config.get('app.name', 'ArgusPI v2')} - Version {self.config.get('app.version', '2.0.0')}\n\n"
                               "This system will automatically scan your USB device\n"
                               "for viruses and malware when you plug it in.\n\n"
                               "Please insert your USB device to begin scanning...")
                self.info_label.configure(text=welcome_text, fg='#2c3e50')
                
        def reset_to_waiting():
            # Reset to normal waiting state after 5 seconds
            if self.running and self.waiting_for_usb:
                self._show_waiting_state()
                
        # Schedule welcome text and then reset
        if self.root:
            self.root.after(100, show_welcome)
            self.root.after(5000, reset_to_waiting)
    
    def on_usb_connected(self, device_info):
        """Handle USB device connection in kiosk mode"""
        if device_info not in self.connected_devices:
            self.connected_devices.append(device_info)
        
        logger.info(f"Kiosk: USB device connected: {device_info}")
        
        # Auto-start scan if enabled, not already scanning, and device has mount point
        # Only scan removable devices (not system drives)
        if (self.auto_scan_enabled and not self.scan_in_progress and 
            device_info.mount_point and self.waiting_for_usb and
            not self._is_system_device(device_info)):
            self.waiting_for_usb = False
            self.scanned_device = device_info
            self._start_auto_scan(device_info)
    
    def on_usb_disconnected(self, device_info):
        """Handle USB device disconnection in kiosk mode"""
        if device_info in self.connected_devices:
            self.connected_devices.remove(device_info)
        
        logger.info(f"Kiosk: USB device disconnected: {device_info}")
        
        # Only reset if the disconnected device was the one being scanned
        if self.scanned_device and self._devices_match(device_info, self.scanned_device):
            logger.info("Scanned device removed - resetting kiosk for next user")
            self._reset_kiosk_state()
    
    def _devices_match(self, device1, device2):
        """Check if two device info objects represent the same device"""
        if not device1 or not device2:
            return False
        return (device1.device_path == device2.device_path and 
                device1.mount_point == device2.mount_point)
    
    def _is_system_device(self, device_info):
        """Check if device is a system device that shouldn't be auto-scanned"""
        if not device_info.mount_point:
            return True
        
        # System mount points to avoid
        system_mounts = ['/', '/boot', '/boot/efi', '/mnt', '/home', '/usr', '/var', '/tmp']
        return device_info.mount_point in system_mounts
    
    def _reset_kiosk_state(self):
        """Reset kiosk state for next user"""
        self.current_scan_result = None
        self.scan_in_progress = False
        self.waiting_for_usb = True
        self.scanned_device = None
        self.start_time = None
        
        # Stop indeterminate progress if running
        if hasattr(self, '_indeterminate_started'):
            if self.progress_bar:
                self.progress_bar.stop()
                self.progress_bar.configure(mode='determinate')
            delattr(self, '_indeterminate_started')
        
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
        self.start_time = time.time()
        
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