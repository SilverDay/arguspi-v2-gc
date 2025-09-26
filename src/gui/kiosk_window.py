"""
Kiosk Mode GUI window for ArgusPI v2
Provides a simplified, full-screen interface for public use
"""

import time
import threading
import os
import subprocess
import signal
import shutil
from contextlib import suppress
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

        self.watchdog_enabled = config.get('kiosk.watchdog.enabled', True)
        self.watchdog_interval = config.get('kiosk.watchdog.interval', 5)
        self.watchdog_timeout = config.get('kiosk.watchdog.timeout', 30)
        self.watchdog_action = (config.get('kiosk.watchdog.action', 'restart-service') or 'restart-service').lower()
        self.watchdog_service = config.get('kiosk.watchdog.service_name', 'arguspi')
        self._watchdog_stop = threading.Event()
        self._watchdog_thread: Optional[threading.Thread] = None
        self._last_watchdog_heartbeat = time.time()
        self._watchdog_triggered = False

        terminal_lock_defaults = {
            'extended': True,
            'disable_vt_switch': True,
            'disable_sysrq': False,
        }
        terminal_lock_config = config.get('kiosk.terminal_lock', {}) or {}
        if not isinstance(terminal_lock_config, dict):
            terminal_lock_config = {}

        self.lock_extended = terminal_lock_config.get('extended', terminal_lock_defaults['extended'])
        self.lock_disable_vt = terminal_lock_config.get('disable_vt_switch', terminal_lock_defaults['disable_vt_switch'])
        self.lock_disable_sysrq = terminal_lock_config.get('disable_sysrq', terminal_lock_defaults['disable_sysrq'])

        self._vt_switch_locked = False
        self._vt_switch_original: Optional[str] = None
        self._sysrq_original: Optional[str] = None
        self._orig_signal_handlers: Dict[int, Any] = {}
        self._stty_state: Optional[str] = None
        
        logger.info(f"Kiosk GUI initialized for station: {self.station_name}")
    
    def run(self):
        """Run the kiosk mode interface"""
        self.running = True
        logger.info("Starting ArgusPI v2 Kiosk Mode")
        
        # Hide cursor and clear screen for full-screen experience
        self._setup_kiosk_display()
        self._start_watchdog()
        
        try:
            # Show welcome screen
            if self.config.get('kiosk.show_welcome', True):
                self._show_kiosk_welcome()
            
            # Main kiosk loop
            while self.running:
                try:
                    self._touch_watchdog()
                    
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
            self._stop_watchdog()
            self._cleanup_kiosk_display()
            self.running = False
    
    def _setup_kiosk_display(self):
        """Setup the display for kiosk mode"""
        try:
            self._capture_stty_state()
            print('\033[?25h', end='', flush=True)

            self._restore_signal_handlers()
            self._unlock_vt_switch()
            self._restore_sysrq()
            self._restore_stty_state()

            # Clear screen on exit
            self._clear_screen()

            self._apply_signal_locks()

            if self.config.get('kiosk.prevent_exit', True):
                if self.lock_extended:
                    self._enforce_extended_terminal_lock()
                else:
                    self._run_shell_command('stty -echo -icanon 2>/dev/null || true')

            if self.config.get('kiosk.hide_system_info', True):
                self._run_shell_command('stty intr undef susp undef quit undef 2>/dev/null || true')

            if self.lock_disable_vt:
                self._lock_vt_switch()

            if self.lock_disable_sysrq:
                self._disable_sysrq()
                
        except Exception as e:
            logger.warning(f"Could not setup kiosk display: {e}")
    
    def _cleanup_kiosk_display(self):
        """Cleanup kiosk display settings"""
        try:
            # Show cursor
            print('\033[?25h', end='', flush=True)
            
            # Restore terminal settings
            os.system('stty echo icanon intr ^C susp ^Z quit ^\\\\ 2>/dev/null || true')
            
            # Clear screen on exit
            os.system('clear')
            
        except Exception as e:
            logger.warning(f"Could not cleanup kiosk display: {e}")
    
    def _show_kiosk_welcome(self):
        """Show kiosk welcome screen"""
        self._clear_screen()
        
        print("=" * 80)
        print()
        print(f"        {self.station_name}")
        print(f"        {self.config.get('app.name', 'ArgusPI v2')} - KIOSK MODE")
        if self.station_location:
            print(f"        Location: {self.station_location}")
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
        
        print("\n" * 6)
        print("    " + "=" * 60)
        print("    |" + " " * 58 + "|")
        print("    |" + f" {self.station_name}".center(58) + "|")
        print("    |" + " " * 15 + "USB VIRUS SCANNER" + " " * 25 + "|")
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 10 + f"Please insert your USB device {char}" + " " * 15 + "|")
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 8 + "The device will be scanned automatically" + " " * 9 + "|")
        print("    |" + " " * 58 + "|")
        
        # Show helpful instructions
        print("    |" + " " * 58 + "|")
        print("    |" + " " * 12 + "Supported devices: USB flash drives" + " " * 11 + "|")
        print("    |" + " " * 10 + "Scan results will be displayed here" + " " * 13 + "|")
        print("    |" + " " * 58 + "|")
        print("    " + "=" * 60)
        print("\n" * 8)
        
        # Show connection status
        removable_devices = [d for d in self.connected_devices if not self._is_system_device(d)]
        if removable_devices:
            print(f"    Removable devices detected: {len(removable_devices)}")
        else:
            print("    No removable devices detected")
    
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
        
        # Handle error states
        if status.startswith('Error:'):
            print("    |" + " " * 20 + "❌ SCAN ERROR" + " " * 25 + "|")
            print("    |" + " " * 58 + "|")
            error_msg = status[7:][:40]  # Remove "Error: " prefix and limit length
            print(f"    |{' ' * 9}{error_msg}{' ' * (49 - len(error_msg))}|")
            print("    |" + " " * 58 + "|")
            print("    |" + " " * 8 + "Please try again with another device" + " " * 13 + "|")
            
        elif threats_found == 0:
            print("    |" + " " * 20 + "✓ SCAN COMPLETE - CLEAN" + " " * 17 + "|")
            print("    |" + " " * 58 + "|")
            print("    |" + " " * 15 + "No threats detected!" + " " * 24 + "|")
        else:
            print("    |" + " " * 18 + "⚠ THREATS DETECTED!" + " " * 19 + "|")
            print("    |" + " " * 58 + "|")
            threat_count_text = f"Found {threats_found} potential threat(s)"
            print(f"    |{' ' * 15}{threat_count_text}{' ' * (43 - len(threat_count_text))}|")
        
        print("    |" + " " * 58 + "|")
        
        # Show scan statistics if not an error
        if not status.startswith('Error:'):
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
    
    def _start_watchdog(self):
        """Start kiosk watchdog thread."""
        if not self.watchdog_enabled:
            return

        if self._watchdog_thread and self._watchdog_thread.is_alive():
            return

        self._watchdog_stop.clear()
        self._watchdog_triggered = False
        self._last_watchdog_heartbeat = time.time()

        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="arguspi-kiosk-watchdog",
            daemon=True
        )
        self._watchdog_thread.start()

    def _stop_watchdog(self):
        """Stop kiosk watchdog thread."""
        if not self._watchdog_thread:
            return

        self._watchdog_stop.set()
        self._watchdog_thread.join(timeout=max(2, int(self.watchdog_interval) + 1))
        self._watchdog_thread = None

    def _touch_watchdog(self):
        """Update watchdog heartbeat timestamp."""
        if self.watchdog_enabled:
            self._last_watchdog_heartbeat = time.time()

    def _watchdog_loop(self):
        """Background loop that monitors kiosk health."""
        logger.debug("Kiosk watchdog thread started")

        while not self._watchdog_stop.wait(self.watchdog_interval):
            if self._watchdog_triggered or not self.watchdog_enabled:
                continue

            elapsed = time.time() - self._last_watchdog_heartbeat
            if elapsed > self.watchdog_timeout:
                logger.error(
                    "Kiosk watchdog timeout exceeded (%.1fs > %.1fs). Initiating recovery.",
                    elapsed,
                    self.watchdog_timeout
                )
                self._watchdog_triggered = True
                self._handle_watchdog_timeout()
                break

        logger.debug("Kiosk watchdog thread exiting")

    def _handle_watchdog_timeout(self):
        """Perform configured watchdog action."""
        self._watchdog_stop.set()

        action = self.watchdog_action
        if action == 'restart-service':
            if not self._restart_service(self.watchdog_service):
                logger.error(
                    "Watchdog failed to restart service '%s'. Forcing process exit for supervisor recovery.",
                    self.watchdog_service
                )
                os._exit(1)

            logger.info("Watchdog restarted service '%s'; exiting process for clean restart.", self.watchdog_service)
            os._exit(0)

        if action == 'exit':
            logger.error("Watchdog exiting process to allow external restart.")
            os._exit(1)

        logger.warning("Unknown watchdog action '%s'; exiting as a safety fallback.", action)
        os._exit(1)

    def _restart_service(self, service_name: str) -> bool:
        """Attempt to restart the system service managing ArgusPI."""
        systemctl_path = shutil.which('systemctl')
        if not systemctl_path:
            logger.error("systemctl not available; cannot restart service '%s'.", service_name)
            return False

        cmd: List[str] = [systemctl_path, 'restart', service_name]
        geteuid = getattr(os, 'geteuid', None)
        if callable(geteuid) and geteuid() != 0:
            cmd.insert(0, 'sudo')

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Service restart command failed: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Unexpected error restarting service: %s", exc)
        return False

    def _run_shell_command(self, command: str):
        """Run a shell command suppressing output (best-effort)."""
        subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    def _capture_stty_state(self):
        """Save current terminal state to restore later."""
        try:
            result = subprocess.check_output(['stty', '-g'], stderr=subprocess.DEVNULL)
            self._stty_state = result.decode().strip()
        except Exception:
            self._stty_state = None

    def _restore_stty_state(self):
        """Restore saved terminal state."""
        if self._stty_state:
            with suppress(Exception):
                subprocess.run(['stty', self._stty_state], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            self._run_shell_command('stty sane 2>/dev/null || true')

    def _enforce_extended_terminal_lock(self):
        """Apply additional terminal locks beyond basic echo/canonical settings."""
        lock_commands = [
            'stty -echo -icanon -isig -ixoff -ixon min 1 time 0 2>/dev/null || true',
            'stty intr undef quit undef susp undef stop undef start undef eof undef eol undef eol2 undef swtch undef 2>/dev/null || true',
            'stty werase undef kill undef rprnt undef lnext undef discard undef 2>/dev/null || true',
        ]
        for cmd in lock_commands:
            self._run_shell_command(cmd)

    def _apply_signal_locks(self):
        """Ignore interactive terminal signals when kiosk prevent-exit is enabled."""
        if not self.config.get('kiosk.prevent_exit', True):
            return

        signals_to_lock = [signal.SIGINT]
        for sig_name in ('SIGTSTP', 'SIGQUIT'):
            sig_obj = getattr(signal, sig_name, None)
            if sig_obj is not None:
                signals_to_lock.append(sig_obj)

        for sig_obj in signals_to_lock:
            try:
                self._orig_signal_handlers[sig_obj] = signal.getsignal(sig_obj)
                signal.signal(sig_obj, signal.SIG_IGN)
            except Exception as exc:
                logger.debug("Unable to override signal %s: %s", sig_obj, exc)

    def _restore_signal_handlers(self):
        """Restore original signal handlers after kiosk shutdown."""
        for sig_obj, handler in self._orig_signal_handlers.items():
            with suppress(Exception):
                signal.signal(sig_obj, handler)
        self._orig_signal_handlers.clear()

    def _lock_vt_switch(self):
        """Prevent virtual-terminal switching (Ctrl+Alt+Fn)."""
        lock_path = Path('/sys/devices/virtual/tty/tty0/lock_vt_switch')
        if not lock_path.exists():
            return

        try:
            self._vt_switch_original = lock_path.read_text().strip()
        except Exception:
            self._vt_switch_original = None

        try:
            lock_path.write_text('1')
            self._vt_switch_locked = True
        except PermissionError:
            logger.debug("Insufficient permissions to lock VT switching.")
        except Exception as exc:
            logger.debug("Failed to lock VT switching: %s", exc)

    def _unlock_vt_switch(self):
        """Restore virtual-terminal switching state."""
        if not self._vt_switch_locked:
            return

        lock_path = Path('/sys/devices/virtual/tty/tty0/lock_vt_switch')
        try:
            value = self._vt_switch_original if self._vt_switch_original is not None else '0'
            lock_path.write_text(value)
        except Exception as exc:
            logger.debug("Failed to restore VT switching state: %s", exc)
        finally:
            self._vt_switch_locked = False
            self._vt_switch_original = None

    def _disable_sysrq(self):
        """Disable magic SysRq key if configured."""
        sysrq_path = Path('/proc/sys/kernel/sysrq')
        if not sysrq_path.exists():
            return

        try:
            self._sysrq_original = sysrq_path.read_text().strip()
        except Exception:
            self._sysrq_original = None

        try:
            sysrq_path.write_text('0')
        except PermissionError:
            logger.debug("Insufficient permissions to disable sysrq.")
        except Exception as exc:
            logger.debug("Failed to disable sysrq: %s", exc)

    def _restore_sysrq(self):
        """Restore SysRq state if it was changed."""
        if self._sysrq_original is None:
            return

        sysrq_path = Path('/proc/sys/kernel/sysrq')
        if not sysrq_path.exists():
            return

        try:
            sysrq_path.write_text(self._sysrq_original)
        except Exception as exc:
            logger.debug("Failed to restore sysrq state: %s", exc)
        finally:
            self._sysrq_original = None

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
        self._touch_watchdog()

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
        self._touch_watchdog()

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
        self._touch_watchdog()
        self.current_scan_result = None
        self.scan_in_progress = False
        self.waiting_for_usb = True
        self.scanned_device = None
        
        # Clear any scan progress info
        if hasattr(self, 'scan_progress_info'):
            self.scan_progress_info = None
    
    def _start_auto_scan(self, device_info):
        """Start automatic scan of connected device"""
        self._touch_watchdog()
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
        
        self._touch_watchdog()
        self.scan_progress_info = progress_info
        
        # Log progress occasionally
        if progress_info.get('phase') == 'scanning':
            scanned = progress_info.get('scanned_files', 0)
            total = progress_info.get('total_files', 0)
            if scanned % 50 == 0:  # Log every 50 files
                logger.debug(f"Scan progress: {scanned}/{total} files")
    
    def on_threat_detected(self, threat_info: Dict[str, Any]):
        """Record threat notifications during kiosk scans."""
        if not threat_info:
            return

        self._touch_watchdog()

        file_path = threat_info.get('file', 'unknown')
        threat_name = threat_info.get('threat', 'Potential threat')
        engine = threat_info.get('engine', 'engine')
        logger.warning(
            "Kiosk alert: threat detected by %s: %s (file=%s)",
            engine,
            threat_name,
            file_path,
        )

        if not isinstance(self.current_scan_result, dict):
            self.current_scan_result = {
                'scanned_files': 0,
                'threats_found': 0,
                'status': 'In progress',
                'threats': [],
                'scan_time': 0,
            }

        threats = self.current_scan_result.setdefault('threats', [])
        threats.append({key: value for key, value in threat_info.items() if key != 'scan_result'})
        self.current_scan_result['threats_found'] = len(threats)

    def on_scan_complete(self, scan_result):
        """Handle scan completion in kiosk mode"""
        self._touch_watchdog()
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
        self._touch_watchdog()
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
