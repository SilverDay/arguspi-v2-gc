"""
Virus scanning engine for ArgusPI v2
"""

import os
import time
import threading
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any
import subprocess
import hashlib
import logging

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class ScanResult:
    """Results from a virus scan"""
    
    def __init__(self):
        self.total_files = 0
        self.scanned_files = 0
        self.infected_files = 0
        self.threats = []  # List of detected threats
        self.scan_time = 0
        self.errors = []
        self.completed = False
        self.stopped = False
    
    def add_threat(self, file_path: str, threat_name: str, engine: str = ""):
        """Add a detected threat"""
        threat = {
            'file': file_path,
            'threat': threat_name,
            'engine': engine,
            'timestamp': time.time()
        }
        self.threats.append(threat)
        self.infected_files += 1
    
    def add_error(self, error_msg: str):
        """Add an error to the scan results"""
        self.errors.append({
            'message': error_msg,
            'timestamp': time.time()
        })


class ScanEngine:
    """Main scanning engine that coordinates different virus scanners"""
    
    def __init__(self, config):
        self.config = config
        self.scanning = False
        self.current_scan = None
        self.stop_requested = False
        
        # Scanner configuration
        self.scan_types = config.get('scanner.scan_types', [
            'exe', 'dll', 'bat', 'cmd', 'scr', 'com', 'pif', 
            'jar', 'zip', 'rar', '7z', 'doc', 'pdf'
        ])
        self.exclude_patterns = config.get('scanner.exclude_patterns', [
            '*.log', 'System Volume Information', '$RECYCLE.BIN'
        ])
        
        logger.info("Scan engine initialized")
    
    def scan_device(self, device_path: str, 
                   progress_callback: Optional[Callable] = None,
                   completion_callback: Optional[Callable] = None):
        """Start scanning a USB device"""
        logger.info(f"Starting scan of device: {device_path}")
        
        if self.scanning:
            logger.warning("Scan already in progress")
            return
        
        self.scanning = True
        self.stop_requested = False
        self.current_scan = ScanResult()
        
        try:
            # Phase 1: Count files to scan
            logger.info("Counting files to scan...")
            self._count_scannable_files(device_path)
            
            if progress_callback:
                progress_callback({
                    'phase': 'scanning',
                    'total_files': self.current_scan.total_files,
                    'scanned_files': 0,
                    'current_file': '',
                    'threats_found': 0
                })
            
            # Phase 2: Scan files
            logger.info(f"Scanning {self.current_scan.total_files} files...")
            start_time = time.time()
            self._scan_files(device_path, progress_callback)
            self.current_scan.scan_time = time.time() - start_time
            
            # Mark as completed if not stopped
            if not self.stop_requested:
                self.current_scan.completed = True
                logger.info(f"Scan completed. Found {self.current_scan.infected_files} threats in {self.current_scan.scan_time:.2f} seconds")
            else:
                self.current_scan.stopped = True
                logger.info("Scan stopped by user")
            
            # Call completion callback
            if completion_callback:
                completion_callback(self.current_scan)
                
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            self.current_scan.add_error(str(e))
            if completion_callback:
                completion_callback(self.current_scan)
        finally:
            self.scanning = False
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            logger.info("Stop scan requested")
            self.stop_requested = True
    
    def _count_scannable_files(self, device_path: str):
        """Count files that should be scanned"""
        count = 0
        try:
            for root, dirs, files in os.walk(device_path):
                if self.stop_requested:
                    break
                    
                # Skip excluded directories
                dirs[:] = [d for d in dirs if not self._is_excluded(d)]
                
                for file in files:
                    if self._should_scan_file(file):
                        count += 1
                        
        except Exception as e:
            logger.error(f"Error counting files: {e}")
            
        self.current_scan.total_files = count
        logger.info(f"Found {count} files to scan")
    
    def _scan_files(self, device_path: str, progress_callback: Optional[Callable]):
        """Scan all files in the device"""
        scanned = 0
        
        try:
            for root, dirs, files in os.walk(device_path):
                if self.stop_requested:
                    break
                    
                # Skip excluded directories
                dirs[:] = [d for d in dirs if not self._is_excluded(d)]
                
                for file in files:
                    if self.stop_requested:
                        break
                        
                    file_path = os.path.join(root, file)
                    
                    if self._should_scan_file(file):
                        self._scan_file(file_path)
                        scanned += 1
                        self.current_scan.scanned_files = scanned
                        
                        # Update progress
                        if progress_callback:
                            progress_callback({
                                'phase': 'scanning',
                                'total_files': self.current_scan.total_files,
                                'scanned_files': scanned,
                                'current_file': file_path,
                                'threats_found': self.current_scan.infected_files
                            })
                        
                        # Small delay to allow UI updates
                        time.sleep(0.01)
                        
        except Exception as e:
            logger.error(f"Error during file scan: {e}")
            self.current_scan.add_error(str(e))
    
    def _scan_file(self, file_path: str):
        """Scan a single file for viruses"""
        try:
            # Basic file checks
            if not os.path.isfile(file_path):
                return
                
            # Get file size
            file_size = os.path.getsize(file_path)
            max_size = self._parse_size(self.config.get('scanner.engines.clamav.max_file_size', '100M'))
            
            if file_size > max_size:
                logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return
            
            # Try different scanning methods
            self._scan_with_builtin_checks(file_path)
            
            # Note: In a real implementation, you would integrate with:
            # - ClamAV for local scanning
            # - VirusTotal API for cloud scanning
            # - Custom signature-based detection
            
        except Exception as e:
            logger.debug(f"Error scanning file {file_path}: {e}")
            self.current_scan.add_error(f"Error scanning {file_path}: {str(e)}")
    
    def _scan_with_builtin_checks(self, file_path: str):
        """Basic built-in security checks"""
        try:
            filename = os.path.basename(file_path).lower()
            
            # Check for suspicious file names
            suspicious_names = [
                'autorun.inf', 'desktop.ini', 'thumbs.db',
                'virus.exe', 'malware.exe', 'trojan.exe'
            ]
            
            for sus_name in suspicious_names:
                if sus_name in filename:
                    self.current_scan.add_threat(
                        file_path, 
                        f"Suspicious filename: {sus_name}",
                        "builtin"
                    )
                    logger.warning(f"Suspicious file detected: {file_path}")
                    return
            
            # Check file extension against known dangerous extensions
            dangerous_extensions = ['.scr', '.pif', '.bat', '.cmd', '.com']
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext in dangerous_extensions:
                # Read file content to check for suspicious patterns
                with open(file_path, 'rb') as f:
                    content = f.read(1024)  # Read first 1KB
                    
                # Look for suspicious patterns (basic)
                suspicious_patterns = [b'virus', b'malware', b'trojan', b'worm']
                
                for pattern in suspicious_patterns:
                    if pattern in content.lower():
                        self.current_scan.add_threat(
                            file_path,
                            f"Suspicious content pattern detected",
                            "builtin"
                        )
                        logger.warning(f"Suspicious content in: {file_path}")
                        return
                        
        except Exception as e:
            logger.debug(f"Error in builtin checks for {file_path}: {e}")
    
    def _should_scan_file(self, filename: str) -> bool:
        """Check if file should be scanned"""
        if self._is_excluded(filename):
            return False
            
        # Check if file extension is in scan types
        file_ext = Path(filename).suffix.lower().lstrip('.')
        return file_ext in [ext.lower() for ext in self.scan_types]
    
    def _is_excluded(self, path: str) -> bool:
        """Check if path matches exclusion patterns"""
        path_lower = path.lower()
        for pattern in self.exclude_patterns:
            if pattern.lower() in path_lower:
                return True
        return False
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10M' to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('K'):
            return int(size_str[:-1]) * 1024
        elif size_str.endswith('M'):
            return int(size_str[:-1]) * 1024 * 1024
        elif size_str.endswith('G'):
            return int(size_str[:-1]) * 1024 * 1024 * 1024
        else:
            return int(size_str)