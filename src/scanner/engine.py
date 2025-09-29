"""
Virus scanning engine for ArgusPI v2
"""

import os
import sys
import time
import threading
import importlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any, Tuple
import subprocess
import hashlib
import logging
import shutil

pyclamd = None
pyclamd_import_error: Optional[ImportError] = None
requests = None

try:
    pyclamd = importlib.import_module("pyclamd")
except ImportError as exc:  # pragma: no cover - optional engine
    pyclamd_import_error = exc
    pyclamd = None

try:
    requests = importlib.import_module("requests")
except ImportError:  # pragma: no cover - optional engine
    requests = None

# Use built-in logging until our custom logger is set up
logger = logging.getLogger(__name__)


class ScanResult:
    """Results from a virus scan"""
    
    def __init__(self):
        self.total_files = 0
        self.scanned_files = 0
        self.infected_files = 0
        self.threats = []  # List of detected threats
        self.scan_time = 0.0
        self.errors = []
        self.completed = False
        self.stopped = False
        self.device_path = ""
        self.clamav_files_scanned = 0
        self.quarantined_files: List[Dict[str, Any]] = []
    
    def add_threat(self, file_path: str, threat_name: str, engine: str = "") -> Dict[str, Any]:
        """Add a detected threat and return the recorded entry."""
        threat = {
            'file': file_path,
            'threat': threat_name,
            'engine': engine,
            'timestamp': time.time()
        }
        self.threats.append(threat)
        self.infected_files += 1
        return threat

    def add_quarantined_file(self, record: Dict[str, Any]) -> None:
        """Track a quarantined file associated with this scan."""
        self.quarantined_files.append(record)
    
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
        self.current_scan: ScanResult = ScanResult()
        self.stop_requested = False
        self._clamav_client = None
        self._clamav_enabled = False
        self._clamav_error_reported = False
        self._virustotal_enabled = False
        self._virustotal_api_key = ""
        self._virustotal_session = None
        self._virustotal_timeout = 30
        self._virustotal_daily_limit = 0
        self._virustotal_requests = 0
        self._virustotal_last_reset = datetime.now(timezone.utc).date()
        self._virustotal_cache: Dict[str, Tuple[bool, str]] = {}
        self._virustotal_error_reported = False
        self._clamav_requested = bool(config.get('scanner.engines.clamav.enabled', False))
        self._clamav_prefer_cli = bool(config.get('scanner.engines.clamav.prefer_cli', False))
        self._clamav_last_init_error = ""
        self._clamav_warning_logged = False
        self._scan_start_time: Optional[float] = None
        self._clamdscan_path: Optional[str] = None
        self.on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None

        default_cli_args = ['--fdpass', '--infected']
        cli_args_config = config.get('scanner.engines.clamav.cli_args', None)
        configured_cli_args: List[str] = []

        if isinstance(cli_args_config, str):
            configured_cli_args = [cli_args_config]
        elif isinstance(cli_args_config, (list, tuple)):
            configured_cli_args = [str(arg) for arg in cli_args_config]
        elif cli_args_config is not None:
            logger.warning(
                "Unexpected value for scanner.engines.clamav.cli_args (%r); using defaults",
                cli_args_config,
            )

        combined_args: List[str] = []
        for arg in default_cli_args + configured_cli_args:
            if not arg:
                continue
            if arg not in combined_args:
                combined_args.append(arg)

        self._clamdscan_extra_args = combined_args
        
        # Scanner configuration
        scan_types_config = config.get('scanner.scan_types', [
            'exe', 'dll', 'bat', 'cmd', 'scr', 'com', 'pif',
            'jar', 'zip', 'rar', '7z', 'doc', 'pdf'
        ])
        if isinstance(scan_types_config, str):
            scan_types_config = [scan_types_config]

        normalized_scan_types = [stype.strip().lower() for stype in scan_types_config]
        self._scan_all_file_types = (
            not normalized_scan_types
            or '*' in normalized_scan_types
            or 'all' in normalized_scan_types
        )
        self.scan_types = {
            stype.lstrip('.') for stype in normalized_scan_types if stype
        }

        self.exclude_patterns = config.get('scanner.exclude_patterns', [
            '*.log', 'System Volume Information', '$RECYCLE.BIN'
        ])
        
        self._setup_clamav_engine()
        self._setup_virustotal_engine()

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
        self.current_scan.device_path = device_path
        self._clamav_warning_logged = False

        if self._clamav_requested and not self._clamav_enabled:
            self._setup_clamav_engine()
        
        try:
            # Phase 1: Count files to scan
            logger.info("Counting files to scan...")
            self._count_scannable_files(device_path)

            if self._clamav_requested and not self._clamav_enabled and not self._clamav_warning_logged:
                warning = self._clamav_last_init_error or "ClamAV engine unavailable; verify clamd service and permissions"
                logger.warning(f"ClamAV engine is disabled: {warning}")
                self.current_scan.add_error(f"ClamAV engine unavailable: {warning}")
                self._clamav_warning_logged = True
            
            if progress_callback:
                progress_callback({
                    'phase': 'scanning',
                    'total_files': self.current_scan.total_files,
                    'scanned_files': 0,
                    'current_file': '',
                    'threats_found': 0,
                    'elapsed_time': 0.0,
                })
            
            # Phase 2: Scan files
            logger.info(f"Scanning {self.current_scan.total_files} files...")
            start_time = time.time()
            self._scan_start_time = start_time
            self._scan_files(device_path, progress_callback)
            self.current_scan.scan_time = time.time() - start_time
            
            # Mark as completed if not stopped
            if not self.stop_requested:
                self.current_scan.completed = True
                logger.info(
                    f"Scan completed. Found {self.current_scan.infected_files} threats in "
                    f"{self.current_scan.scan_time:.2f} seconds "
                    f"(ClamAV scanned {self.current_scan.clamav_files_scanned} files)"
                )
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
            self._scan_start_time = None
    
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
                                'threats_found': self.current_scan.infected_files,
                                'elapsed_time': (time.time() - self._scan_start_time) if self._scan_start_time else 0.0,
                            })
                        
                        # Small delay to allow UI updates
                        time.sleep(0.01)
                        
        except Exception as e:
            logger.error(f"Error during file scan: {e}")
            self.current_scan.add_error(str(e))
    
    def _record_threat(self, file_path: str, threat_name: str, engine: str) -> None:
        threat_entry = self.current_scan.add_threat(file_path, threat_name, engine)
        callback = self.on_threat_detected
        if callback:
            threat_info = {
                'file': file_path,
                'threat': threat_name,
                'engine': engine,
                'device_path': self.current_scan.device_path,
                'timestamp': time.time(),
                'scan_result': self.current_scan,
                'threat_entry': threat_entry,
            }
            try:
                callback(threat_info)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.debug("Threat callback failed: %s", exc, exc_info=True)

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
            
            if not self.stop_requested and self._clamav_enabled:
                self._scan_with_clamav(file_path)
            
            if not self.stop_requested and self._virustotal_enabled:
                self._scan_with_virustotal(file_path)
            
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
                    self._record_threat(
                        file_path,
                        f"Suspicious filename: {sus_name}",
                        "builtin",
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
                        self._record_threat(
                            file_path,
                            "Suspicious content pattern detected",
                            "builtin",
                        )
                        logger.warning(f"Suspicious content in: {file_path}")
                        return
                        
        except Exception as e:
            logger.debug(f"Error in builtin checks for {file_path}: {e}")

    def _setup_clamav_engine(self):
        if not self._clamav_requested:
            return

        cli_candidate = self.config.get('scanner.engines.clamav.cli_path', 'clamdscan') or 'clamdscan'
        candidates: List[str] = []
        if cli_candidate:
            candidates.append(str(cli_candidate))
        if 'clamdscan' not in candidates:
            candidates.append('clamdscan')

        self._clamdscan_path = None
        for candidate in candidates:
            path = shutil.which(candidate)
            if path:
                self._clamdscan_path = path
                break

        if self._clamav_prefer_cli:
            if self._clamdscan_path:
                logger.info(
                    "ClamAV configured to prefer CLI; using %s",
                    self._clamdscan_path,
                )
                self._clamav_client = None
                self._clamav_last_init_error = ""
                self._clamav_enabled = True
                return
            else:
                logger.warning(
                    "ClamAV CLI preference requested but no clamdscan executable found; attempting python client instead"
                )

        if pyclamd is None:
            detail = "pyclamd module not installed"
            if pyclamd_import_error:
                detail = f"pyclamd import failed: {pyclamd_import_error}"
            if self._clamdscan_path:
                logger.info(
                    "%s; falling back to ClamAV CLI at %s",
                    detail,
                    self._clamdscan_path,
                )
                self._clamav_last_init_error = ""
                self._clamav_enabled = True
            else:
                self._clamav_last_init_error = detail
                logger.warning(
                    "%s; disabling ClamAV engine (python=%s)",
                    detail,
                    sys.executable,
                )
                logger.debug("sys.path for ClamAV import: %s", sys.path)
                self._clamav_enabled = False
            return

        client = self._initialize_clamav_client()
        if client:
            self._clamav_client = client
            self._clamav_last_init_error = ""
            logger.info("ClamAV engine enabled via python bindings")
        elif self._clamdscan_path:
            logger.info(
                "ClamAV daemon unreachable via pyclamd; using CLI fallback at %s",
                self._clamdscan_path,
            )
            self._clamav_client = None
            self._clamav_last_init_error = ""
        else:
            if not self._clamav_last_init_error:
                self._clamav_last_init_error = "Unable to connect to clamd daemon (check socket path and permissions)"
            logger.warning("ClamAV engine configured but unavailable; continuing without it")

        self._clamav_enabled = bool(self._clamav_client or self._clamdscan_path)

    def _initialize_clamav_client(self):
        if pyclamd is None:
            return None

        socket_path = self.config.get('scanner.engines.clamav.socket')
        host = self.config.get('scanner.engines.clamav.host', '127.0.0.1')
        port = self.config.get('scanner.engines.clamav.port', 3310)

        try:
            if socket_path:
                client = pyclamd.ClamdUnixSocket(socket_path)
            else:
                try:
                    client = pyclamd.ClamdUnixSocket()
                except Exception:
                    client = pyclamd.ClamdNetworkSocket(host, port)
            client.ping()
            return client
        except Exception as e:
            self._clamav_last_init_error = str(e)
            logger.warning(f"Unable to initialize ClamAV engine: {e}")
            return None

    def _setup_virustotal_engine(self):
        if not self.config.get('scanner.engines.virustotal.enabled', False):
            return

        api_key_config = self.config.get('scanner.engines.virustotal.api_key', '') or ''
        api_key = os.getenv('VT_API_KEY', api_key_config).strip()

        if not api_key:
            logger.warning("VirusTotal API key not configured; disabling VirusTotal engine")
            return

        if requests is None:
            logger.warning("requests library not available; disabling VirusTotal engine")
            return

        self._virustotal_enabled = True
        self._virustotal_api_key = api_key

        try:
            self._virustotal_timeout = int(self.config.get('scanner.engines.virustotal.timeout', 30))
        except (TypeError, ValueError):
            self._virustotal_timeout = 30

        try:
            self._virustotal_daily_limit = int(self.config.get('scanner.engines.virustotal.max_daily_requests', 500))
        except (TypeError, ValueError):
            self._virustotal_daily_limit = 500

        self._virustotal_session = requests.Session()
        logger.info("VirusTotal engine enabled")

    def _reset_virustotal_counters_if_needed(self):
        today = datetime.now(timezone.utc).date()
        if today != self._virustotal_last_reset:
            self._virustotal_last_reset = today
            self._virustotal_requests = 0
            self._virustotal_error_reported = False

    def _can_make_virustotal_request(self) -> bool:
        if self._virustotal_daily_limit <= 0:
            return True
        return self._virustotal_requests < self._virustotal_daily_limit

    def _scan_with_clamav(self, file_path: str):
        if not self._clamav_enabled:
            return

        if self._clamav_client:
            try:
                result = self._clamav_client.scan_file(file_path)
                self.current_scan.clamav_files_scanned += 1
                if result:
                    for _, data in result.items():
                        if not data:
                            continue
                        status, signature = data
                        if status == 'FOUND':
                            signature_name = signature or 'ClamAV detection'
                            self._record_threat(file_path, signature_name, 'clamav')
                            logger.warning(f"ClamAV detected threat in {file_path}: {signature_name}")
                            break
                return
            except Exception as exc:
                if not self._clamav_error_reported:
                    logger.warning(f"ClamAV scan failed: {exc}")
                    self._clamav_error_reported = True
                self.current_scan.add_error(f"ClamAV scan failed for {file_path}: {exc}")
                self._clamav_last_init_error = str(exc)
                if self._clamdscan_path:
                    logger.warning(
                        "Disabling pyclamd client after failure; falling back to CLI for remaining files"
                    )
                    self._clamav_client = None
                    self._clamav_error_reported = False
                else:
                    self._clamav_enabled = False
                return

        if self._clamdscan_path:
            self._scan_with_clamdscan(file_path)

    def _scan_with_clamdscan(self, file_path: str):
        if not self._clamdscan_path:
            return

        cmd: List[str] = [self._clamdscan_path]
        if self._clamdscan_extra_args:
            cmd.extend(self._clamdscan_extra_args)
        if '--stdout' not in self._clamdscan_extra_args:
            cmd.append('--stdout')
        if '--no-summary' not in self._clamdscan_extra_args:
            cmd.append('--no-summary')
        cmd.append(file_path)

        try:
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            if not self._clamav_error_reported:
                logger.warning("ClamAV CLI executable not found at %s", self._clamdscan_path)
                self._clamav_error_reported = True
            self._clamdscan_path = None
            self._clamav_enabled = False
            return
        except Exception as exc:  # pragma: no cover - defensive
            if not self._clamav_error_reported:
                logger.warning("ClamAV CLI invocation failed: %s", exc)
                self._clamav_error_reported = True
            self.current_scan.add_error(f"ClamAV CLI failed for {file_path}: {exc}")
            return

        stdout = (process.stdout or '').strip()
        stderr = (process.stderr or '').strip()
        exit_code = process.returncode

        if exit_code == 0:
            self.current_scan.clamav_files_scanned += 1
            return

        if exit_code == 1:
            self.current_scan.clamav_files_scanned += 1
            detection_line = ''
            for line in reversed(stdout.splitlines()):
                if line.endswith('FOUND'):
                    detection_line = line
                    break

            signature_name = 'ClamAV detection'
            if detection_line:
                _, _, detail = detection_line.partition(':')
                detail = detail.strip()
                if detail.upper().endswith('FOUND'):
                    detail = detail[:-5].strip()
                if detail:
                    signature_name = detail

            self._record_threat(file_path, signature_name, 'clamav')
            logger.warning(f"ClamAV detected threat in {file_path}: {signature_name}")
            return

        message = stderr or stdout or f"clamdscan exited with code {exit_code}"
        self.current_scan.add_error(f"ClamAV CLI error for {file_path}: {message}")
        if not self._clamav_error_reported:
            logger.warning("ClamAV CLI error (code %s): %s", exit_code, message)
            self._clamav_error_reported = True

    def _scan_with_virustotal(self, file_path: str):
        if not self._virustotal_enabled or not self._virustotal_session:
            return

        self._reset_virustotal_counters_if_needed()
        if not self._can_make_virustotal_request():
            if not self._virustotal_error_reported:
                logger.warning("VirusTotal daily request limit reached; skipping further lookups")
                self._virustotal_error_reported = True
            return

        sha256 = self._hash_file(file_path)
        if not sha256:
            return

        cached = self._virustotal_cache.get(sha256)
        if cached is not None:
            malicious, detail = cached
            if malicious:
                self._record_threat(file_path, detail, 'virustotal')
            return

        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {'x-apikey': self._virustotal_api_key}

        try:
            response = self._virustotal_session.get(url, headers=headers, timeout=self._virustotal_timeout)
            self._virustotal_requests += 1
        except Exception as e:
            logger.warning(f"VirusTotal request failed: {e}")
            self.current_scan.add_error(f"VirusTotal error for {file_path}: {e}")
            return

        if response.status_code == 401:
            logger.error("VirusTotal API key rejected; disabling VirusTotal engine")
            self._virustotal_enabled = False
            return

        if response.status_code == 404:
            self._virustotal_cache[sha256] = (False, "")
            return

        if response.status_code != 200:
            logger.warning(
                f"VirusTotal lookup failed ({response.status_code}): {response.text[:200]}"
            )
            return

        try:
            payload = response.json()
        except ValueError as e:
            logger.warning(f"VirusTotal returned invalid JSON: {e}")
            return

        attributes = payload.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0) or stats.get('suspicious', 0)

        if not malicious:
            self._virustotal_cache[sha256] = (False, "")
            return

        analysis_results = attributes.get('last_analysis_results', {})
        details: List[str] = []
        for engine, result in analysis_results.items():
            if not isinstance(result, dict):
                continue
            if result.get('category') in ('malicious', 'suspicious') and result.get('result'):
                details.append(f"{engine}: {result['result']}")

        if not details:
            details.append('VirusTotal: malicious file detected')

        detail_summary = '; '.join(details[:5])
        self._virustotal_cache[sha256] = (True, detail_summary)
        self._record_threat(file_path, detail_summary, 'virustotal')
        logger.warning(f"VirusTotal detected threat in {file_path}: {detail_summary}")

    def _hash_file(self, file_path: str) -> Optional[str]:
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    if self.stop_requested:
                        return None
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.debug(f"Unable to hash file {file_path}: {e}")
            return None
    
    def _should_scan_file(self, filename: str) -> bool:
        """Check if file should be scanned"""
        if self._is_excluded(filename):
            return False

        if self._scan_all_file_types:
            return True

        file_ext = Path(filename).suffix.lower().lstrip('.')
        if not file_ext:
            return False

        return file_ext in self.scan_types
    
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
