"""
SIEM Integration for ArgusPI v2
Supports multiple protocols and formats for security event logging
"""

import json
import socket
import logging
import syslog
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import requests
from threading import Thread
import queue

logger = logging.getLogger(__name__)


class SIEMClient:
    """SIEM integration client supporting multiple protocols"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('siem.enabled', False)
        self.protocol = config.get('siem.protocol', 'syslog').lower()
        self.server = config.get('siem.server', 'localhost')
        self.port = config.get('siem.port', 514)
        self.format = config.get('siem.format', 'json').lower()
        self.timeout = config.get('siem.timeout', 5)
        self.station_name = config.get('station.name', 'ArgusPI Scanner')
        
        # Event configuration
        self.events = config.get('siem.events', {})
        
        # Message queue for async sending
        self.message_queue = queue.Queue()
        self.worker_thread = None
        
        if self.enabled:
            self._start_worker()
            logger.info(f"SIEM client initialized: {self.protocol}://{self.server}:{self.port}")
    
    def _start_worker(self):
        """Start background worker thread for async message sending"""
        self.worker_thread = Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
    
    def _worker(self):
        """Background worker to send messages asynchronously"""
        while True:
            try:
                message = self.message_queue.get(timeout=1)
                if message is None:  # Shutdown signal
                    break
                self._send_message_sync(message)
                self.message_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"SIEM worker error: {e}")
    
    def send_event(self, event_type: str, data: Dict[str, Any], priority: str = 'info'):
        """Send security event to SIEM"""
        if not self.enabled or not self.events.get(event_type, True):
            return
        
        try:
            message = self._format_message(event_type, data, priority)
            self.message_queue.put(message)
        except Exception as e:
            logger.error(f"Failed to queue SIEM message: {e}")
    
    def _format_message(self, event_type: str, data: Dict[str, Any], priority: str) -> Dict[str, Any]:
        """Format message according to configured format"""
        timestamp = datetime.now(timezone.utc).isoformat()
        
        base_data = {
            'timestamp': timestamp,
            'station_name': self.station_name,
            'event_type': event_type,
            'priority': priority,
            **data
        }
        
        if self.format == 'json':
            return {
                'format': 'json',
                'data': base_data
            }
        elif self.format == 'cef':
            return {
                'format': 'cef',
                'data': self._format_cef(event_type, base_data)
            }
        elif self.format == 'leef':
            return {
                'format': 'leef',
                'data': self._format_leef(event_type, base_data)
            }
        else:
            return {
                'format': 'json',
                'data': base_data
            }
    
    def _format_cef(self, event_type: str, data: Dict[str, Any]) -> str:
        """Format message in Common Event Format (CEF)"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        cef_header = f"CEF:0|ArgusPI|USB Scanner|2.0|{event_type}|{event_type.replace('_', ' ').title()}|{self._priority_to_severity(data.get('priority', 'info'))}"
        
        extensions = []
        for key, value in data.items():
            if key not in ['priority', 'event_type']:
                extensions.append(f"{key}={value}")
        
        extension_str = ' '.join(extensions)
        return f"{cef_header}|{extension_str}"
    
    def _format_leef(self, event_type: str, data: Dict[str, Any]) -> str:
        """Format message in Log Event Extended Format (LEEF)"""
        # LEEF:Version|Vendor|Product|Version|EventID|[Extension]
        leef_header = f"LEEF:2.0|ArgusPI|USB Scanner|2.0|{event_type}"
        
        extensions = []
        for key, value in data.items():
            extensions.append(f"{key}={value}")
        
        extension_str = '\t'.join(extensions)
        return f"{leef_header}|{extension_str}"
    
    def _priority_to_severity(self, priority: str) -> int:
        """Convert priority string to CEF severity number"""
        severity_map = {
            'low': 3,
            'info': 5,
            'medium': 6,
            'high': 8,
            'critical': 10
        }
        return severity_map.get(priority.lower(), 5)
    
    def _send_message_sync(self, message: Dict[str, Any]):
        """Send message synchronously using configured protocol"""
        try:
            if self.protocol == 'syslog':
                self._send_syslog(message)
            elif self.protocol == 'http':
                self._send_http(message)
            elif self.protocol == 'tcp':
                self._send_tcp(message)
            else:
                logger.error(f"Unsupported SIEM protocol: {self.protocol}")
        except Exception as e:
            logger.error(f"Failed to send SIEM message via {self.protocol}: {e}")
    
    def _send_syslog(self, message: Dict[str, Any]):
        """Send message via syslog"""
        facility = self._get_syslog_facility()
        priority_level = self._get_syslog_priority(message['data'].get('priority', 'info'))
        
        if message['format'] == 'json':
            msg = json.dumps(message['data'])
        else:
            msg = message['data']
        
        # Send to remote syslog server
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            priority = facility * 8 + priority_level
            syslog_msg = f"<{priority}>{msg}"
            sock.sendto(syslog_msg.encode('utf-8'), (self.server, self.port))
        finally:
            sock.close()
    
    def _send_http(self, message: Dict[str, Any]):
        """Send message via HTTP POST"""
        url = f"http://{self.server}:{self.port}/events"
        headers = {'Content-Type': 'application/json'}
        
        if message['format'] == 'json':
            data = json.dumps(message['data'])
        else:
            data = message['data']
        
        response = requests.post(url, data=data, headers=headers, timeout=self.timeout)
        response.raise_for_status()
    
    def _send_tcp(self, message: Dict[str, Any]):
        """Send message via TCP socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.server, self.port))
            
            if message['format'] == 'json':
                data = json.dumps(message['data'])
            else:
                data = str(message['data'])
            
            # Add newline for TCP protocols
            sock.send((data + '\n').encode('utf-8'))
        finally:
            sock.close()
    
    def _get_syslog_facility(self) -> int:
        """Get syslog facility number"""
        facility_map = {
            'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
            'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
            'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
            'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
            'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23
        }
        facility_name = self.config.get('siem.facility', 'local0')
        return facility_map.get(facility_name, 16)
    
    def _get_syslog_priority(self, priority: str) -> int:
        """Get syslog priority level"""
        priority_map = {
            'emergency': 0, 'alert': 1, 'critical': 2, 'error': 3,
            'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
        }
        return priority_map.get(priority.lower(), 6)
    
    def shutdown(self):
        """Shutdown SIEM client"""
        if self.worker_thread and self.worker_thread.is_alive():
            self.message_queue.put(None)  # Shutdown signal
            self.worker_thread.join(timeout=2)


# Convenience functions for common events
def send_scan_start_event(siem_client: SIEMClient, device_path: str):
    """Send scan start event"""
    siem_client.send_event('scan_start', {
        'device_path': device_path,
        'action': 'scan_initiated'
    }, 'info')

def send_scan_complete_event(siem_client: SIEMClient, device_path: str, 
                           scanned_files: int, threats_found: int, scan_time: float):
    """Send scan complete event"""
    priority = 'high' if threats_found > 0 else 'info'
    siem_client.send_event('scan_complete', {
        'device_path': device_path,
        'scanned_files': scanned_files,
        'threats_found': threats_found,
        'scan_time_seconds': scan_time,
        'action': 'scan_completed'
    }, priority)

def send_threat_found_event(siem_client: SIEMClient, device_path: str, threats: list):
    """Send threats found event"""
    siem_client.send_event('threats_found', {
        'device_path': device_path,
        'threat_count': len(threats),
        'threats': threats,
        'action': 'threats_detected'
    }, 'critical')

def send_usb_event(siem_client: SIEMClient, event_type: str, device_info: str):
    """Send USB connection/disconnection event"""
    siem_client.send_event(event_type, {
        'device_info': str(device_info),
        'action': f'usb_{event_type.split("_")[1]}'
    }, 'info')

def send_system_error_event(siem_client: SIEMClient, error_message: str, component: str):
    """Send system error event"""
    siem_client.send_event('system_errors', {
        'error_message': error_message,
        'component': component,
        'action': 'system_error'
    }, 'error')