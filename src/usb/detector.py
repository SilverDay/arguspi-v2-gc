"""
USB device detection and management for ArgusPI v2
"""

import os
import time
import subprocess
import threading
from pathlib import Path
from typing import Optional, Callable, Dict, List
import psutil

from logging.logger import get_logger

logger = get_logger(__name__)


class USBDeviceInfo:
    """Information about a USB device"""
    
    def __init__(self, device_path: str, mount_point: Optional[str] = None, 
                 filesystem: Optional[str] = None, size: int = 0, label: Optional[str] = None):
        self.device_path = device_path
        self.mount_point = mount_point
        self.filesystem = filesystem
        self.size = size
        self.label = label
        self.connected_time = time.time()
    
    def __str__(self):
        return f"USB Device: {self.device_path} ({self.filesystem}, {self._format_size()}) at {self.mount_point}"
    
    def _format_size(self) -> str:
        """Format device size in human readable format"""
        if self.size < 1024:
            return f"{self.size} B"
        elif self.size < 1024 * 1024:
            return f"{self.size / 1024:.1f} KB"
        elif self.size < 1024 * 1024 * 1024:
            return f"{self.size / (1024 * 1024):.1f} MB"
        else:
            return f"{self.size / (1024 * 1024 * 1024):.1f} GB"


class USBDetector:
    """USB device detector with automatic mounting and read-only protection"""
    
    def __init__(self, config):
        self.config = config
        self.monitoring = False
        self.devices = {}  # device_path -> USBDeviceInfo
        
        # Callbacks
        self.on_device_connected: Optional[Callable] = None
        self.on_device_disconnected: Optional[Callable] = None
        
        self.mount_base = Path(config.get('usb.mount_point', '/media/arguspi'))
        self.read_only = config.get('usb.read_only', True)
        self.supported_fs = config.get('usb.supported_filesystems', ['vfat', 'ntfs', 'ext2', 'ext3', 'ext4'])
        
        # Ensure mount base directory exists
        self.mount_base.mkdir(parents=True, exist_ok=True)
    
    def start_monitoring(self):
        """Start monitoring for USB device changes"""
        logger.info("Starting USB device monitoring...")
        self.monitoring = True
        
        # Initial scan for existing devices
        self._scan_existing_devices()
        
        # Monitor for changes
        while self.monitoring:
            try:
                current_devices = self._get_current_devices()
                
                # Check for new devices
                for device_path, device_info in current_devices.items():
                    if device_path not in self.devices:
                        self._handle_device_connected(device_info)
                
                # Check for removed devices
                for device_path in list(self.devices.keys()):
                    if device_path not in current_devices:
                        self._handle_device_disconnected(self.devices[device_path])
                
                time.sleep(2)  # Poll every 2 seconds
                
            except Exception as e:
                logger.error(f"Error in USB monitoring: {e}", exc_info=True)
                time.sleep(5)  # Longer wait on error
    
    def stop_monitoring(self):
        """Stop USB device monitoring"""
        logger.info("Stopping USB device monitoring...")
        self.monitoring = False
        
        # Unmount all devices we mounted
        for device_info in self.devices.values():
            if device_info.mount_point:
                self._unmount_device(device_info)
    
    def _scan_existing_devices(self):
        """Scan for already connected USB devices"""
        current_devices = self._get_current_devices()
        for device_path, device_info in current_devices.items():
            self.devices[device_path] = device_info
            logger.info(f"Found existing USB device: {device_info}")
    
    def _get_current_devices(self) -> Dict[str, USBDeviceInfo]:
        """Get currently connected USB devices"""
        devices = {}
        
        try:
            # Use lsblk to get block device information
            result = subprocess.run(['lsblk', '-J', '-o', 'NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL'], 
                                    capture_output=True, text=True, check=True)
            
            import json
            data = json.loads(result.stdout)
            
            for device in data.get('blockdevices', []):
                self._process_block_device(device, devices, '/dev/')
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get device list: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse lsblk output: {e}")
        except Exception as e:
            logger.error(f"Error getting current devices: {e}")
        
        return devices
    
    def _process_block_device(self, device: dict, devices: dict, parent_path: str):
        """Process block device information recursively"""
        device_name = device.get('name', '')
        device_path = parent_path + device_name
        
        # Check if this looks like a USB device
        if self._is_usb_device(device_path):
            fstype = device.get('fstype')
            size = self._parse_size(device.get('size', '0'))
            mountpoint = device.get('mountpoint')
            label = device.get('label')
            
            if fstype in self.supported_fs:
                device_info = USBDeviceInfo(
                    device_path=device_path,
                    mount_point=mountpoint,
                    filesystem=fstype,
                    size=size,
                    label=label
                )
                devices[device_path] = device_info
        
        # Process child devices (partitions)
        for child in device.get('children', []):
            self._process_block_device(child, devices, parent_path)
    
    def _is_usb_device(self, device_path: str) -> bool:
        """Check if device is a USB device"""
        try:
            # Check if device path contains USB indicators
            if '/dev/sd' in device_path:
                # Check if it's actually USB via udev
                result = subprocess.run(['udevadm', 'info', '--query=property', '--name', device_path],
                                        capture_output=True, text=True)
                return 'ID_BUS=usb' in result.stdout
            return False
        except Exception as e:
            logger.debug(f"Error checking if {device_path} is USB: {e}")
            return False
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes"""
        if not size_str or size_str == '0':
            return 0
        
        size_str = size_str.strip().upper()
        multipliers = {'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
        
        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[:-1]) * multiplier)
                except ValueError:
                    pass
        
        try:
            return int(size_str)
        except ValueError:
            return 0
    
    def _handle_device_connected(self, device_info: USBDeviceInfo):
        """Handle a newly connected device"""
        logger.info(f"USB device connected: {device_info}")
        
        # Mount the device if not already mounted
        if not device_info.mount_point:
            mount_point = self._mount_device(device_info)
            device_info.mount_point = mount_point
        
        self.devices[device_info.device_path] = device_info
        
        if self.on_device_connected:
            self.on_device_connected(device_info)
    
    def _handle_device_disconnected(self, device_info: USBDeviceInfo):
        """Handle a disconnected device"""
        logger.info(f"USB device disconnected: {device_info}")
        
        # Unmount if we mounted it
        if device_info.mount_point and device_info.mount_point.startswith(str(self.mount_base)):
            self._unmount_device(device_info)
        
        if device_info.device_path in self.devices:
            del self.devices[device_info.device_path]
        
        if self.on_device_disconnected:
            self.on_device_disconnected(device_info)
    
    def _mount_device(self, device_info: USBDeviceInfo) -> Optional[str]:
        """Mount a USB device"""
        try:
            # Create mount point
            device_name = Path(device_info.device_path).name
            mount_point = self.mount_base / device_name
            mount_point.mkdir(exist_ok=True)
            
            # Mount command with read-only option
            mount_options = ['ro'] if self.read_only else []
            
            cmd = ['sudo', 'mount']
            if mount_options:
                cmd.extend(['-o', ','.join(mount_options)])
            cmd.extend([device_info.device_path, str(mount_point)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Mounted {device_info.device_path} at {mount_point}")
            return str(mount_point)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to mount {device_info.device_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error mounting device: {e}")
            return None
    
    def _unmount_device(self, device_info: USBDeviceInfo):
        """Unmount a USB device"""
        if not device_info.mount_point:
            return
        
        try:
            subprocess.run(['sudo', 'umount', device_info.mount_point], 
                           capture_output=True, text=True, check=True)
            
            # Remove mount point if we created it
            if device_info.mount_point.startswith(str(self.mount_base)):
                Path(device_info.mount_point).rmdir()
            
            logger.info(f"Unmounted {device_info.device_path} from {device_info.mount_point}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unmount {device_info.mount_point}: {e}")
        except Exception as e:
            logger.error(f"Error unmounting device: {e}")
    
    def get_connected_devices(self) -> List[USBDeviceInfo]:
        """Get list of currently connected devices"""
        return list(self.devices.values())