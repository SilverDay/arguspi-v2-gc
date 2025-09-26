"""
USB device detection and management for ArgusPI v2
"""

import os
import time
import subprocess
from pathlib import Path
from typing import Optional, Callable, Dict, List, Any
import json
import logging
import importlib
import importlib.util

_pyudev_spec = importlib.util.find_spec("pyudev")
if _pyudev_spec is None:  # pragma: no cover - pyudev required at runtime
    raise RuntimeError("pyudev library is required for USB detection. Please install pyudev.")

pyudev = importlib.import_module("pyudev")
_PYUDEV_DEVICE_NOT_FOUND = getattr(pyudev, "DeviceNotFoundError", Exception)

# Use built-in logging until our custom logger is set up  
logger = logging.getLogger(__name__)


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
        self._context = pyudev.Context()
        self._monitor = None
        self._observer: Optional[Any] = None
        
        # Ensure mount base directory exists (use local directory if /media fails)
        try:
            self.mount_base.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback to local directory for testing
            self.mount_base = Path.cwd() / "test_mount"
            self.mount_base.mkdir(parents=True, exist_ok=True)
            logger.warning(f"Using fallback mount directory: {self.mount_base}")
        except Exception as e:
            logger.error(f"Could not create mount directory: {e}")
            self.mount_base = Path.cwd() / "test_mount"
            self.mount_base.mkdir(parents=True, exist_ok=True)
    
    def start_monitoring(self):
        """Start monitoring for USB device changes"""
        logger.info("Starting USB device monitoring...")

        if self.monitoring:
            logger.debug("USB monitoring already active")
            return

        self.monitoring = True

        try:
            self._monitor = pyudev.Monitor.from_netlink(self._context)
            # Listen for all block device events; handler will filter for USB partitions
            self._monitor.filter_by("block")
            observer = pyudev.MonitorObserver(
                self._monitor,
                callback=self._handle_udev_event,
                name="arguspi-usb-monitor",
                daemon=True
            )
            observer.start()
            self._observer = observer
            logger.debug("Started pyudev monitor observer")
        except Exception as error:
            self.monitoring = False
            self._observer = None
            self._monitor = None
            logger.error(f"Failed to start USB monitoring: {error}", exc_info=True)
            raise

        # Initial scan for devices that were present before monitoring began
        self._scan_existing_devices()
    
    def stop_monitoring(self):
        """Stop USB device monitoring"""
        logger.info("Stopping USB device monitoring...")
        if not self.monitoring:
            logger.debug("USB monitoring already stopped")
        self.monitoring = False

        observer = self._observer
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=3.0)
                logger.debug("Stopped pyudev monitor observer")
            except Exception as error:
                logger.debug(f"Error stopping monitor observer: {error}")
        self._observer = None
        self._monitor = None
        
        # Unmount all devices we mounted
        for device_info in list(self.devices.values()):
            if device_info.mount_point:
                self._unmount_device(device_info)
        self.devices.clear()
    
    def _scan_existing_devices(self):
        """Scan for already connected USB devices"""
        logger.debug("Scanning for existing USB devices...")
        try:
            current_devices = self._get_current_devices()
            logger.debug(f"Found {len(current_devices)} devices")
            for device_path, device_info in current_devices.items():
                logger.info(f"Found existing USB device: {device_info}")
                self._handle_device_connected(device_info)
        except Exception as e:
            logger.error(f"Error in _scan_existing_devices: {e}", exc_info=True)
    
    def _handle_udev_event(self, device: Any):
        """Handle pyudev events for USB devices"""
        action = getattr(device, "action", None)
        if action is None:
            try:
                action = device.get("ACTION")
            except Exception:  # pragma: no cover - pyudev internals
                action = None
        if not action:
            return
        if not self.monitoring:
            return

        device_node = getattr(device, "device_node", None)
        if not device_node:
            return

        if action not in {"add", "remove", "change"}:
            return

        if not self._is_usb_device(device_node, device):
            return

        logger.debug(f"udev event '{action}' received for {device_node}")

        if action == "add":
            device_info = self._create_device_info_from_udev(device_node, device)
            if not device_info:
                logger.debug(f"Skipping {device_node}: unable to collect filesystem details")
                return
            self._handle_device_connected(device_info)
        elif action == "remove":
            existing = self.devices.get(device_node)
            if existing:
                self._handle_device_disconnected(existing)
        elif action == "change":
            if device_node not in self.devices:
                return
            updated_info = self._create_device_info_from_udev(device_node, device)
            if updated_info:
                self._refresh_device_metadata(updated_info)

    def _create_device_info_from_udev(self, device_path: str, device: Any) -> Optional[USBDeviceInfo]:
        """Create USBDeviceInfo from a udev device"""
        filesystem = device.get('ID_FS_TYPE')
        label = device.get('ID_FS_LABEL') or device.get('ID_FS_LABEL_ENC')
        mount_point = self._find_mount_point(device_path)

        size = 0
        try:
            sectors = device.attributes.asint('size')
        except Exception:
            sectors = None

        if sectors:
            block_size = 512
            for attribute in ('queue/logical_block_size', 'queue/hw_sector_size', 'queue/physical_block_size'):
                try:
                    candidate = device.attributes.asint(attribute)
                except Exception:
                    continue
                if candidate:
                    block_size = candidate
                    break
            size = sectors * block_size

        if not filesystem:
            lsblk_info = self._lookup_device_via_lsblk(device_path)
            if lsblk_info:
                filesystem = lsblk_info.get('filesystem') or filesystem
                mount_point = mount_point or lsblk_info.get('mount_point')
                label = label or lsblk_info.get('label')
                size = size or lsblk_info.get('size', 0)

        if filesystem and filesystem not in self.supported_fs:
            logger.info(f"Unsupported filesystem {filesystem} for {device_path}")
            return None

        return USBDeviceInfo(
            device_path=device_path,
            mount_point=mount_point,
            filesystem=filesystem,
            size=size,
            label=label
        )

    def _lookup_device_via_lsblk(self, device_path: str) -> Optional[Dict[str, Any]]:
        """Use lsblk to collect metadata for a specific device"""
        try:
            result = subprocess.run(
                ['lsblk', '-J', '-o', 'NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL', device_path],
                capture_output=True,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as error:
            logger.debug(f"lsblk failed for {device_path}: {error}")
            return None

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            logger.debug(f"lsblk JSON parse error for {device_path}: {error}")
            return None

        device_map: Dict[str, Dict[str, Any]] = {}
        for entry in data.get('blockdevices', []):
            self._collect_lsblk_device(entry, '/dev/', device_map)

        return device_map.get(device_path)

    def _collect_lsblk_device(self, entry: dict, parent_path: str, result: Dict[str, Dict[str, Any]]):
        device_name = entry.get('name')
        if not device_name:
            return
        device_path = parent_path + device_name
        result[device_path] = {
            'filesystem': entry.get('fstype'),
            'size': self._parse_size(entry.get('size', '0')),
            'mount_point': entry.get('mountpoint'),
            'label': entry.get('label')
        }

        for child in entry.get('children', []) or []:
            self._collect_lsblk_device(child, parent_path, result)

    def _find_mount_point(self, device_path: str) -> Optional[str]:
        try:
            with open('/proc/mounts', 'r', encoding='utf-8') as mounts_file:
                for line in mounts_file:
                    parts = line.split()
                    if not parts:
                        continue
                    mount_source = os.path.realpath(parts[0])
                    if mount_source == os.path.realpath(device_path):
                        return parts[1]
        except FileNotFoundError:
            return None
        except Exception as error:
            logger.debug(f"Failed to determine mount point for {device_path}: {error}")
        return None

    def _refresh_device_metadata(self, updated_info: USBDeviceInfo):
        existing = self.devices.get(updated_info.device_path)
        if not existing:
            return

        if updated_info.mount_point:
            existing.mount_point = updated_info.mount_point
        if updated_info.filesystem:
            existing.filesystem = updated_info.filesystem
        if updated_info.size:
            existing.size = updated_info.size
        if updated_info.label:
            existing.label = updated_info.label

    def _get_current_devices(self) -> Dict[str, USBDeviceInfo]:
        """Get currently connected USB devices"""
        devices = {}
        
        # In debug mode, add a simulated USB device for testing
        if self.config.get('app.debug', False):
            test_usb_path = self.mount_base / "test_usb"
            if test_usb_path.exists():
                device_info = USBDeviceInfo(
                    device_path="/dev/test_usb",
                    mount_point=str(test_usb_path),
                    filesystem="vfat",
                    size=1024*1024,  # 1MB
                    label="TEST_USB"
                )
                devices["/dev/test_usb"] = device_info
                logger.debug("Added test USB device for debugging")
        
        try:
            # Use lsblk to get block device information
            result = subprocess.run(['lsblk', '-J', '-o', 'NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL'], 
                                    capture_output=True, text=True, check=True)
            
            data = json.loads(result.stdout)
            logger.debug(f"Processing {len(data.get('blockdevices', []))} block devices from lsblk")
            
            for device in data.get('blockdevices', []):
                self._process_block_device(device, devices, '/dev/')
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get device list: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse lsblk output: {e}")
        except Exception as e:
            logger.error(f"Error getting current devices: {e}")
        
        logger.debug(f"Returning {len(devices)} devices")
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
    
    def _is_usb_device(self, device_path: str, udev_device: Optional[Any] = None) -> bool:
        """Check if device is a USB-backed block device"""
        try:
            if self.config.get('app.debug', False):
                return True

            device = udev_device
            if device is None and self._context is not None:
                try:
                    device = self._context.device_from_device_file(device_path)
                except _PYUDEV_DEVICE_NOT_FOUND:
                    device = None
                except Exception as error:
                    logger.debug(f"pyudev lookup failed for {device_path}: {error}")
                    device = None

            if device is not None:
                if device.get('ID_BUS') != 'usb':
                    return False
                devtype = device.get('DEVTYPE')
                if devtype and devtype not in {'disk', 'partition'}:
                    return False
                fs_usage = device.get('ID_FS_USAGE')
                if fs_usage and fs_usage not in {'filesystem', 'crypto'}:
                    return False
                return True

            if '/dev/sd' in device_path:
                result = subprocess.run(
                    ['udevadm', 'info', '--query=property', '--name', device_path],
                    capture_output=True,
                    text=True
                )
                return 'ID_BUS=usb' in result.stdout

            return False
        except Exception as error:
            logger.debug(f"Error checking if {device_path} is USB: {error}")
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

        existing_device = self.devices.get(device_info.device_path)
        if existing_device:
            logger.debug(f"USB device {device_info.device_path} already tracked; refreshing metadata")
            self._refresh_device_metadata(device_info)
            return

        if device_info.filesystem and device_info.filesystem not in self.supported_fs:
            logger.info(f"Skipping unsupported filesystem {device_info.filesystem} on {device_info.device_path}")
            return

        if not device_info.filesystem:
            logger.debug(
                "Detected block device %s without filesystem; waiting for partitions",
                device_info.device_path,
            )
            self.devices[device_info.device_path] = device_info
            return

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
