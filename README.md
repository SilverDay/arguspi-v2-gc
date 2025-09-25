# arguspi-v2-gc

This is a version of ArgusPI that is more modular and easier to extend (Copilot version).

## USB Virus Scanner for Raspberry Pi

ArgusPI v2 is a comprehensive USB virus scanning solution designed for Raspberry Pi systems. It features both a console mode for administrators and a kiosk mode for public use.

## Features

- **Automatic USB Device Detection**: Automatically detects and mounts USB devices
- **Multi-Engine Scanning**: Supports ClamAV and VirusTotal scanning engines
- **Console Mode**: Full-featured command-line interface for administrators
- **Kiosk Mode**: Simple, public-facing interface for unattended operation
- **Read-Only Protection**: Mounts USB devices in read-only mode for safety
- **Comprehensive Logging**: Detailed logging with configurable levels
- **Configurable**: YAML-based configuration with environment variable overrides

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/SilverDay/arguspi-v2-gc.git
   cd arguspi-v2-gc
   ```

2. Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Install ClamAV (recommended):
   ```bash
   sudo apt update
   sudo apt install clamav clamav-daemon
   sudo freshclam
   ```

## Usage

### Console Mode (Administrator)
Start ArgusPI v2 in console mode for full administrative access:

```bash
python3 main.py
```

This provides access to:
- Manual device scanning
- Scan result history
- Settings configuration
- Device management

### Kiosk Mode (Public Use)
Start ArgusPI v2 in kiosk mode for public, unattended operation:

```bash
python3 main.py --kiosk
```

**Kiosk Mode Workflow:**
1. User plugs in a USB device
2. Device is automatically detected and scanned
3. Scan results are displayed on screen
4. Results remain visible until USB device is removed
5. System resets for the next user

**Kiosk Mode Features:**
- Full-screen interface optimized for touchscreens
- Automatic USB device scanning
- Clear visual feedback for scan progress
- Security restrictions to prevent OS access
- Simple, user-friendly design

### Command Line Options

```bash
python3 main.py --help
```

Available options:
- `--kiosk`: Start in kiosk mode for public use
- `--config CONFIG`: Use custom configuration file
- `--version`: Show version information

## Configuration

The application uses a YAML configuration file located at `config/default.yaml`. Key configuration sections:

### Kiosk Mode Settings
```yaml
kiosk:
  enabled: false                # Enable kiosk mode
  auto_scan: true              # Auto-scan connected USB devices
  show_welcome: true           # Show welcome screen
  result_timeout: 0            # Keep results displayed (0 = until USB removed)
  allow_manual_scan: false     # Allow manual scan initiation
  hide_system_info: true       # Hide system information
  prevent_exit: true           # Prevent accidental exit
  screen_saver_timeout: 300    # Screen saver timeout (seconds)
```

### Scanner Settings
```yaml
scanner:
  engines:
    clamav:
      enabled: true
      database_update: true
    virustotal:
      enabled: true
      api_key: ""  # Set via VT_API_KEY environment variable
  scan_types: ["exe", "dll", "bat", "cmd", "scr", "zip", "rar"]
```

### USB Settings
```yaml
usb:
  auto_detect: true
  read_only: true              # Mount devices read-only for safety
  supported_filesystems: ["vfat", "ntfs", "ext2", "ext3", "ext4"]
```

## Security Features

### Kiosk Mode Security
- **Read-only mounting**: USB devices are mounted read-only to prevent malware execution
- **System access prevention**: Terminal shortcuts and system commands are disabled
- **Automatic reset**: System resets after each USB device removal
- **No configuration access**: Users cannot modify settings in kiosk mode

## Use Cases

### Public Kiosks
Deploy ArgusPI v2 in libraries, schools, or public spaces where users need to scan their USB devices for viruses.

### Corporate Security
Use in corporate environments to scan USB devices before allowing them on the network.

### Home Security
Personal virus scanning station for family USB devices.

## Requirements

- Raspberry Pi (3B+ or newer recommended)
- Python 3.7+
- USB ports for device scanning
- Internet connection (for VirusTotal integration, optional)

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure the user has sudo privileges for mounting USB devices
2. **ClamAV Database**: Run `sudo freshclam` to update virus definitions
3. **USB Detection**: Check that USB devices are properly formatted and recognized by the system

### Logs
Application logs are stored in `logs/arguspi.log`. Check this file for detailed error information.

## Development

This version of ArgusPI v2 is designed to be modular and extensible. Key components:

- `src/core/application.py`: Main application controller
- `src/gui/main_window.py`: Console mode interface
- `src/gui/kiosk_window.py`: Kiosk mode interface
- `src/usb/detector.py`: USB device detection and mounting
- `src/scanner/engine.py`: Virus scanning coordination

## License

This project is part of the ArgusPI family of USB security tools.
