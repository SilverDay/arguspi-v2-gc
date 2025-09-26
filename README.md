# arguspi-v2-gc

This is a version of ArgusPI that is more modular and easier to extend (Copilot version).

## USB Virus Scanner for Raspberry Pi

ArgusPI v2 is a comprehensive USB virus scanning solution designed for Raspberry Pi systems. It features both a console mode for administrators and a kiosk mode for public use.

## Features

- **Automatic USB Device Detection**: Real-time udev monitoring that automatically detects and mounts USB devices using `pyudev`
- **Multi-Engine Scanning**: Supports ClamAV and VirusTotal scanning engines
- **Console Mode**: Full-featured command-line interface for administrators
- **Qt Desktop Mode**: Rich PySide6-based desktop interface sharing the same callback surface
- **Kiosk Mode**: Simple, public-facing interface for unattended operation
- **Read-Only Protection**: Mounts USB devices in read-only mode for safety
- **USB Device Profiling**: Captures vendor/product metadata, flags HID-capable peripherals, and warns on non-storage devices before scanning
- **Modular Security Controls**: Enforce USB policy rules, quarantine infected files, and maintain a device reputation database
- **Comprehensive Logging**: Detailed logging with configurable levels
- **Configurable**: YAML-based configuration with environment variable overrides
- **Resilient SIEM Delivery**: Automatically queues events locally when offline and flushes once connectivity returns

## Security Modules

ArgusPI v2 includes optional security adjuncts that can be enabled per environment:

- **Quarantine Manager** (`security.quarantine`): Copies detected threats into an isolated directory, captures JSON reports, and enforces a retention limit.
- **Device Reputation Store** (`security.reputation`): Persists device sightings in SQLite, tracks warning counts, and surfaces flag status during future connections.
- **USB Policy Rules** (`security.rules`): Evaluates connected devices against local and remotely-synchronised rule sets (blocked VID/PID pairs, serial prefixes, interface classes).

Threat detections immediately raise SIEM alerts (`threat_detected`), notify the active GUI backend, and optionally quarantine the offending file when enabled.

### Configuring USB Policy Rules

USB policy enforcement is highly configurable so you can blend on-device rules with centrally managed policies:

- **Inline Local Rules** (`security.rules.local`): Edit `blocked_devices`, `blocked_serial_prefixes`, or `blocked_interfaces` directly inside `config/default.yaml` to hard-code policy entries that ship with the appliance.
- **External Local Rule File** (`security.rules.local_file`): Point this setting at a separate YAML file (default: `config/rules.local.yaml`) that mirrors the `security.rules.local` structure. This keeps day-two changes out of the main configuration and makes it easier to distribute customised rule sets across scanners.

  ```yaml
  # config/rules.local.yaml
  blocked_devices:
    - vid: "1058"
      pid: "25a1"
      reason: "Quarantine known-bad USB enclosure"
  blocked_serial_prefixes: []
  blocked_interfaces:
    - class: "03"
      subclass: "01"
      protocol: "01"
      reason: "Disallow HID masquerading"
  ```

  The local file is optional—leave it empty or remove the key entirely if you don't need it. When present, its entries are merged with the inline lists before evaluation.

- **Remote Synchronisation** (`security.rules.sync`): Enable this block to fetch additional policy entries from an HTTP(S) endpoint returning JSON encoded rules. ArgusPI periodically refreshes the data according to `sync.interval_minutes` and caches the most recent successful download so the rules remain available offline.

Rule precedence combines all sources: inline + external file + remote sync. Any match raises a USB warning, forwards the event to SIEM, surfaces it in the active UI, and blocks automatic scans (unless you explicitly allow them per rule in a future release). Use this layering to separate permanent defaults from rapidly changing threat intelligence.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/SilverDay/arguspi-v2-gc.git
   cd arguspi-v2-gc
   ```

2. Create a project-local virtual environment:

```bash
python3 -m venv --system-site-packages .venv
```

> The `--system-site-packages` flag lets the virtual environment see globally installed modules (like system-wide `pyclamd`), so you can manage ClamAV bindings in one place. If `python3 -m venv` is unavailable, install it with `sudo apt install python3-venv`.

3. Activate the environment and install dependencies:

```bash
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

> Note: `pyclamd` is pinned to version 0.4.0 because it is the latest release published to PyPI/piwheels. This version remains compatible with the ClamAV integrations in ArgusPI.

4. Create the shared USB mount directory and hand ownership to your runtime user (the installer performs these commands automatically):

```bash
sudo mkdir -p /media/arguspi
sudo chown $USER:$USER /media/arguspi
```

5. Install GUI system libraries (required only for the Tkinter-based console/kiosk interfaces):

```bash
sudo apt install python3-tk
```

6. (Optional) Install native Qt libraries if you plan to use the PySide6 desktop interface:

```bash
sudo apt install libxcb-cursor0 libxcb-xinerama0
```

> These packages cover common Raspberry Pi OS dependencies. Additional libraries may be required depending on your Linux distribution or window system.

7. Install ClamAV (recommended) and ensure the clamd service is running:

```bash
sudo apt update
sudo apt install clamav clamav-daemon
sudo freshclam
sudo systemctl enable --now clamav-daemon
```

> The installer automatically adds the ArgusPI runtime user to the `clamav` group so it can talk to the `clamd` socket. If you create your own service user, make sure to add it manually with `sudo usermod -a -G clamav <user>` and restart the ArgusPI service afterward.

8. (Optional) Enable VirusTotal lookups by supplying an API key:

```bash
export VT_API_KEY="your-virustotal-api-key"
```

> **Watchdog Restart Note:** When using kiosk watchdog auto-restart, ensure the runtime user can execute `systemctl restart arguspi` without an interactive password prompt (for example by creating a sudoers rule). Otherwise the watchdog falls back to exiting so the supervisor can recover the service.

## Usage

Activate the virtual environment for each new shell session before running ArgusPI commands:

```bash
source .venv/bin/activate
```

### Console Mode (Administrator)

Start ArgusPI v2 in console mode for full administrative access:

```bash
python main.py
```

This provides access to:

- Manual device scanning
- Scan result history
- Settings configuration
- Device management

### Kiosk Mode (Public Use)

Start ArgusPI v2 in kiosk mode for public, unattended operation:

```bash
python main.py --kiosk
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

### Qt Desktop Mode (Rich UI)

Set the GUI backend to Qt in your configuration (`gui.backend: "qt"`), then launch ArgusPI normally:

```bash
python main.py
```

**Qt Desktop Features:**

- Modern, widget-based interface built with PySide6
- Live device list with start/stop scan controls
- Real-time progress bar and activity log
- Shares the same callbacks as the console interface for easy integration

> The Qt backend requires an active X11/Wayland session. When running headless, use a virtual framebuffer (e.g., `xvfb-run`).

### Command Line Options

```bash
python3 main.py --help
```

Available options:

- `--kiosk`: Start in kiosk mode for public use
- `--config CONFIG`: Use custom configuration file
- `--config-editor`: Launch the interactive terminal configuration editor and exit
- `--version`: Show version information

### Interactive Configuration Editor

ArgusPI includes a terminal-based configuration editor so you don't need to hand-edit YAML files.

```bash
python main.py --config-editor
```

Key capabilities:

- Browse nested sections of `config/default.yaml` (or any file supplied via `--config`).
- Edit values in place with type-aware prompts; booleans and common enumerations (log level, GUI backend, SIEM protocol, etc.) present pick lists so you can press the matching number instead of typing the value.
- Add or delete keys and list items, reload from disk, and save changes to the existing file or a new path.

The editor exits immediately after you save (or discard) your changes, making it safe to run on production systems before relaunching the scanner.

### Auto-Startup Service

ArgusPI v2 can be installed as a system service for automatic startup after reboot:

```bash
sudo ./install.sh
```

This will:

- Install ArgusPI to `/opt/arguspi`
- Create a dedicated Python virtual environment and install dependencies inside it
- Create a systemd service that runs ArgusPI through that virtual environment
- Install a udev rule that disables desktop auto-mount prompts for USB storage so ArgusPI controls the mounts
- Enable automatic startup (if configured)

You can drop into the deployed environment with:

```bash
source /opt/arguspi/.venv/bin/activate
```

**Service Management:**

```bash
# Start the service
sudo systemctl start arguspi

# Stop the service
sudo systemctl stop arguspi

# Check service status
sudo systemctl status arguspi

# View logs
sudo journalctl -u arguspi -f

# Enable/disable auto-start
sudo systemctl enable arguspi   # Enable
sudo systemctl disable arguspi  # Disable

# Launch kiosk UI on the Pi's primary console (TTY1)
sudo systemctl start arguspi-kiosk@tty1.service

# Stop the kiosk UI
sudo systemctl stop arguspi-kiosk@tty1.service

# Enable kiosk auto-start on boot
sudo systemctl enable arguspi-kiosk@tty1.service

# Disable kiosk auto-start
sudo systemctl disable arguspi-kiosk@tty1.service
```

> Enabling the kiosk service on `tty1` replaces the default console login for that terminal. Use `sudo systemctl disable arguspi-kiosk@tty1.service` (and optionally `sudo systemctl start getty@tty1.service`) to restore the standard login prompt.

## Configuration

The application uses a YAML configuration file located at `config/default.yaml`. Key configuration sections:

### Station Settings

```yaml
station:
  name: "ArgusPI Scanner" # Custom name for this scan station
  location: "" # Optional location description
  auto_start: false # Auto-start kiosk mode on system boot
```

### GUI Settings

```yaml
gui:
  backend: "console" # console, qt, kiosk
  theme: "light" # light or dark (Qt backend supports both)
  orientation: "auto" # auto, portrait, landscape (used by kiosk layouts)
  touchscreen: true # Enable larger controls for kiosk/Qt modes
  fullscreen: true # Fullscreen toggle for kiosk/Qt modes
```

### SIEM Integration

```yaml
siem:
  enabled: false # Enable SIEM integration
  protocol: "syslog" # Protocol: syslog, http, tcp
  server: "localhost" # SIEM server address
  port: 514 # SIEM server port
  facility: "local0" # Syslog facility (for syslog protocol)
  format: "json" # Message format: json, cef, leef
  events: # Which events to send
    scan_start: true
    scan_complete: true
    threats_found: true
    usb_connected: true
    usb_disconnected: true
    usb_metadata: true
    usb_warning: true
    system_errors: true
  timeout: 5 # Connection timeout in seconds
  offline_cache:
    enabled: true
    path: "logs/siem_offline_cache.jsonl"
    max_records: 1000
    flush_interval: 30
```

### Kiosk Mode Settings

```yaml
kiosk:
  enabled: false # Enable kiosk mode
  auto_scan: true # Auto-scan connected USB devices
  show_welcome: true # Show welcome screen
  result_timeout: 0 # Keep results displayed (0 = until USB removed)
  allow_manual_scan: false # Allow manual scan initiation
  hide_system_info: true # Hide system information
  prevent_exit: true # Prevent accidental exit
  screen_saver_timeout: 300 # Screen saver timeout (seconds)
  watchdog:
    enabled: true
    interval: 5
    timeout: 30
    action: "restart-service" # restart-service, exit
    service_name: "arguspi"
  terminal_lock:
    extended: true
    disable_vt_switch: true
    disable_sysrq: false
```

### Scanner Settings

```yaml
scanner:
  engines:
    clamav:
      enabled: true
      database_update: true
      max_file_size: "100M"
      max_scan_size: "1000M"
      socket: "/var/run/clamav/clamd.ctl"
      host: "127.0.0.1"
      port: 3310
        cli_path: "clamdscan"
        cli_args:
          - "--fdpass"
          - "--infected"
        prefer_cli: false
    virustotal:
      enabled: true
      api_key: "" # Set via VT_API_KEY environment variable
  scan_types: ["*"] # Scan all file types; replace with extensions (without dots) to limit scope
```

> Tip: ArgusPI automatically falls back to `clamdscan` when the Python bindings are unavailable or the daemon socket cannot be reached. Set `prefer_cli: true` if you want to skip the Python client entirely (useful when the CLI proves faster in your environment). The default CLI flags (`--fdpass` and `--infected`) ensure the kiosk user can scan files it does not own and that only infected entries appear in the output. Add additional flags under `scanner.engines.clamav.cli_args` if you need to tweak behaviour (for example `--detect-pua`).

### USB Settings

```yaml
usb:
  auto_detect: true
  read_only: true # Mount devices read-only for safety
  supported_filesystems: ["vfat", "ntfs", "ext2", "ext3", "ext4"]
```

### USB Detection

- USB insert/remove events are captured via [`pyudev`](https://pyudev.readthedocs.io/)
- Run the service with sufficient permissions to subscribe to udev (typically via `sudo` or a systemd service)
- For non-root usage, ensure the runtime user belongs to the `plugdev` group and has read access to `/dev/bus/usb`
- Existing devices are discovered on startup and new ones are handled immediately without polling
- Each USB attachment is profiled for vendor, product, serial, and interface descriptors; devices without the mass-storage class are logged, forwarded to SIEM as warnings, and surfaced to operators before any scan attempts to reduce HID spoofing attacks

## Security Features

### Kiosk Mode Security

- **Read-only mounting**: USB devices are mounted read-only to prevent malware execution
- **System access prevention**: Terminal shortcuts and system commands are disabled
- **Automatic reset**: System resets after each USB device removal
- **No configuration access**: Users cannot modify settings in kiosk mode
- **Self-healing watchdog**: Monitors kiosk health and restarts the service automatically if it hangs (configurable)
- **Enhanced terminal locking**: Disables VT switching and critical key sequences to reduce escape vectors

### SIEM Integration

ArgusPI v2 supports integration with Security Information and Event Management (SIEM) systems:

- **Multiple Protocols**: Syslog (UDP), HTTP POST, and raw TCP
- **Flexible Formats**: JSON, Common Event Format (CEF), and Log Event Extended Format (LEEF)
- **Comprehensive Events**: USB connections, scan results, threat detections, USB metadata/warning alerts, and system errors
- **Customizable Station Identity**: Each scanner can be uniquely identified by name and location
- **Asynchronous Delivery**: Non-blocking event delivery to prevent impact on scanning performance

**Supported SIEM Systems:**

- Splunk
- IBM QRadar
- ArcSight
- LogRhythm
- Elastic Security (ELK Stack)
- Any syslog-compatible system

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
4. **Desktop Auto-Mount Prompts**: If you still see "Removable Medium" pop-ups, ensure `/etc/udev/rules.d/99-arguspi-no-automount.rules` exists with the contents installed by `install.sh`, then reload udev with `sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=block`

### Logs

Application logs are stored in `logs/arguspi.log`. Check this file for detailed error information.

## Development

This version of ArgusPI v2 is designed to be modular and extensible. Key components:

- `src/core/application.py`: Main application controller
- `src/gui/main_window.py`: Console mode interface
- `src/gui/kiosk_window.py`: Kiosk mode interface
- `src/gui/qt_window.py`: PySide6 desktop interface
- `src/usb/detector.py`: USB device detection and mounting
- `src/scanner/engine.py`: Virus scanning coordination

## License

This project is provided under the MIT License.
