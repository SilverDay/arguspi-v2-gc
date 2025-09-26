#!/usr/bin/env bash

# ArgusPI v2 Installation Script
# This script installs ArgusPI as a system service
# (Line endings enforced via .gitattributes: LF for Linux compatibility)

set -euo pipefail

INSTALL_DIR="/opt/arguspi"
SERVICE_FILE="system/arguspi.service"
KIOSK_SERVICE_FILE="system/arguspi-kiosk@.service"

copy_application_files() {
    echo "Copying application files..."
    if command -v rsync >/dev/null 2>&1; then
        rsync -a \
            --exclude '.git/' \
            --exclude '.venv/' \
            --exclude '__pycache__/' \
            ./ "$INSTALL_DIR/"
    else
        echo "rsync not found; falling back to tar pipeline"
        tar --exclude='.git' --exclude='.venv' --exclude='__pycache__' -cf - . | (cd "$INSTALL_DIR" && tar -xf -)
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Detect the user who should own the installation
# Use SUDO_USER if available (user who ran sudo), otherwise fall back to other methods
DETECTED_USER=""
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    DETECTED_USER="$SUDO_USER"
elif [ -n "$USER" ] && [ "$USER" != "root" ]; then
    DETECTED_USER="$USER"
elif command -v logname >/dev/null 2>&1; then
    DETECTED_USER="$(logname 2>/dev/null || echo "")"
    if [ -z "$DETECTED_USER" ] || [ "$DETECTED_USER" = "root" ]; then
        DETECTED_USER="$(who am i | awk '{print $1}' 2>/dev/null || echo "")"
    fi
fi

# Final fallback - use the first non-root user with a home directory
if [ -z "$DETECTED_USER" ] || [ "$DETECTED_USER" = "root" ]; then
    DETECTED_USER="$(getent passwd | grep -E ':/home/' | head -1 | cut -d: -f1)"
fi

# If still no user found, exit with error
if [ -z "$DETECTED_USER" ] || [ "$DETECTED_USER" = "root" ]; then
    echo "Error: Could not determine non-root user for installation."
    echo "Please specify the user by setting the USER environment variable:"
    echo "  sudo USER=your_username ./install.sh"
    exit 1
fi

USER="$DETECTED_USER"

echo "ArgusPI v2 Installation Script"
echo "==============================="
echo "Detected user: $USER"

# Check if user exists
if ! id "$USER" &>/dev/null; then
    echo "Error: User '$USER' does not exist. Please create the user first."
    exit 1
fi

# Ensure the runtime user can access the ClamAV daemon socket if available
if getent group clamav >/dev/null 2>&1; then
    echo "Adding $USER to clamav group for ClamAV access..."
    usermod -a -G clamav "$USER"
fi

echo "Installing ArgusPI v2..."

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"

echo "Preparing USB mount base under /media/arguspi (requires root)"
mkdir -p /media/arguspi
chown "$USER:$USER" /media/arguspi

# Copy application files
copy_application_files

# Remove any previously bundled virtual environment directory (if present)
rm -rf "$INSTALL_DIR/.venv"

# Set ownership
echo "Setting file ownership..."
chown -R "$USER:$USER" "$INSTALL_DIR"

echo "Setting up Python virtual environment (with system site packages)..."
runuser -l "$USER" -c "cd $INSTALL_DIR && python3 -m venv --system-site-packages .venv"

echo "Installing Python dependencies inside virtual environment..."
runuser -l "$USER" -c "cd $INSTALL_DIR && .venv/bin/pip install --upgrade pip"
runuser -l "$USER" -c "cd $INSTALL_DIR && .venv/bin/pip install -r requirements.txt"

# Install systemd service
echo "Installing systemd service..."
# Create the service file with the correct user
sed "s/User=pi/User=$USER/g; s/Group=pi/Group=$USER/g" "$INSTALL_DIR/$SERVICE_FILE" > /etc/systemd/system/arguspi.service

if [ -f "$INSTALL_DIR/$KIOSK_SERVICE_FILE" ]; then
    echo "Installing kiosk systemd service template..."
    sed "s/User=pi/User=$USER/g; s/Group=pi/Group=$USER/g" "$INSTALL_DIR/$KIOSK_SERVICE_FILE" > /etc/systemd/system/arguspi-kiosk@.service
fi

# Install udev rule to disable desktop auto-mount for USB storage
UDEV_RULE_SOURCE="$INSTALL_DIR/system/99-arguspi-no-automount.rules"
UDEV_RULE_TARGET="/etc/udev/rules.d/99-arguspi-no-automount.rules"
if [ -f "$UDEV_RULE_SOURCE" ]; then
    echo "Installing udev rule to disable desktop USB auto-mount..."
    install -m 644 "$UDEV_RULE_SOURCE" "$UDEV_RULE_TARGET"
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=block
fi

# Reload systemd and enable service
echo "Configuring systemd service..."
systemctl daemon-reload
systemctl enable arguspi.service

echo ""
echo "Installation complete!"
echo ""
echo "To start ArgusPI v2 service:"
echo "  sudo systemctl start arguspi"
echo ""
echo "To check service status:"
echo "  sudo systemctl status arguspi"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u arguspi -f"
echo ""
echo "Python virtual environment: $INSTALL_DIR/.venv"
echo "To open a shell with the ArgusPI environment, run:"
echo "  source $INSTALL_DIR/.venv/bin/activate"
echo ""
echo "Configuration file: $INSTALL_DIR/config/default.yaml"
echo "To enable auto-start on boot, the service is already enabled."
echo "To disable auto-start: sudo systemctl disable arguspi"
