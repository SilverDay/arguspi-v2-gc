#!/bin/bash

# ArgusPI v2 Installation Script
# This script installs ArgusPI as a system service

set -e

INSTALL_DIR="/opt/arguspi"
SERVICE_FILE="system/arguspi.service"

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check if user exists
if ! id "$USER" &>/dev/null; then
    echo "Error: User '$USER' does not exist. Please create the user first."
    exit 1
fi

echo "Installing ArgusPI v2..."

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"

# Copy application files
echo "Copying application files..."
cp -r . "$INSTALL_DIR"

# Set ownership
echo "Setting file ownership..."
chown -R "$USER:$USER" "$INSTALL_DIR"

# Install systemd service
echo "Installing systemd service..."
# Create the service file with the correct user
sed "s/User=pi/User=$USER/g; s/Group=pi/Group=$USER/g" "$INSTALL_DIR/$SERVICE_FILE" > /etc/systemd/system/arguspi.service

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
echo "Configuration file: $INSTALL_DIR/config/default.yaml"
echo "To enable auto-start on boot, the service is already enabled."
echo "To disable auto-start: sudo systemctl disable arguspi"