#!/bin/bash

# ArgusPI v2 Installation Script
# This script installs ArgusPI as a system service

set -e

INSTALL_DIR="/opt/arguspi"
SERVICE_FILE="system/arguspi.service"
USER="pi"

echo "ArgusPI v2 Installation Script"
echo "==============================="

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
cp "$INSTALL_DIR/$SERVICE_FILE" /etc/systemd/system/arguspi.service

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