#!/bin/bash
# Setup systemd service for GEEKS-AD-Tools auto-start

echo "Setting up GEEKS-AD-Tools systemd service..."

# Copy service file
sudo cp /home/bphillips/GEEKS-AD-Tools/geeks-ad-plus.service /etc/systemd/system/geeks-ad-tools.service

# Reload systemd
sudo systemctl daemon-reload

# Enable service (auto-start on boot)
sudo systemctl enable geeks-ad-tools.service

# Stop any existing manual instances
pkill -f "python.*app.py" || true
sleep 2

# Start the service
sudo systemctl start geeks-ad-tools.service

# Check status
echo ""
echo "Service status:"
sudo systemctl status geeks-ad-tools.service --no-pager | head -15

echo ""
if sudo systemctl is-enabled geeks-ad-tools.service > /dev/null 2>&1; then
    echo "✅ Service is enabled for auto-start on boot"
else
    echo "❌ Service is NOT enabled"
fi

if sudo systemctl is-active geeks-ad-tools.service > /dev/null 2>&1; then
    echo "✅ Service is running"
else
    echo "❌ Service is NOT running"
fi

echo ""
echo "Service configured with:"
echo "  - Auto-start on boot: Enabled"
echo "  - Auto-restart on crash: Enabled (Restart=on-failure)"
echo "  - Working Directory: /home/bphillips/GEEKS-AD-Tools"
echo "  - Virtual Environment: /home/bphillips/GEEKS-AD-Tools/venv"

