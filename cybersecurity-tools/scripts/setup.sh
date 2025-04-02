#!/bin/bash

echo "[+] Setting up Cybersecurity Tools..."

# Update system packages (optional, recommended for Linux users)
echo "[+] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
echo "[+] Installing required Python packages..."
pip install -r requirements.txt

# Ensure scripts have execution permissions
echo "[+] Setting executable permissions for scripts..."
chmod +x scripts/setup.sh
chmod +x scripts/run_all_tools.py

echo "[+] Setup complete. You can now run the tools!"
