#!/bin/bash

echo "LitterBox Docker Setup"
echo "====================="

echo "[+] Installing Docker, Docker Compose, and CPU checker..."
sudo apt install docker.io docker-compose cpu-checker -y

echo "[+] Checking KVM support..."
if sudo kvm-ok; then
    echo "[+] KVM acceleration available"
else
    echo "[!] KVM not available - will run slower"
    echo "[!] Enable virtualization in BIOS or use KVM: 'N' in docker-compose"
fi


# Create directories
mkdir -p oem
mkdir -p share

# Create install.bat
cat > oem/install.bat << 'EOF'
@echo off
echo [+] LitterBox Installation Starting...
powershell -ExecutionPolicy Bypass -File "C:\OEM\install.ps1"
echo [+] Installation complete!
EOF

# Copy existing install.ps1
cp install.ps1 oem/install.ps1

echo ""
echo "Starting Windows installation..."
echo "Web viewer: http://localhost:8006"
echo "Monitor installation progress in browser"
echo "Windows will auto-install, then LitterBox will be set up"
echo "LitterBox will be ready at http://localhost:1337 when complete"

# Start Docker container
sudo docker-compose up

