#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo " TriSeal WSL2 & Docker Runtime Setup"
echo "========================================================"

# 1. Ensure systemd is enabled in /etc/wsl.conf
if [ -f /etc/wsl.conf ]; then
    if ! grep -q "systemd=true" /etc/wsl.conf; then
        echo "[boot]" | sudo tee -a /etc/wsl.conf
        echo "systemd=true" | sudo tee -a /etc/wsl.conf
        echo "[+] Added systemd=true to /etc/wsl.conf"
    fi
else
    echo -e "[boot]\nsystemd=true" | sudo tee /etc/wsl.conf
    echo "[+] Created /etc/wsl.conf with systemd=true"
fi

# 2. Update package lists and install prerequisites
sudo apt-get update -y
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    apt-transport-https \
    make \
    python3 \
    python3-pip \
    python3-venv \
    jq

# 3. Install Docker Engine if not installed
if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker Engine..."
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker "$USER" || true
    echo "[+] Docker Engine installed."
else
    echo "[+] Docker is already installed."
fi

# Ensure docker service is running
sudo systemctl enable docker || true
sudo systemctl start docker || sudo service docker start || true

# 4. Attempt to install gVisor (runsc)
echo "[*] Installing gVisor (runsc)..."
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg --yes || true
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null || true
sudo apt-get update -y || true
sudo apt-get install -y runsc || true

CHAMBER_RUNTIME="runc"

if command -v runsc &> /dev/null; then
    echo "[*] Registering runsc in Docker daemon..."
    sudo runsc install || true
    sudo systemctl restart docker || sudo service docker restart || true

    echo "[*] Running gVisor preflight test..."
    if sudo docker run --runtime=runsc --rm alpine dmesg 2>&1 | grep -iq "gvisor"; then
        echo "[SUCCESS] gVisor (runsc) preflight check PASSED!"
        CHAMBER_RUNTIME="runsc"
    elif sudo docker run --runtime=runsc --rm alpine echo "ok" 2>&1 | grep -q "ok"; then
        echo "[SUCCESS] gVisor (runsc) container test PASSED!"
        CHAMBER_RUNTIME="runsc"
    else
        echo "[WARNING] gVisor (runsc) failed under this WSL2 kernel. Falling back to hardened runc."
        CHAMBER_RUNTIME="runc"
    fi
else
    echo "[INFO] runsc package could not be installed. Falling back to hardened runc."
    CHAMBER_RUNTIME="runc"
fi

# 5. Export environment configuration
echo "CHAMBER_RUNTIME=${CHAMBER_RUNTIME}" > .env
echo "CHAMBER_RUNTIME=${CHAMBER_RUNTIME}"
echo "========================================================"
echo " Setup complete! Active runtime: ${CHAMBER_RUNTIME}"
echo " Configuration saved to .env"
echo "========================================================"
