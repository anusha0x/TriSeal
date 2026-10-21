#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../chambers/llm/bin" && pwd)"
mkdir -p "${DEST_DIR}"

if [ -f "${DEST_DIR}/llama-server" ] || [ -f "${DEST_DIR}/build/bin/llama-server" ]; then
    echo "[+] llama-server already present."
    exit 0
fi

URL="https://github.com/ggml-org/llama.cpp/releases/download/b11756/llama-b11756-bin-ubuntu-x64.tar.gz"
echo "[*] Downloading official prebuilt llama.cpp binaries from: ${URL}"

curl -sL -f "${URL}" -o /tmp/llama.tar.gz
tar -xzf /tmp/llama.tar.gz -C "${DEST_DIR}"
rm -f /tmp/llama.tar.gz

# If binaries are nested under build/bin, symlink or move them
if [ -d "${DEST_DIR}/build/bin" ]; then
    cp -r "${DEST_DIR}"/build/bin/* "${DEST_DIR}/" || true
fi

chmod +x "${DEST_DIR}"/llama-* 2>/dev/null || true
echo "[+] Extracted llama binaries to ${DEST_DIR}"
ls -lh "${DEST_DIR}/llama-server"
