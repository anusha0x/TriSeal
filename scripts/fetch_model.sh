#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../chambers/llm/models" && pwd)"
mkdir -p "${DEST_DIR}"

MODEL_FILE="${DEST_DIR}/model.gguf"
HASH_FILE="${DEST_DIR}/model.sha256"

# Default to Qwen2.5-0.5B or Qwen2.5-1.5B instruct for fast, responsive CPU inference
MODEL_URL="${MODEL_URL:-https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf}"

echo "========================================================"
echo " TriSeal: Fetching LLM GGUF Model for CPU Inference"
echo " Destination: ${MODEL_FILE}"
echo " Source: ${MODEL_URL}"
echo "========================================================"

if [ -f "${MODEL_FILE}" ] && [ -s "${MODEL_FILE}" ]; then
    echo "[+] Model already exists at ${MODEL_FILE}."
else
    echo "[*] Downloading model (this may take a couple minutes)..."
    curl -L --retry 3 --retry-delay 2 "${MODEL_URL}" -o "${MODEL_FILE}.tmp"
    mv "${MODEL_FILE}.tmp" "${MODEL_FILE}"
    echo "[+] Model downloaded successfully."
fi

# Calculate and record SHA-256 hash for ledger verification
echo "[*] Computing SHA-256 hash..."
sha256sum "${MODEL_FILE}" | awk '{print $1}' > "${HASH_FILE}"
MODEL_HASH=$(cat "${HASH_FILE}")
echo "[+] Model Weight SHA-256: ${MODEL_HASH}"
echo "========================================================"
