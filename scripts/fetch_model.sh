#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${PROJECT_ROOT}/chambers/llm/models"
mkdir -p "${DEST_DIR}"

MODEL_FILE="${DEST_DIR}/model.gguf"
HASH_FILE="${DEST_DIR}/model.sha256"

# Default to Qwen2.5-0.5B or Qwen2.5-1.5B instruct for fast, responsive CPU inference
MODEL_URL="${MODEL_URL:-https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf}"

# Official HuggingFace SHA-256 checksum for Qwen2.5-0.5B-Instruct-Q4_K_M.gguf
EXPECTED_SHA256="${EXPECTED_SHA256:-74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db}"

echo "========================================================"
echo " TriSeal: Fetching LLM GGUF Model for CPU Inference"
echo " Destination: ${MODEL_FILE}"
echo " Source:      ${MODEL_URL}"
echo " Expected:    ${EXPECTED_SHA256}"
echo "========================================================"

if [ -f "${MODEL_FILE}" ] && [ -s "${MODEL_FILE}" ]; then
    echo "[+] Model already exists at ${MODEL_FILE}."
else
    echo "[*] Downloading model (this may take 2-4 minutes)..."
    curl -L --retry 3 --retry-delay 2 "${MODEL_URL}" -o "${MODEL_FILE}.tmp"
    mv "${MODEL_FILE}.tmp" "${MODEL_FILE}"
    echo "[+] Model downloaded successfully."
fi

# Calculate and record SHA-256 hash for ledger verification
echo "[*] Verifying SHA-256 hash against official source..."
MODEL_HASH=$(sha256sum "${MODEL_FILE}" | awk '{print $1}')
echo "${MODEL_HASH}" > "${HASH_FILE}"

if [ "${MODEL_HASH}" != "${EXPECTED_SHA256}" ]; then
    echo "[-] ERROR: Checksum mismatch!"
    echo "    Expected: ${EXPECTED_SHA256}"
    echo "    Got:      ${MODEL_HASH}"
    exit 1
fi

echo "[+] Model Weight SHA-256 Verified: ${MODEL_HASH}"
echo "========================================================"

# Fetch official llama.cpp binaries if needed
if [ -f "${PROJECT_ROOT}/scripts/download_llama.sh" ]; then
    bash "${PROJECT_ROOT}/scripts/download_llama.sh"
fi
