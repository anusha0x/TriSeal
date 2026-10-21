#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYTHONPATH:-.}:/root/triseal"

echo "========================================================================"
echo " TRISEAL: End-to-End Adversarial AI Safety Infrastructure Walkthrough"
echo " Track 04: Bayora Problem Statement · Hack in Hills '26"
echo "========================================================================"

# Step 1: Launch Baseline Environment
echo -e "\n[STEP 1/5] Deploying Baseline (Unsealed) Environment..."
docker compose -f docker-compose.baseline.yml down -v --remove-orphans 2>/dev/null || true
docker compose -f docker-compose.baseline.yml up -d
sleep 3
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Step 2: Run Leak Test Suite against Baseline
echo -e "\n[STEP 2/5] Executing Defensive Leak Test Suite against Baseline..."
python3 -m tests.leaksuite.runner --mode baseline

# Step 3: Switch to TriSeal Hardened Setup
echo -e "\n[STEP 3/5] Switching to Hardened TriSeal Environment (${CHAMBER_RUNTIME:-runsc})..."
docker compose -f docker-compose.baseline.yml down -v --remove-orphans
docker compose -f docker-compose.triseal.yml up -d
sleep 3
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Step 4: Run Leak Test Suite against TriSeal
echo -e "\n[STEP 4/5] Executing Defensive Leak Test Suite against TriSeal..."
python3 -m tests.leaksuite.runner --mode triseal

# Step 5: Audit Ledger Verification & Tamper Demonstration
echo -e "\n[STEP 5/5] Auditing Cryptographic Ledger and Demonstrating Tamper Detection..."
python3 -m ledger.tamper_demo

echo -e "\n========================================================================"
echo " TriSeal Walkthrough Complete! All DoD criteria demonstrated."
echo " Launch UI to inspect Scoreboard: make ui"
echo "========================================================================"
