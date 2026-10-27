SHELL := /bin/bash
MODE ?= triseal
CHAMBER_RUNTIME ?= runc

.PHONY: help setup fetch-model fetch-datasets up down ps logs test-baseline test-triseal test-all verify-ledger tamper-demo ui clean control-plane anchor demo

help:
	@echo "TriSeal Management Commands:"
	@echo "  make setup            - Run WSL2 and Docker runtime setup"
	@echo "  make fetch-model      - Download LLM GGUF model and record SHA-256"
	@echo "  make fetch-datasets   - Fetch AdvBench, HarmBench, Gandalf benchmark datasets"
	@echo "  make up MODE=baseline - Launch baseline environment"
	@echo "  make up MODE=triseal  - Launch hardened TriSeal environment"
	@echo "  make down             - Stop active containers"
	@echo "  make test-baseline    - Execute full Leak Test Suite against Baseline"
	@echo "  make test-triseal     - Execute full Leak Test Suite against TriSeal"
	@echo "  make test-all         - Run tests against both Baseline and TriSeal"
	@echo "  make verify-ledger    - Cryptographically audit the event ledger"
	@echo "  make tamper-demo      - Demonstrate ledger tamper detection"
	@echo "  make ui               - Launch the Security-Ops UI"

setup:
	bash scripts/setup_wsl.sh

fetch-model:
	bash scripts/fetch_model.sh

fetch-datasets:
	bash scripts/fetch_datasets.sh

up:
	@if [ "$(MODE)" = "baseline" ]; then \
		docker compose -f docker-compose.baseline.yml up -d --build; \
	else \
		docker compose -f docker-compose.triseal.yml up -d --build; \
	fi

down:
	docker compose -f docker-compose.baseline.yml down -v --remove-orphans || true
	docker compose -f docker-compose.triseal.yml down -v --remove-orphans || true

ps:
	docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Networks}}"

logs:
	@if [ "$(MODE)" = "baseline" ]; then \
		docker compose -f docker-compose.baseline.yml logs -f; \
	else \
		docker compose -f docker-compose.triseal.yml logs -f; \
	fi

test-baseline:
	python3 -m tests.leaksuite.runner --mode baseline

test-triseal:
	python3 -m tests.leaksuite.runner --mode triseal

test-all:
	@echo "=== [1/2] Running Baseline Leaksuite ==="
	docker compose -f docker-compose.triseal.yml down -v --remove-orphans 2>/dev/null || true
	docker compose -f docker-compose.baseline.yml up -d
	sleep 8
	python3 -m tests.leaksuite.runner --mode baseline
	@echo "=== [2/2] Running TriSeal Leaksuite ==="
	docker compose -f docker-compose.baseline.yml down -v --remove-orphans 2>/dev/null || true
	docker compose -f docker-compose.triseal.yml up -d
	sleep 8
	python3 -m tests.leaksuite.runner --mode triseal

verify-ledger:
	python3 -m ledger.verifier --ledger-file data/ledger.jsonl --checkpoints data/checkpoints.jsonl --trusted-key ledger/trust/ledger_signing.pub --anchor-file docs/anchors.txt

anchor:
	python3 -m ledger.anchor

demo:
	bash scripts/demo.sh

control-plane:
	PYTHONPATH=. python3 -m uvicorn server:app --app-dir control-plane --host 0.0.0.0 --port 8080

ui:
	cd ui && npm run dev

