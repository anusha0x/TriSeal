# TriSeal: Sealed Multi-Chamber Infrastructure for Adversarial AI Safety Testing
**Hack in Hills '26 · Track 04 · Bayora Problem Statement**  
*Securing Adversarial AI Safety Testing Infrastructure*

---

## 1. Executive Summary

Adversarial AI safety testing presents a fundamental security trilemma:
1. **Red Teams (Attackers)** must be given freedom to run adversarial jailbreak and prompt injection payloads, but must **never** be permitted to observe defender guardrail internals, probe network topology, or extract side-channel timing signals.
2. **Blue Teams (Defenders)** must inspect inputs and outputs with sealed guardrails, but must **never** observe live attack payloads prior to testing or leak defense regex/classifier configurations to attackers.
3. **Target Models (LLMs)** must evaluate prompts realistically on CPU/GPU, but must **never** retain residual context, cross-tenant KV-cache state (e.g. PromptPeek side channels), or allow model weight contamination.

**TriSeal** solves this by establishing three strictly isolated chambers mediated by a single audited gate (**Arbiter Gateway**) and an append-only, Ed25519-signed SHA-256 ledger with periodic Merkle checkpoints.

---

## 2. Architecture Diagram

```
                                 CONTROL PLANE (FastAPI, Trusted)
                 Round State Machine · Commit-Reveal · Key Release · Ed25519 Tokens
                              │ policy & token budget       │ seal & key release
                              ▼                             ▼
         RED CHAMBER ──▶ ARBITER GATEWAY ──────▶ BLUE CHAMBER ──────▶ LLM CHAMBER
        (attack runner)   (OPA · Token Budget ·   (sealed guard ·     (llama.cpp CPU ·
                           Uniform Replies ·       zero egress ·       per-tenant slot
                           Fixed Deadline D)       YAML config)        cache erase)
               ▲                  │                       │                  │
               │                  │ uniform reply         │ output check     │ response
               └──────────────────┴───────────────────────┴──────────────────┘
                                  │ (all hops hashed: zero plaintext)
                                  ▼
                    TAMPER-EVIDENT LEDGER (Ed25519 · SHA-256 Chain · Merkle Checkpoints)
                                  │
                    MONITOR (metadata only: Docker stats, network counters, alerts)
```

### The Three Chambers & Gateway:
- **Red Chamber (`chambers/red/`)**: Attack runner loading benchmark datasets (AdvBench, HarmBench, JailbreakBench, Gandalf). Contains benign probe targets for container escape, network crossing, storage snooping, and noisy-neighbor stress.
- **Blue Chamber (`chambers/blue/`)**: Sealed defense guardrail enforcing regex and keyword policies (`guard.yaml`) on prompt ingress and LLM output egress. Has zero external network access.
- **LLM Chamber (`chambers/llm/`)**: Local model serving via `llama.cpp` on CPU (`Qwen2.5-1.5B-Instruct-Q4_K_M.gguf`). Enforces strict per-tenant slot cache isolation and round-boundary context erasure (`POST /v1/slots/erase`).
- **Arbiter Gateway (`arbiter/`)**: Sole entrypoint connecting Red, Blue, and LLM across separate internal bridge networks (`net_red`, `net_blue`, `net_llm`). Enforces uniform reply envelopes and fixed-time deadline releases ($D = 3500\text{ms}$).
- **Audit Ledger (`ledger/`)**: Append-only cryptographic ledger storing SHA-256 hashes of all hop events, signed with Ed25519 keys, backed by Merkle trees and verifiable via CLI/API.

---

## 3. Real Recorded Benchmark: Baseline vs. TriSeal

All metrics below are **empirically measured** on the real host under WSL2 Linux Kernel 6.6 with standalone Docker Engine 29.1.3 and gVisor `runsc`:

| Test ID | Test Name | Target Requirement | Baseline (Naive) Result | TriSeal (Hardened) Result | Verdict |
|---|---|---|---|---|:---:|
| **T1** | Container Escape | Every probe denied; host canary untouched | **FAIL** (unconstrained capabilities & proc) | **PASS** (0 probes allowed; capabilities dropped) | **BLOCKED** |
| **T2** | Network Crossing | 0 connections crossing internal nets | **FAIL** (3 connections crossing; direct reach) | **PASS** (0 connections crossing; physical net isolation) | **BLOCKED** |
| **T3** | Storage Snooping | Access denied; canaries untouched | **PASS** (0 files read) | **PASS** (0 files read; read-only tmpfs rootfs) | **SECURE** |
| **T4** | Timing Oracle | Difference $< 10\text{ ms}$ at p95 | **FAIL** (204.39 ms delta; side channel open) | **PASS** (1.73 ms delta; deadline $D=3500\text{ms}$) | **BLOCKED** |
| **T5** | KV-Cache Probe | No hit/miss signal in TriSeal | **FAIL** (181.1 ms PromptPeek cache hit leak) | **PASS** (4.8 ms delta; per-tenant slot cache) | **BLOCKED** |
| **T6** | Contamination | Weight hash matches; 0 cross-session recall | **PASS** (no recall) | **PASS** (hash match; 0 recall after slot erase) | **SECURE** |
| **T7** | Log Tamper | Verification fails and alert fires | **PASS** (tamper caught at sequence #2) | **PASS** (tamper caught at sequence #2; Ed25519 alert) | **SECURE** |
| **T8** | Resource Starvation| Latency within $\pm 10\%$ of idle baseline | **FAIL** (+59.5% latency shift under stress) | **PASS** ($\pm 0.1\%$ latency variance; cgroup limits) | **BLOCKED** |
| **TOTAL** | **Summary Score** | **All 8 Tests Passed** | **3 / 8 Passed** (5 Critical Leaks) | **8 / 8 Passed** (0 Leaks Detected) | **100% PASS** |

---

## 4. Key Security Invariants Enforced

1. **Zero Outbound Egress & Internal Bridge Separation**:
   Red Chamber is physically attached only to `net_red`. Blue Chamber is attached only to `net_blue`. LLM is attached only to `net_llm`. No direct routing exists between Red and Blue or Red and LLM. All communication must traverse Arbiter.
2. **Fixed-Time Deadline Reply Releases**:
   Whether a query is immediately blocked by Blue input inspection (~5ms) or evaluated by the LLM (~100ms), Arbiter delays release until exactly $D = 3500\text{ms}$. Response envelopes are byte-for-byte and key-for-key structurally identical.
3. **Per-Tenant Slot Isolation & Cache Erasure**:
   Tenant prompts are partitioned into isolated slots in `llama.cpp`. Shared cross-tenant KV caches are disabled. After each round, the slot cache is wiped to prevent prompt extraction attacks like PromptPeek.
4. **Append-Only Signed Audit Ledger with Zero Plaintext**:
   Prompt text and completions are never stored in plaintext in the ledger. Instead, only canonical SHA-256 hashes (`payload_hash`), actor identities, and metadata are chained:
   $$\text{entry\_hash} = \text{SHA-256}(\text{prev\_hash} \parallel \text{canonical\_json}(\text{event}))$$
   Each entry is signed with Ed25519. Any 1-bit modification breaks hash integrity and invalidates all downstream signatures.
5. **gVisor User-Space Kernel Isolation**:
   Chambers run with `runtime: runsc`, running an independent user-space Sentry kernel that intercepts syscalls and shields the host kernel from container escapes.

---

## 5. Quickstart & Verification Guide

### Prerequisites
- Windows 10/11 with WSL2 (Ubuntu 22.04 or 24.04 LTS).
- Docker Engine with gVisor (`runsc`) registered (or run `scripts/setup_wsl.sh`).

### Fetching Models & Datasets (Excluded from Git)
```bash
bash scripts/fetch_model.sh      # Downloads llama.cpp binaries and Qwen2.5 GGUF weights
bash scripts/fetch_datasets.sh   # Fetches AdvBench, HarmBench, JailbreakBench, Gandalf
```

### 1-Command Automated End-to-End Walkthrough (Definition of Done)
```bash
bash scripts/demo.sh
```
This script executes all 5 steps required by the hackathon rubric:
1. Deploys the Baseline environment and measures live latency/network access.
2. Runs the Defensive Leak Test Suite against Baseline (demonstrates real leaks).
3. Switches to the hardened TriSeal environment with `runsc`.
4. Runs the Defensive Leak Test Suite against TriSeal (verifies all leaks blocked, 8/8 pass).
5. Executes the cryptographic ledger auditor and demonstrates automated tamper detection.

### Running Individual Commands via `make`
```bash
# Launch TriSeal environment
make up MODE=triseal

# Run Leak Test Suite against TriSeal
make test-triseal

# Audit Ledger Integrity
make verify-ledger

# Run Cryptographic Tamper Demo
make tamper-demo

# Launch Frontend Security Console
make ui
```

### Accessing Services
- **Security-Ops Web Console**: [http://127.0.0.1:5173](http://127.0.0.1:5173)
- **Control Plane REST API**: [http://127.0.0.1:8080/v1/health](http://127.0.0.1:8080/v1/health)
- **Arbiter Gateway**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 6. Repository Layout

```
TriSeal/
├── arbiter/                  # Audited gateway, uniform response envelopes, fixed deadline release
│   ├── Dockerfile
│   └── server.py
├── chambers/
│   ├── blue/                 # Sealed guardrails (guard.yaml regex/keyword rules)
│   ├── llm/                  # llama.cpp server, per-tenant slot cache erasure
│   └── red/                  # Attack runner, AdvBench/HarmBench/Gandalf datasets, probes
├── control-plane/            # Commit-reveal state machine, policy engine, REST + SSE API
│   ├── server.py
│   └── round_manager.py
├── ledger/                   # Ed25519-signed SHA-256 hash chain, Merkle checkpoints, verifier
│   ├── chain.py
│   ├── crypto.py
│   ├── merkle.py
│   ├── verifier.py
│   └── tamper_demo.py
├── policy/
│   └── access.rego           # OPA capability token policy and query budget rules
├── results/                  # Real measured JSON results for baseline and triseal
├── scripts/
│   ├── demo.sh               # 1-command DoD walkthrough script
│   ├── setup_wsl.sh          # Linux preflight & runtime setup
│   ├── fetch_model.sh        # llama.cpp binaries and GGUF weight verification
│   └── fetch_datasets.sh     # Benchmark dataset downloader
├── tests/
│   ├── leaksuite/runner.py   # 8-test defensive Leak Test Suite (T1–T8)
│   ├── test_ledger.py        # Pytest cryptographic ledger test suite
│   └── test_control_plane.py # Pytest commit-reveal state machine test suite
├── ui/                       # React 18 + Vite + TypeScript + Tailwind console
│   └── src/components/       # Scoreboard, Audit Verifier, Round & Threat Model views
├── docker-compose.baseline.yml
├── docker-compose.triseal.yml
├── Makefile
└── README.md
```

---

## 7. Compliance & Track Criteria Alignment

- **Honest Measurements**: Zero hardcoded passes, zero mocked metrics. All results reflect real container execution under Linux and gVisor `runsc`.
- **Reproducible**: Every test can be audited via CLI, automated script, or interactive web console.
- **Cryptographically Sealed**: Ed25519 + SHA-256 hash chain + Merkle roots guarantee immutable auditability.
