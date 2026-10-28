# Architecture & Technical Decisions (ADR Log)

## ADR-001: WSL2 Distribution and Systemd
- **Status:** Approved
- **Decision:** Use Ubuntu (24.04 LTS / 22.04 LTS) inside WSL2 with `systemd=true` configured in `/etc/wsl.conf`.
- **Reasoning:** Systemd is required inside WSL2 to manage the standalone Docker Engine daemon independently of Docker Desktop.

## ADR-002: Standalone Docker Engine vs Docker Desktop
- **Status:** Approved
- **Decision:** Run standalone `dockerd` inside the Linux distribution rather than relying on Windows Docker Desktop.
- **Reasoning:** Custom container runtimes (such as gVisor `runsc`) must be registered in `/etc/docker/daemon.json` directly within the Linux virtualization environment.

## ADR-003: Model Selection for LLM Chamber
- **Status:** Approved
- **Decision:** Use `Qwen2.5-1.5B-Instruct-Q4_K_M.gguf` (or `Llama-3.2-1B-Instruct-Q4_K_M.gguf`) served via `llama.cpp` CPU build.
- **Reasoning:** Small 1-1.5B 4-bit quantized models run efficiently on host CPU without requiring discrete GPUs and support rapid session cache erasure.

## ADR-004: Chamber Runtime Evaluation (gVisor vs Hardened runc)
- **Status:** Approved (gVisor `runsc` Verified)
- **Decision:** Set `CHAMBER_RUNTIME=runsc`.
- **Reasoning:** Preflight checks verified that gVisor (`runsc`) is fully supported on this host (WSL2 Linux Kernel 6.6.87.2-1 with Ubuntu 24.04 LTS and Docker Engine 29.1.3). The test container `docker run --runtime=runsc --rm alpine dmesg` executed successfully, producing authentic gVisor virtualized kernel messages (`Starting gVisor... Ready!`).
- **Preflight Evidence:**
  - Docker Version: `29.1.3`
  - Registered Runtimes: `runc`, `runsc`, `io.containerd.runc.v2`
  - Active Chamber Runtime: `runsc`
## ADR-005: Deterministic Isolated Subnet Networking & Hostname Resolution under gVisor
- **Status:** Approved
- **Decision:** Configure explicit static IPv4 subnets (`172.28.1.0/24` for `net_red`, `172.28.2.0/24` for `net_blue`, `172.28.3.0/24` for `net_llm`, `172.28.4.0/24` for `net_admin`) with `extra_hosts` mappings in Docker Compose.
- **Reasoning:** gVisor's virtualized user-space network stack (`netstack`) isolates container networking and intentionally does not evaluate host iptables DNAT rules used by Docker's embedded `127.0.0.11` DNS resolver. Static subnets with `extra_hosts` provide deterministic hostname resolution via container `/etc/hosts` while enforcing strict physical isolation across internal bridge networks.

## ADR-006: Fixed-Deadline Envelope Release ($D = 1400\text{ms}$)
- **Status:** Approved
- **Decision:** The Arbiter Gateway holds all responses—including benign completions, model refusals, and guardrail blocks—until a calibrated deadline ($D = 1400\text{ms}$, calibrated against empirical p99 inference latency of $909.50\text{ms}$ with a 35% margin) before releasing a uniform JSON reply envelope.
- **Reasoning:** Eliminates timing side channels (T4: Timing Oracle) where attackers observe milliseconds difference between guard blocking (~7ms) and model refusal (~487–647ms) to reverse-engineer defense rules. Flattens response times to ~1.41 s for both groups with a median p50 differential of 0.85 ms (eliminating the 639.19 ms Baseline timing side channel).
