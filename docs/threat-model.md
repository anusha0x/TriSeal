# TriSeal: Threat Model & Security Specification
**Track 04 · Bayora Problem Statement · Hack in Hills '26**

---

## 1. System Overview & Trust Assumptions

TriSeal isolates three untrusted/semi-trusted adversarial entities:
1. **Red Chamber (Attacker):** Untrusted code execution environment running adversarial attack payloads, jailbreak probes, and prompt injections.
2. **Blue Chamber (Defender):** Semi-trusted sealed environment inspecting inputs and outputs with strict pattern matching and safety guardrails. Must not see live attack payloads prior to testing or leak defense internals.
3. **LLM Chamber (Model Under Test):** Model inference server (`llama.cpp` on CPU). Must not leak KV-cache state or retain cross-session memory contamination.

### Trusted Computing Base (TCB)
- **Host Linux Kernel & Isolation Hypervisor:** The WSL2 Linux host kernel running gVisor (`runsc`).
- **TriSeal Control Plane & Arbiter Gateway:** Trusted gateway mediating all cross-chamber traffic, issuing capability tokens, and appending cryptographically signed hashes to the ledger.
- **Docker Daemon:** The control plane holds access to the Docker socket for lifecycle orchestration.

---

## 2. In-Scope Threats (What TriSeal Protects Against)

| Threat Vector | Attack Scenario | TriSeal Countermeasure |
|---|---|---|
| **Early Payload Leak (Red → Blue)** | Attacker payloads visible to defenders before the round concludes, enabling overfitted defense rules. | Commit-reveal protocol. Payloads are AES-256-GCM encrypted and committed via SHA-256 before the round. Decryption keys are held by the Control Plane until REVEAL. |
| **Defense Oracle Leak (Blue → Red)** | Attacker infers internal guardrail patterns or model refusals from error codes or response latency differentials. | **Uniform fixed-deadline replies:** Guard blocks and model refusals share an identical JSON response envelope. All replies are held until calibrated deadline $D$ ($D = \text{p99} + \text{margin}$), eliminating timing side channels. |
| **KV-Cache Snooping (Tenant ↔ Tenant)** | PromptPeek attack: measuring Time-to-First-Token (TTFT) to deduce prompts executed by another tenant sharing the model. | Per-tenant isolated slots and session cache erasure (`POST /v1/slots/erase`) executed after every test round. |
| **Model Contamination (Anyone → LLM)** | Cross-session state persistence (planting canary codewords or prompt memory leaks). | Read-only model weights verified against SHA-256 weight hash. Prompt cache flushes between sessions prevent memory recall. |
| **Audit Ledger Tampering (Anyone → Results)** | Adversary or operator modifies, deletes, or reorders test logs to misrepresent safety findings. | Append-only SHA-256 hash chain with Ed25519 digital signatures and periodic Merkle checkpoints. Verifier pinpoints first corrupted sequence. |
| **Container Breakout & Lateral Movement** | Malicious payload in Red attempts to escape to host or connect directly to Blue/LLM. | gVisor user-space kernel (`runsc`), `cap_drop: ALL`, `no-new-privileges: true`, read-only rootfs, and 3 distinct internal Docker networks (`internal: true`) with 0 egress. |

---

## 3. Out-of-Scope Threats & Residual Risks

### 3.1 Malicious Host Operator
- **Risk:** An operator with `root` access on the physical host machine can inspect memory, kill processes, or extract private signing keys.
- **Mitigation/Boundary:** Out of scope for this sandbox prototype. In production, this requires Hardware Trusted Execution Environments (TEEs) such as AMD SEV-SNP or Intel TDX with remote attestation.

### 3.2 Linux Kernel Zero-Day Exploits
- **Risk:** An unknown kernel exploit targeting the host kernel or gVisor sandbox boundary.
- **Residual Risk:** gVisor intercepting system calls in user space drastically reduces the attack surface compared to standard `runc`, but residual kernel risk remains.

### 3.3 Shared GPU Hardware Side Channels
- **Risk:** Microarchitectural cache attacks on shared GPU memory.
- **Status:** TriSeal prototype executes exclusively on CPU (`llama.cpp` CPU build) without GPU dependencies, eliminating GPU side channels in this environment.

### 3.4 Out-of-Band Human Collusion
- **Risk:** Human operators on the Red team verbally communicating payloads to members of the Blue team.
- **Mitigation:** Out of scope for software infrastructure; enforced by organizational policy and audit trails.

### 3.5 Control Plane Docker Socket Trust
- **Risk:** The Control Plane interacts with the Docker socket to manage containers.
- **Residual Risk:** If the Control Plane is compromised, the attacker gains container management privileges. Minimized by binding all control plane APIs exclusively to localhost.

---

## 4. Production Evolution Path

1. **Sandboxing:** gVisor (`runsc`) $\rightarrow$ Confidential Containers (Kata Containers with AMD SEV-SNP / Intel TDX).
2. **Network Security:** Docker internal networks $\rightarrow$ Cilium eBPF network policies with mTLS encryption (SPIFFE/SPIRE identities).
3. **Capability Tokens:** Ed25519 tokens $\rightarrow$ Cryptographically attenuated Biscuit tokens.
4. **Audit Anchoring:** Local signed Merkle checkpoints $\rightarrow$ Public transparency log anchoring (Sigstore Rekor).
