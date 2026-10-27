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
| **Defense Oracle Leak (Blue → Red)** | Attacker infers internal guardrail patterns or model refusals from error codes or response latency differentials. | **Uniform fixed-deadline replies:** Guard blocks and model refusals share an identical JSON response envelope. All replies are held until calibrated deadline D (D = p99 + margin), eliminating timing side channels. |
| **KV-Cache Snooping (Tenant ↔ Tenant)** | PromptPeek attack: measuring Time-to-First-Token (TTFT) to deduce prompts executed by another tenant sharing the model. | Per-tenant isolated slots and session cache erasure (`POST /v1/slots/erase`) executed after every test round. |
| **Model Contamination (Anyone → LLM)** | Cross-session state persistence (planting canary codewords or prompt memory leaks). | Read-only model weights verified against SHA-256 weight hash. Prompt cache flushes between sessions prevent memory recall. |
| **Audit Ledger Tampering (Anyone → Results)** | Adversary or operator modifies, deletes, or reorders test logs to misrepresent safety findings. | Append-only SHA-256 hash chain with Ed25519 digital signatures, pinned root public key, and periodic Merkle checkpoints. Verifier pinpoints first corrupted sequence. |
| **Container Breakout & Lateral Movement** | Malicious payload in Red attempts to escape to host or connect directly to Blue/LLM. | gVisor user-space kernel (`runsc`), `cap_drop: ALL`, `no-new-privileges: true`, read-only rootfs, and 4 distinct internal Docker networks (`internal: true`) with 0 egress. |

---

## 3. Out-of-Scope Threats & Residual Risks

### 3.1 Malicious Host Operator & Signing Key Compromise
- **Risk:** An operator with `root` access on the physical host machine can inspect memory, kill processes, or extract the private signing key (`ledger_ed25519`).
- **Residual Risk:** An attacker who holds or compromises the private signing key can forge new signatures that match the pinned public key.
- **Mitigation & Boundary:** Only an out-of-band external anchor (such as git-committed checkpoints in `docs/anchors.txt`, or an immutable public transparency log like Sigstore Rekor) mitigates this by providing an external witness. In production, this requires Hardware Trusted Execution Environments (TEEs) such as AMD SEV-SNP or Intel TDX with remote attestation.

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
- **Residual Risk:** If the Control Plane is compromised, the attacker gains container management privileges. Minimized by binding all control plane APIs exclusively to localhost and avoiding docker socket mounts into chambers.

---

## 4. Production Evolution Path & Architectural Reality

The current prototype prioritizes strict empirical verification on standard developer workstations (Linux/WSL2 CPU) without cloud GPU or kernel-level dependencies:

1. **Sandboxing:**
   - *Current (Built):* gVisor (`runsc`) user-space Sentry kernel + dropped Linux capabilities + read-only rootfs.
   - *Production Path:* Confidential Containers (Kata Containers with AMD SEV-SNP or Intel TDX hardware memory encryption and remote attestation).
2. **Network Security:**
   - *Current (Built):* 4 isolated Docker bridge networks (`internal: true`) with iptables namespace segregation and 0 external egress.
   - *Production Path (Why Future):* Cilium eBPF network policies with mTLS encryption (SPIFFE/SPIRE). eBPF requires host kernel BPF access (`CAP_BPF`) and BTF enabled, which standard WSL2 kernels lack. Docker internal bridges provide identical L3/L4 packet dropping for local sandboxing.
3. **Capability Tokens & Policy:**
   - *Current (Built):* Ed25519-signed capability tokens verified by Arbiter Gateway.
   - *Production Path (Why Future):* Biscuit decentralized attenuated tokens and Open Policy Agent (OPA) dynamic bundle distribution. In a single-host prototype, Arbiter and Control Plane share cryptographic authority, so external Rust/Go FFI daemons add latency and image footprint without changing the boundary.
4. **Audit Anchoring:**
   - *Current (Built):* Append-only SHA-256 hash chain + Ed25519 signatures against pinned authority key (`ledger/trust/ledger_signing.pub`) + Merkle root checkpoints committed to `docs/anchors.txt`.
   - *Production Path (Why Future):* Sigstore Rekor immutable public transparency log. Enterprise AI safety testing frequently involves confidential or proprietary red team payloads that cannot be disclosed to a public log; the local Merkle anchor uses the exact same Merkle tree structure, ready to swap in a private enterprise Rekor instance.
5. **Model Serving:**
   - *Current (Built):* Native `llama.cpp` (`llama-server` b11756) on CPU with `Qwen2.5-0.5B-Instruct` GGUF, dynamic file byte SHA-256 weight hash, `--no-cache-prompt`, and audited slot erasure.
   - *Production Path (Why Future):* vLLM multi-GPU engine with PagedAttention and hardware memory encryption. Requires high-end NVIDIA GPUs (CUDA 12+, 16GB+ VRAM); `llama.cpp` was selected specifically to permit local auditability on any standard CPU.

