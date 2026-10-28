# TriSeal: Technical Architecture Specification

## 1. System Topology & Chamber Boundaries

TriSeal implements a multi-chamber security model enforcing isolation across adversarial AI safety testing participants.

```
                     +---------------------------------------+
                     |    CONTROL PLANE (Trusted, Port 8080) |
                     | Round State Machine · Commit-Reveal   |
                     | Ed25519 Capability Tokens            |
                     +---------------------------------------+
                                         |
                                         v
                     +---------------------------------------+
                     |      ARBITER GATEWAY (Port 8000)      |
                     | Audited Boundary Gate · Uniform Envelopes |
                     | Fixed Deadline D · Zero-Plaintext Ledger |
                     +---------------------------------------+
                           /             |             \
              (net_red)   /  (net_blue)  |  (net_llm)   \
                         v               v               v
+-----------------------------+ +-----------------+ +-------------------+
|     RED CHAMBER (8003)      | |   BLUE (8001)   | |    LLM (8002)     |
| Attack Runner (Datasets)    | | Sealed Guard    | | llama.cpp CPU     |
| Probe Targets (T1-T3, T8)   | | YAML Guardrails | | Slot Cache Erase  |
| AES-GCM Encrypted Payloads  | | Zero Egress     | | Read-Only Weights |
+-----------------------------+ +-----------------+ +-------------------+
```

### 1.1 Network Separation
- **`net_red`:** `internal: true`. Attached only to `red` and `arbiter`.
- **`net_blue`:** `internal: true`. Attached only to `blue` and `arbiter`.
- **`net_llm`:** `internal: true`. Attached only to `llm` and `arbiter`.
- **Result:** No packet can route directly between Red, Blue, or LLM. Only Arbiter bridges requests. External internet routing is disabled.

---

## 2. Cryptographic Ledger System

### 2.1 Canonical Serialization
To guarantee deterministic cryptographic hashes across heterogeneous environments, all event payloads are serialized using RFC 8785 canonical JSON formatting (keys sorted lexicographically, no whitespace between separators, UTF-8 encoded).

### 2.2 Hash-Chain Continuity
For each sequential entry $i$:
$$\text{entry\_hash}_i = \text{SHA-256}\left(\text{prev\_hash}_i \parallel \text{canonical\_json}(\text{event\_data}_i)\right)$$
Where:
- $\text{prev\_hash}_0 = 0^{64}$ (64 hexadecimal zeros).
- $\text{prev\_hash}_i = \text{entry\_hash}_{i-1}$ for $i > 0$.

### 2.3 Ed25519 Signatures
Every event hash is signed with the Control Plane's Ed25519 private key:
$$\text{sig}_i = \text{Sign}_{\text{Ed25519}}(\text{priv\_key}, \text{entry\_hash}_i)$$

### 2.4 Merkle Checkpoints
Every $N$ entries ($N=10$), an append-only Merkle checkpoint is generated. The Merkle root summarizes the $N$ entry hashes in a binary tree:
$$\text{MerkleRoot} = \text{BuildTree}(\text{entry\_hash}_{k}, \dots, \text{entry\_hash}_{k+N-1})$$
Checkpoints are independently signed and recorded in `data/checkpoints.jsonl`.

---

## 3. Side-Channel Elimination

### 3.1 Fixed Deadline Release ($D$)
In adversarial testing, response time leaks whether a prompt was blocked by a fast regex filter or processed through full model token generation (timing oracle attack).
- TriSeal establishes a fixed release deadline:
  $$D = \text{p99}_{\text{latency}} + \text{margin}$$
- For the active `Qwen2.5-0.5B-Instruct` model, empirical p99 inference latency is $909.50\text{ ms}$, yielding calibrated deadline $D = 1400\text{ ms}$ (`REPLY_DEADLINE_MS=1400`).
- Guard blocks and model completions are held in asynchronous timers until $t = D$.
- If generation times out at $D$, a uniform timeout refusal is emitted.
- Result: Timing variance between blocked and refused queries drops from $> 600\text{ms}$ in Baseline to a median p50 differential of $0.85\text{ms}$ in TriSeal ($< 12\text{ms}$ at p95 under host CPU virtualization).

### 3.2 Uniform Response Envelope
All replies from the Arbiter follow an identical JSON envelope:
```json
{
  "status": "completed",
  "response": "...",
  "refusal": true,
  "code": "UNIFORM_REPLY",
  "round_id": "...",
  "envelope_version": "1.0"
}
```
Attackers cannot distinguish between rule-based guard blocks and model refusals via HTTP status codes or JSON schema differences.

### 3.3 KV-Cache Slot Isolation
In shared LLMs, prompt prefixes remain cached in GPU/CPU memory (PromptPeek attack). TriSeal assigns dedicated slots per tenant and executes cache erasure (`POST /v1/slots/erase`) at the conclusion of every test round, preventing cross-tenant time-to-first-token inference.
