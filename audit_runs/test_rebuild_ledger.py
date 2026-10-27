import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import sys
sys.path.insert(0, ".")
from ledger.verifier import LedgerVerifier

# 1. Create a legitimate ledger with trusted authority key pair A
priv1 = ed25519.Ed25519PrivateKey.generate()
pub1_obj = priv1.public_key()
pub1_pem = pub1_obj.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
pub1_hex = pub1_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

trusted_key_path = Path("audit_runs/pinned_authority.pub")
trusted_key_path.write_bytes(pub1_pem)

entries = []
prev = "0" * 64
for i in range(5):
    body = {
        "seq": i,
        "ts": "2026-10-21T00:00:00Z",
        "round_id": "r1",
        "actor": "red",
        "event_type": "PROMPT_INGRESS",
        "payload_hash": hashlib.sha256(f"legitimate_prompt_{i}".encode()).hexdigest(),
        "meta": {"hop": 1},
        "prev_hash": prev,
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    ehash = hashlib.sha256((prev + canon).encode()).hexdigest()
    sig = priv1.sign(ehash.encode()).hex()
    entry = {**body, "entry_hash": ehash, "signature": sig, "pub_key": pub1_hex}
    entries.append(entry)
    prev = ehash

Path("audit_runs/legitimate_ledger.jsonl").write_text("\n".join(json.dumps(e) for e in entries) + "\n")

# 2. An attacker with host access replaces sequence #2, generates key pair B, recomputes hashes and rogue signatures
priv_attacker = ed25519.Ed25519PrivateKey.generate()
pub_attacker_hex = priv_attacker.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

entries_tampered = []
prev = "0" * 64
for i, e in enumerate(entries):
    e_new = dict(e)
    if i == 2:
        e_new["payload_hash"] = hashlib.sha256(b"MALICIOUS_SUBSTITUTED_PAYLOAD").hexdigest()
    e_new["prev_hash"] = prev
    body = {k: v for k, v in e_new.items() if k not in ["entry_hash", "signature", "pub_key"]}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    ehash = hashlib.sha256((prev + canon).encode()).hexdigest()
    sig = priv_attacker.sign(ehash.encode()).hex()
    e_new["entry_hash"] = ehash
    e_new["signature"] = sig
    e_new["pub_key"] = pub_attacker_hex
    entries_tampered.append(e_new)
    prev = ehash

Path("audit_runs/forged_ledger.jsonl").write_text("\n".join(json.dumps(e) for e in entries_tampered) + "\n")

# 3. Verify both ledgers against pinned authority public key
verifier_orig = LedgerVerifier("audit_runs/legitimate_ledger.jsonl", None, trusted_pub_key_path=str(trusted_key_path))
res_orig = verifier_orig.verify_chain()

verifier_forged = LedgerVerifier("audit_runs/forged_ledger.jsonl", None, trusted_pub_key_path=str(trusted_key_path))
res_forged = verifier_forged.verify_chain()

print("Original ledger valid:", res_orig["valid"])
print("Forged ledger valid:  ", res_forged["valid"])
print("Forged ledger reason: ", res_forged.get("reason"))
if not res_forged["valid"]:
    print("SUCCESS: Forged ledger was rejected due to pinned root public key enforcement!")
else:
    print("FAIL: Forged ledger was incorrectly accepted!")
