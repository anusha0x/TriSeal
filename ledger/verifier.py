import os
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

from .schema import compute_entry_hash, canonical_json
from .crypto import KeyManager
from .merkle import MerkleTree

class LedgerVerifier:
    """Cryptographic auditor for append-only hash chains and Merkle checkpoints."""

    def __init__(self, ledger_file: str = "data/ledger.jsonl", checkpoint_file: Optional[str] = "data/checkpoints.jsonl"):
        self.ledger_file = Path(ledger_file)
        self.checkpoint_file = Path(checkpoint_file) if checkpoint_file else None

    def read_entries(self) -> List[Dict[str, Any]]:
        entries = []
        if self.ledger_file.exists():
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f):
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception as e:
                            raise ValueError(f"Malformed JSON at line {idx+1}: {e}")
        return entries

    def verify_chain(self) -> Dict[str, Any]:
        """Recomputes hash chain from genesis and verifies all digital signatures."""
        entries = self.read_entries()
        if not entries:
            return {"valid": True, "total_entries": 0, "message": "Ledger is empty"}

        expected_prev = "0" * 64

        for idx, entry in enumerate(entries):
            seq = entry.get("seq")
            # 1. Monotonic sequence check
            if seq != idx:
                return {
                    "valid": False,
                    "broken_seq": idx,
                    "reason": f"Sequence discontinuity: expected {idx}, got {seq}",
                    "entry": entry,
                }

            # 2. Previous hash linkage check
            actual_prev = entry.get("prev_hash")
            if actual_prev != expected_prev:
                return {
                    "valid": False,
                    "broken_seq": seq,
                    "reason": f"Hash chain broken: prev_hash {actual_prev} does not match previous entry_hash {expected_prev}",
                    "entry": entry,
                }

            # 3. Canonical entry hash recomputation
            recomputed_hash = compute_entry_hash(actual_prev, entry)
            stored_hash = entry.get("entry_hash")
            if recomputed_hash != stored_hash:
                return {
                    "valid": False,
                    "broken_seq": seq,
                    "reason": f"Content tampering detected: recomputed hash {recomputed_hash} != stored hash {stored_hash}",
                    "entry": entry,
                }

            # 4. Ed25519 signature verification
            sig = entry.get("signature")
            pub_key = entry.get("pub_key")
            if not sig or not pub_key:
                return {
                    "valid": False,
                    "broken_seq": seq,
                    "reason": "Missing signature or public key",
                    "entry": entry,
                }

            sig_valid = KeyManager.verify(pub_key, stored_hash.encode("utf-8"), sig)
            if not sig_valid:
                return {
                    "valid": False,
                    "broken_seq": seq,
                    "reason": "Invalid cryptographic signature",
                    "entry": entry,
                }

            # Advance chain state
            expected_prev = stored_hash

        return {
            "valid": True,
            "total_entries": len(entries),
            "latest_seq": entries[-1]["seq"],
            "latest_hash": entries[-1]["entry_hash"],
            "message": "All entries cryptographically verified",
        }

    def verify_checkpoints(self) -> Dict[str, Any]:
        """Verifies all Merkle checkpoints against entries in the ledger."""
        if not self.checkpoint_file or not self.checkpoint_file.exists():
            return {"valid": True, "checkpoints_verified": 0, "message": "No checkpoints found"}

        entries = self.read_entries()
        entry_map = {e["seq"]: e["entry_hash"] for e in entries}

        checkpoints = []
        with open(self.checkpoint_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    checkpoints.append(json.loads(line))

        for cp in checkpoints:
            start_seq = cp["start_seq"]
            end_seq = cp["end_seq"]
            stored_root = cp["merkle_root"]
            pub_key = cp["pub_key"]
            sig = cp["signature"]

            # 1. Verify signature on checkpoint data
            cp_core = {
                "start_seq": start_seq,
                "end_seq": end_seq,
                "count": cp["count"],
                "merkle_root": stored_root,
                "ts": cp["ts"],
            }
            if not KeyManager.verify(pub_key, canonical_json(cp_core).encode("utf-8"), sig):
                return {
                    "valid": False,
                    "reason": f"Invalid signature on checkpoint [{start_seq}..{end_seq}]",
                    "checkpoint": cp,
                }

            # 2. Recompute Merkle root over ledger slice
            leaf_hashes = [entry_map[s] for s in range(start_seq, end_seq + 1) if s in entry_map]
            if len(leaf_hashes) != cp["count"]:
                return {
                    "valid": False,
                    "reason": f"Checkpoint count mismatch: expected {cp['count']}, ledger has {len(leaf_hashes)}",
                    "checkpoint": cp,
                }

            tree = MerkleTree(leaf_hashes)
            if tree.root != stored_root:
                return {
                    "valid": False,
                    "reason": f"Merkle root mismatch on checkpoint [{start_seq}..{end_seq}]: recomputed {tree.root} != stored {stored_root}",
                    "checkpoint": cp,
                }

        return {
            "valid": True,
            "checkpoints_verified": len(checkpoints),
            "message": "All Merkle checkpoints verified",
        }

def main():
    parser = argparse.ArgumentParser(description="TriSeal Tamper-Evident Ledger Verifier")
    parser.add_argument("--ledger-file", default="data/ledger.jsonl", help="Path to ledger jsonl file")
    parser.add_argument("--checkpoints", default="data/checkpoints.jsonl", help="Path to checkpoints jsonl file")
    args = parser.parse_args()

    verifier = LedgerVerifier(args.ledger_file, args.checkpoints)
    chain_res = verifier.verify_chain()
    print("=" * 60)
    print(" TriSeal Cryptographic Audit Result")
    print("=" * 60)
    if chain_res["valid"]:
        print(f"[PASS] Chain Integrity: VERIFIED ({chain_res.get('total_entries', 0)} entries)")
        print(f"       Latest Hash: {chain_res.get('latest_hash', 'N/A')}")
        cp_res = verifier.verify_checkpoints()
        if cp_res["valid"]:
            print(f"[PASS] Merkle Checkpoints: VERIFIED ({cp_res.get('checkpoints_verified', 0)} checkpoints)")
        else:
            print(f"[FAIL] Merkle Checkpoint Integrity: {cp_res.get('reason')}")
            exit(1)
    else:
        print(f"[FAIL] Chain Tampering Detected at Sequence #{chain_res.get('broken_seq')}")
        print(f"       Reason: {chain_res.get('reason')}")
        exit(1)

if __name__ == "__main__":
    main()
