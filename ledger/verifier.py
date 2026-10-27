import os
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

from .schema import compute_entry_hash, canonical_json
from .crypto import KeyManager
from .merkle import MerkleTree

from cryptography.hazmat.primitives import serialization

class LedgerVerifier:
    """Cryptographic auditor for append-only hash chains and Merkle checkpoints."""

    def __init__(
        self,
        ledger_file: str = "data/ledger.jsonl",
        checkpoint_file: Optional[str] = "data/checkpoints.jsonl",
        trusted_pub_key_path: Optional[str] = "ledger/trust/ledger_signing.pub",
        anchor_file: Optional[str] = "docs/anchors.txt",
    ):
        self.ledger_file = Path(ledger_file)
        self.checkpoint_file = Path(checkpoint_file) if checkpoint_file else None
        self.trusted_pub_key_path = Path(trusted_pub_key_path) if trusted_pub_key_path else None
        self.anchor_file = Path(anchor_file) if anchor_file else None
        self.trusted_pub_key_hex = self._load_trusted_pub_key()

    def _load_trusted_pub_key(self) -> Optional[str]:
        if not self.trusted_pub_key_path or not self.trusted_pub_key_path.exists():
            return None
        content = self.trusted_pub_key_path.read_text(encoding="utf-8").strip()
        if content.startswith("-----BEGIN PUBLIC KEY-----"):
            pub_key = serialization.load_pem_public_key(content.encode("utf-8"))
            raw = pub_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return raw.hex()
        return content

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
        """Recomputes hash chain from genesis and verifies all digital signatures against pinned root key."""
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

            # 4. Ed25519 signature verification against pinned trust root
            sig = entry.get("signature")
            entry_pub_key = entry.get("pub_key")
            if not sig:
                return {
                    "valid": False,
                    "broken_seq": seq,
                    "reason": "Missing signature",
                    "entry": entry,
                }

            # Must NOT trust pub_key embedded in entry if pinned trust root is provided
            if self.trusted_pub_key_hex:
                if entry_pub_key and entry_pub_key.lower() != self.trusted_pub_key_hex.lower():
                    return {
                        "valid": False,
                        "broken_seq": seq,
                        "reason": f"Untrusted public key: entry has {entry_pub_key}, expected pinned key {self.trusted_pub_key_hex}",
                        "entry": entry,
                    }
                verify_key = self.trusted_pub_key_hex
            else:
                verify_key = entry_pub_key

            if not verify_key:
                return {
                    "valid": False,
                    "broken_seq": seq,
                    "reason": "Missing verification public key and no pinned trust root",
                    "entry": entry,
                }

            sig_valid = KeyManager.verify(verify_key, stored_hash.encode("utf-8"), sig)
            if not sig_valid:
                return {
                    "valid": False,
                    "broken_seq": seq,
                    "reason": "Invalid cryptographic signature under trusted authority",
                    "entry": entry,
                }

            # Advance chain state
            expected_prev = stored_hash

        return {
            "valid": True,
            "total_entries": len(entries),
            "latest_seq": entries[-1]["seq"],
            "latest_hash": entries[-1]["entry_hash"],
            "message": "All entries cryptographically verified against pinned trust root",
        }

    def verify_checkpoints(self) -> Dict[str, Any]:
        """Verifies all Merkle checkpoints against entries in the ledger using pinned root key."""
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
            entry_pub_key = cp.get("pub_key")
            sig = cp["signature"]

            if self.trusted_pub_key_hex:
                if entry_pub_key and entry_pub_key.lower() != self.trusted_pub_key_hex.lower():
                    return {
                        "valid": False,
                        "reason": f"Untrusted checkpoint public key: got {entry_pub_key}, expected pinned key {self.trusted_pub_key_hex}",
                        "checkpoint": cp,
                    }
                verify_key = self.trusted_pub_key_hex
            else:
                verify_key = entry_pub_key

            # 1. Verify signature on checkpoint data
            cp_core = {
                "start_seq": start_seq,
                "end_seq": end_seq,
                "count": cp["count"],
                "merkle_root": stored_root,
                "ts": cp["ts"],
            }
            if not KeyManager.verify(verify_key, canonical_json(cp_core).encode("utf-8"), sig):
                return {
                    "valid": False,
                    "reason": f"Invalid signature on checkpoint [{start_seq}..{end_seq}] under trusted authority",
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

    def verify_anchors(self) -> Dict[str, Any]:
        """Compares ledger against committed external anchors in docs/anchors.txt."""
        if not self.anchor_file or not self.anchor_file.exists():
            return {"valid": True, "anchors_verified": 0, "message": "No external anchor file present"}

        entries = self.read_entries()
        entry_map = {e["seq"]: e for e in entries}

        cp_map = {}
        if self.checkpoint_file and self.checkpoint_file.exists():
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        cp = json.loads(line)
                        cp_map[cp["end_seq"]] = cp["merkle_root"]

        anchors = []
        with open(self.anchor_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("{"):
                    try:
                        record = json.loads(line)
                        if "seq" in record:
                            # Map keys if needed
                            rec = {
                                "seq": record["seq"],
                                "hash": record.get("hash") or record.get("entry_hash"),
                                "root": record.get("root") or record.get("merkle_root"),
                                "ts": record.get("ts"),
                            }
                            anchors.append((line_no, rec))
                            continue
                    except Exception:
                        pass
                parts = [p.strip() for p in line.split("|")]
                record = {}
                for p in parts:
                    if ":" in p:
                        k, v = p.split(":", 1)
                        record[k.strip()] = v.strip()
                if "seq" in record:
                    anchors.append((line_no, record))

        for line_no, anchor in anchors:
            seq = int(anchor["seq"])
            if seq not in entry_map:
                return {
                    "valid": False,
                    "reason": f"External anchor at line {line_no} references seq {seq} not present in ledger",
                    "anchor": anchor,
                }

            entry = entry_map[seq]
            if "hash" in anchor and anchor["hash"] != entry["entry_hash"]:
                return {
                    "valid": False,
                    "reason": f"External anchor mismatch at seq {seq}: expected entry_hash {anchor['hash']}, ledger has {entry['entry_hash']}",
                    "anchor": anchor,
                }
            if "root" in anchor:
                expected_root = anchor["root"]
                if seq in cp_map and cp_map[seq] != expected_root:
                    return {
                        "valid": False,
                        "reason": f"External anchor Merkle root mismatch at seq {seq}: expected {expected_root}, checkpoint has {cp_map[seq]}",
                        "anchor": anchor,
                    }

        return {
            "valid": True,
            "anchors_verified": len(anchors),
            "message": f"All {len(anchors)} external anchors verified against ledger",
        }

def main():
    parser = argparse.ArgumentParser(description="TriSeal Tamper-Evident Ledger Verifier")
    parser.add_argument("--ledger-file", default="data/ledger.jsonl", help="Path to ledger jsonl file")
    parser.add_argument("--checkpoints", default="data/checkpoints.jsonl", help="Path to checkpoints jsonl file")
    parser.add_argument("--trusted-key", default="ledger/trust/ledger_signing.pub", help="Path to pinned authority public key")
    parser.add_argument("--anchor-file", default="docs/anchors.txt", help="Path to external anchors file")
    args = parser.parse_args()

    verifier = LedgerVerifier(args.ledger_file, args.checkpoints, args.trusted_key, args.anchor_file)
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

        anchor_res = verifier.verify_anchors()
        if anchor_res["valid"]:
            if anchor_res.get("anchors_verified", 0) > 0:
                print(f"[PASS] External Anchors: VERIFIED ({anchor_res.get('anchors_verified')} anchors)")
        else:
            print(f"[FAIL] External Anchor Mismatch: {anchor_res.get('reason')}")
            exit(1)
    else:
        print(f"[FAIL] Chain Tampering / Untrusted Key Detected at Sequence #{chain_res.get('broken_seq')}")
        print(f"       Reason: {chain_res.get('reason')}")
        exit(1)

if __name__ == "__main__":
    main()
