import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ledger.merkle import MerkleTree

def create_anchor(
    ledger_file: str = "data/ledger.jsonl",
    checkpoint_file: str = "data/checkpoints.jsonl",
    anchor_file: str = "docs/anchors.txt",
) -> Optional[dict]:
    """Appends an external anchor record (seq, merkle_root, entry_hash, ts) to docs/anchors.txt."""
    lpath = Path(ledger_file)
    cppath = Path(checkpoint_file)
    apath = Path(anchor_file)

    if not lpath.exists():
        print(f"[-] Ledger file {ledger_file} does not exist.")
        return None

    entries = []
    with open(lpath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    if not entries:
        print("[-] Ledger is empty; nothing to anchor.")
        return None

    latest_entry = entries[-1]
    latest_seq = latest_entry["seq"]
    latest_hash = latest_entry["entry_hash"]

    # Retrieve or compute Merkle root
    merkle_root = None
    if cppath.exists():
        with open(cppath, "r", encoding="utf-8") as f:
            cps = [json.loads(l) for l in f if l.strip()]
            if cps:
                merkle_root = cps[-1]["merkle_root"]

    if not merkle_root:
        # Compute Merkle root over all entry hashes up to latest
        hashes = [e["entry_hash"] for e in entries]
        tree = MerkleTree(hashes)
        merkle_root = tree.root

    ts = datetime.now(timezone.utc).isoformat()
    anchor_record = {
        "ts": ts,
        "seq": latest_seq,
        "root": merkle_root,
        "hash": latest_hash,
    }

    apath.parent.mkdir(parents=True, exist_ok=True)
    anchor_line = f"{ts} | seq:{latest_seq} | root:{merkle_root} | hash:{latest_hash}\n"
    with open(apath, "a", encoding="utf-8") as f:
        f.write(anchor_line)

    print(f"[+] Successfully anchored sequence #{latest_seq} to {anchor_file}")
    print(f"    Merkle Root: {merkle_root}")
    print(f"    Entry Hash:  {latest_hash}")
    return anchor_record

def main():
    parser = argparse.ArgumentParser(description="TriSeal External Ledger Anchor Utility")
    parser.add_argument("--ledger-file", default="data/ledger.jsonl", help="Path to ledger file")
    parser.add_argument("--checkpoints", default="data/checkpoints.jsonl", help="Path to checkpoints file")
    parser.add_argument("--anchor-file", default="docs/anchors.txt", help="Path to external anchors file")
    args = parser.parse_args()

    create_anchor(args.ledger_file, args.checkpoints, args.anchor_file)

if __name__ == "__main__":
    main()
