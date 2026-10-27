import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from .schema import canonical_json, compute_entry_hash, compute_payload_hash
from .crypto import KeyManager
from .merkle import MerkleTree

class LedgerChain:
    """Cryptographic append-only event ledger with Ed25519 signatures and Merkle checkpoints."""

    def __init__(self, ledger_file: str = "data/ledger.jsonl", checkpoint_file: str = "data/checkpoints.jsonl", checkpoint_interval: int = 10, key_manager: Optional[KeyManager] = None):
        self.ledger_file = Path(ledger_file)
        self.checkpoint_file = Path(checkpoint_file)
        self.checkpoint_interval = checkpoint_interval
        try:
            self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        default_key_dir = os.environ.get("KEY_DIR")
        if not default_key_dir:
            if Path("/app/data/keys/ledger_ed25519").exists():
                default_key_dir = "/app/data/keys"
            elif Path("data/keys/ledger_ed25519").exists():
                default_key_dir = "data/keys"
            else:
                default_key_dir = str(self.ledger_file.parent / "keys")
        self.key_manager = key_manager or KeyManager(default_key_dir)
        self._entries: List[Dict[str, Any]] = []
        self._load_existing()

    def _load_existing(self):
        self._entries = []
        if self.ledger_file.exists():
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        import json
                        self._entries.append(json.loads(line))

    @property
    def latest_seq(self) -> int:
        return self._entries[-1]["seq"] if self._entries else -1

    @property
    def latest_hash(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else "0" * 64

    def append(self, round_id: str, actor: str, event_type: str, payload: Any, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Appends a new hashed and signed event to the ledger."""
        next_seq = self.latest_seq + 1
        prev_hash = self.latest_hash
        ts = datetime.now(timezone.utc).isoformat()
        payload_hash = compute_payload_hash(payload)
        meta = meta or {}

        event_core = {
            "seq": next_seq,
            "ts": ts,
            "round_id": round_id,
            "actor": actor,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "meta": meta,
            "prev_hash": prev_hash,
        }

        entry_hash = compute_entry_hash(prev_hash, event_core)
        signature = self.key_manager.sign(entry_hash.encode("utf-8"))

        entry = {
            **event_core,
            "entry_hash": entry_hash,
            "signature": signature,
            "pub_key": self.key_manager.public_key_hex,
        }

        # Append to memory
        self._entries.append(entry)

        # Append to file
        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(canonical_json(entry) + "\n")

        # Trigger Merkle checkpoint if interval reached
        if len(self._entries) % self.checkpoint_interval == 0:
            self._create_checkpoint()

        return entry

    def _create_checkpoint(self):
        """Creates a signed Merkle checkpoint covering the last N entries."""
        batch = self._entries[-self.checkpoint_interval:]
        start_seq = batch[0]["seq"]
        end_seq = batch[-1]["seq"]
        leaf_hashes = [e["entry_hash"] for e in batch]
        tree = MerkleTree(leaf_hashes)
        root = tree.root

        cp_data = {
            "start_seq": start_seq,
            "end_seq": end_seq,
            "count": len(batch),
            "merkle_root": root,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        cp_canon = canonical_json(cp_data)
        signature = self.key_manager.sign(cp_canon.encode("utf-8"))

        checkpoint_entry = {
            **cp_data,
            "signature": signature,
            "pub_key": self.key_manager.public_key_hex,
        }

        with open(self.checkpoint_file, "a", encoding="utf-8") as f:
            f.write(canonical_json(checkpoint_entry) + "\n")

    def get_entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)
