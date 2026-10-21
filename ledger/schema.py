import json
import hashlib
from typing import Dict, Any, Optional

def canonical_json(obj: Dict[str, Any]) -> str:
    """RFC 8785 style canonical JSON formatting (sorted keys, compact separators)."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def compute_payload_hash(payload: Any) -> str:
    """Computes SHA-256 of canonical payload string or raw bytes."""
    if isinstance(payload, bytes):
        return compute_sha256(payload)
    if isinstance(payload, str):
        return compute_sha256(payload.encode("utf-8"))
    return compute_sha256(canonical_json(payload).encode("utf-8"))

def compute_entry_hash(prev_hash: str, event_data: Dict[str, Any]) -> str:
    """Computes entry hash: SHA-256(prev_hash || canonical_json(event_without_entry_hash_and_sig))."""
    # Exclude entry_hash and signature from the content to be hashed
    payload = {
        "seq": event_data["seq"],
        "ts": event_data["ts"],
        "round_id": event_data["round_id"],
        "actor": event_data["actor"],
        "event_type": event_data["event_type"],
        "payload_hash": event_data["payload_hash"],
        "meta": event_data.get("meta", {}),
        "prev_hash": prev_hash,
    }
    canon = canonical_json(payload)
    return compute_sha256((prev_hash + canon).encode("utf-8"))
