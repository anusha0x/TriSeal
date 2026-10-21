import os
import json
import base64
import hashlib
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ledger.chain import LedgerChain
from ledger.schema import canonical_json, compute_sha256
from ledger.crypto import KeyManager

class RoundState(str, Enum):
    COMMIT = "COMMIT"
    SEAL = "SEAL"
    RUN = "RUN"
    REVEAL = "REVEAL"
    VERIFY = "VERIFY"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class RoundManager:
    """Manages the audited Round State Machine and Commit-Reveal protocol."""

    def __init__(self, ledger: LedgerChain, key_manager: Optional[KeyManager] = None):
        self.ledger = ledger
        self.key_manager = key_manager or KeyManager("data/keys")
        self.rounds: Dict[str, Dict[str, Any]] = {}

    def create_round(self, round_id: str) -> Dict[str, Any]:
        rnd = {
            "round_id": round_id,
            "state": RoundState.COMMIT,
            "commits": {},
            "reveals": {},
            "encrypted_store": {},
            "tokens": {},
            "created_at": self.ledger.latest_hash,
        }
        self.rounds[round_id] = rnd
        self.ledger.append(
            round_id=round_id,
            actor="control-plane",
            event_type="ROUND_INITIALIZED",
            payload={"state": RoundState.COMMIT},
        )
        return rnd

    def submit_commit(self, round_id: str, actor: str, commit_hash: str, encrypted_blob_b64: str, nonce_b64: str) -> Dict[str, Any]:
        rnd = self.rounds.get(round_id)
        if not rnd:
            raise ValueError(f"Round {round_id} does not exist")
        if rnd["state"] != RoundState.COMMIT:
            raise ValueError(f"Cannot commit in state {rnd['state']}")

        rnd["commits"][actor] = commit_hash
        rnd["encrypted_store"][actor] = {
            "blob": encrypted_blob_b64,
            "nonce": nonce_b64,
        }

        self.ledger.append(
            round_id=round_id,
            actor=actor,
            event_type="COMMIT_REGISTERED",
            payload={"actor": actor, "commit_hash": commit_hash},
        )
        return {"status": "committed", "actor": actor, "commit_hash": commit_hash}

    def seal_and_run(self, round_id: str, query_budget: int = 50) -> Dict[str, Any]:
        rnd = self.rounds.get(round_id)
        if not rnd:
            raise ValueError(f"Round {round_id} does not exist")
        if "red" not in rnd["commits"] or "blue" not in rnd["commits"]:
            raise ValueError("Both red and blue must commit before sealing")

        rnd["state"] = RoundState.SEAL
        self.ledger.append(round_id=round_id, actor="control-plane", event_type="ROUND_SEALED", payload={})

        # Issue capability token for Red
        token_payload = {
            "round_id": round_id,
            "actor": "red",
            "budget": query_budget,
            "scope": ["execute_prompt"],
        }
        token_canon = canonical_json(token_payload)
        sig = self.key_manager.sign(token_canon.encode("utf-8"))
        token_token = base64.urlsafe_b64encode(json.dumps({"body": token_payload, "sig": sig}).encode()).decode()
        rnd["tokens"]["red"] = token_token

        rnd["state"] = RoundState.RUN
        self.ledger.append(
            round_id=round_id,
            actor="control-plane",
            event_type="ROUND_STARTED",
            payload={"query_budget": query_budget},
        )
        return {"status": "running", "token": token_token}

    def reveal(self, round_id: str, actor: str, key_hex: str) -> Dict[str, Any]:
        rnd = self.rounds.get(round_id)
        if not rnd:
            raise ValueError(f"Round {round_id} does not exist")

        rnd["state"] = RoundState.REVEAL
        enc = rnd["encrypted_store"].get(actor)
        if not enc:
            raise ValueError(f"No encrypted material for {actor}")

        try:
            key_bytes = bytes.fromhex(key_hex)
            aesgcm = AESGCM(key_bytes)
            nonce = base64.b64decode(enc["nonce"])
            ciphertext = base64.b64decode(enc["blob"])
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            # Recompute commit hash: SHA-256(plaintext)
            computed_hash = hashlib.sha256(plaintext).hexdigest()
            expected_hash = rnd["commits"].get(actor)

            if computed_hash != expected_hash:
                rnd["state"] = RoundState.FAILED
                self.ledger.append(
                    round_id=round_id,
                    actor="control-plane",
                    event_type="REVEAL_MISMATCH",
                    payload={"actor": actor, "expected": expected_hash, "computed": computed_hash},
                )
                return {"valid": False, "reason": "Hash mismatch against commit"}

            rnd["reveals"][actor] = plaintext.decode("utf-8", errors="ignore")
            self.ledger.append(
                round_id=round_id,
                actor=actor,
                event_type="REVEAL_VERIFIED",
                payload={"actor": actor, "hash": computed_hash},
            )
            return {"valid": True, "actor": actor, "hash": computed_hash}

        except Exception as e:
            rnd["state"] = RoundState.FAILED
            return {"valid": False, "reason": f"Decryption failure: {e}"}

    def verify_round(self, round_id: str) -> Dict[str, Any]:
        rnd = self.rounds.get(round_id)
        if not rnd:
            raise ValueError(f"Round {round_id} does not exist")

        rnd["state"] = RoundState.VERIFY
        if rnd["state"] == RoundState.FAILED:
            return {"status": "FAILED", "reason": "Round failed verification"}

        rnd["state"] = RoundState.COMPLETED
        self.ledger.append(
            round_id=round_id,
            actor="control-plane",
            event_type="ROUND_COMPLETED",
            payload={"status": "AUDITED_AND_VERIFIED"},
        )
        return {"status": "COMPLETED", "round_id": round_id}
