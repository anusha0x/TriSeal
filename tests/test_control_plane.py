import json
import base64
import os
import sys
import hashlib
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).parent.parent / "control-plane"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from ledger.chain import LedgerChain
from ledger.crypto import KeyManager
from round_manager import RoundManager, RoundState

@pytest.fixture
def manager(tmp_path):
    ledger = LedgerChain(str(tmp_path / "ledger.jsonl"), str(tmp_path / "cp.jsonl"), checkpoint_interval=5)
    km = KeyManager(str(tmp_path / "keys"))
    return RoundManager(ledger, km)

def test_round_commit_reveal_success(manager):
    rnd = manager.create_round("round_101")
    assert rnd["state"] == RoundState.COMMIT

    # Red prepares payload and encrypts
    red_key = AESGCM.generate_key(bit_length=256)
    red_aes = AESGCM(red_key)
    red_nonce = os.urandom(12)
    red_payload = b"AdvBench Harmful Prompts Canonical Set"
    red_ciphertext = red_aes.encrypt(red_nonce, red_payload, None)
    red_commit_hash = hashlib.sha256(red_payload).hexdigest()

    # Blue prepares guard and encrypts
    blue_key = AESGCM.generate_key(bit_length=256)
    blue_aes = AESGCM(blue_key)
    blue_nonce = os.urandom(12)
    blue_payload = b"Blue Guard Config YAML Rules"
    blue_ciphertext = blue_aes.encrypt(blue_nonce, blue_payload, None)
    blue_commit_hash = hashlib.sha256(blue_payload).hexdigest()

    # Submit commits
    manager.submit_commit(
        "round_101", "red", red_commit_hash,
        base64.b64encode(red_ciphertext).decode(),
        base64.b64encode(red_nonce).decode()
    )
    manager.submit_commit(
        "round_101", "blue", blue_commit_hash,
        base64.b64encode(blue_ciphertext).decode(),
        base64.b64encode(blue_nonce).decode()
    )

    # Seal and run
    run_res = manager.seal_and_run("round_101", query_budget=50)
    assert run_res["status"] == "running"
    assert "token" in run_res

    # Reveal
    rev_red = manager.reveal("round_101", "red", red_key.hex())
    assert rev_red["valid"] is True
    assert rev_red["hash"] == red_commit_hash

    rev_blue = manager.reveal("round_101", "blue", blue_key.hex())
    assert rev_blue["valid"] is True
    assert rev_blue["hash"] == blue_commit_hash

    # Final verify
    final = manager.verify_round("round_101")
    assert final["status"] == "COMPLETED"

def test_commit_reveal_mismatch_fails_round(manager):
    manager.create_round("round_102")

    key1 = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    payload1 = b"Real Payload"
    ciphertext1 = AESGCM(key1).encrypt(nonce, payload1, None)
    commit_hash = hashlib.sha256(payload1).hexdigest()

    # Pretend blue also committed
    manager.submit_commit("round_102", "red", commit_hash, base64.b64encode(ciphertext1).decode(), base64.b64encode(nonce).decode())
    manager.submit_commit("round_102", "blue", "dummy_hash", "blob", "nonce")

    # Tamper: encrypt DIFFERENT payload with key2
    key2 = AESGCM.generate_key(bit_length=256)
    tampered_payload = b"Altered Payload Mismatch"
    tampered_ciphertext = AESGCM(key2).encrypt(nonce, tampered_payload, None)
    manager.rounds["round_102"]["encrypted_store"]["red"]["blob"] = base64.b64encode(tampered_ciphertext).decode()

    # Reveal with key2
    res = manager.reveal("round_102", "red", key2.hex())
    assert res["valid"] is False
    assert "mismatch" in res["reason"].lower()
    assert manager.rounds["round_102"]["state"] == RoundState.FAILED
