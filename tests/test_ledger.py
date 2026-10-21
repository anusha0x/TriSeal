import json
import pytest
from pathlib import Path
from ledger.chain import LedgerChain
from ledger.verifier import LedgerVerifier
from ledger.crypto import KeyManager
from ledger.merkle import MerkleTree

@pytest.fixture
def tmp_ledger(tmp_path):
    ledger_file = tmp_path / "test_ledger.jsonl"
    cp_file = tmp_path / "test_checkpoints.jsonl"
    return ledger_file, cp_file

def test_ledger_append_and_verify(tmp_ledger):
    ledger_file, cp_file = tmp_ledger
    chain = LedgerChain(str(ledger_file), str(cp_file), checkpoint_interval=5)

    for i in range(12):
        chain.append(
            round_id="round_alpha",
            actor="red" if i % 2 == 0 else "arbiter",
            event_type="STEP",
            payload={"index": i, "data": f"content_{i}"},
            meta={"hop": i},
        )

    verifier = LedgerVerifier(str(ledger_file), str(cp_file))
    res = verifier.verify_chain()
    assert res["valid"] is True
    assert res["total_entries"] == 12

    cp_res = verifier.verify_checkpoints()
    assert cp_res["valid"] is True
    assert cp_res["checkpoints_verified"] == 2  # 2 checkpoints for 12 items (interval=5)

def test_ledger_detects_content_tamper(tmp_ledger):
    ledger_file, cp_file = tmp_ledger
    chain = LedgerChain(str(ledger_file), str(cp_file), checkpoint_interval=5)

    for i in range(6):
        chain.append("r1", "red", "STEP", {"data": i})

    # Tamper with entry #2
    lines = ledger_file.read_text(encoding="utf-8").strip().split("\n")
    entry2 = json.loads(lines[2])
    entry2["actor"] = "attacker"
    lines[2] = json.dumps(entry2)
    ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = LedgerVerifier(str(ledger_file), None)
    res = verifier.verify_chain()
    assert res["valid"] is False
    assert res["broken_seq"] == 2
    assert "Content tampering detected" in res["reason"]

def test_ledger_detects_signature_tamper(tmp_ledger):
    ledger_file, cp_file = tmp_ledger
    chain = LedgerChain(str(ledger_file), str(cp_file), checkpoint_interval=5)

    for i in range(4):
        chain.append("r1", "red", "STEP", {"data": i})

    # Tamper with signature of entry #1
    lines = ledger_file.read_text(encoding="utf-8").strip().split("\n")
    entry1 = json.loads(lines[1])
    # Flip the first two hex characters
    entry1["signature"] = ("00" if entry1["signature"][:2] != "00" else "11") + entry1["signature"][2:]
    lines[1] = json.dumps(entry1)
    ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = LedgerVerifier(str(ledger_file), None)
    res = verifier.verify_chain()
    assert res["valid"] is False
    assert res["broken_seq"] == 1
    assert "Invalid cryptographic signature" in res["reason"]

def test_ledger_detects_deletion(tmp_ledger):
    ledger_file, cp_file = tmp_ledger
    chain = LedgerChain(str(ledger_file), str(cp_file), checkpoint_interval=5)

    for i in range(5):
        chain.append("r1", "red", "STEP", {"data": i})

    # Delete entry #2
    lines = ledger_file.read_text(encoding="utf-8").strip().split("\n")
    del lines[2]
    ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = LedgerVerifier(str(ledger_file), None)
    res = verifier.verify_chain()
    assert res["valid"] is False
    assert res["broken_seq"] == 2
    assert "Sequence discontinuity" in res["reason"]

def test_merkle_tree_proof():
    hashes = [f"leaf_hash_{i:02d}" for i in range(7)]
    tree = MerkleTree(hashes)
    root = tree.root

    for i in range(len(hashes)):
        proof = tree.get_proof(i)
        assert MerkleTree.verify_proof(hashes[i], proof, root) is True
