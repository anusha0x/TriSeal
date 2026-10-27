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

def test_ledger_rejects_untrusted_signing_key(tmp_ledger, tmp_path):
    ledger_file, cp_file = tmp_ledger
    chain = LedgerChain(str(ledger_file), str(cp_file), checkpoint_interval=5)
    for i in range(3):
        chain.append("r1", "red", "STEP", {"data": i})

    # Legitimate key
    trusted_key_file = tmp_path / "trusted.pub"
    trusted_key_file.write_text(chain.key_manager.public_key_hex)

    # Verifier with legitimate pinned key passes
    v_good = LedgerVerifier(str(ledger_file), str(cp_file), trusted_pub_key_path=str(trusted_key_file))
    assert v_good.verify_chain()["valid"] is True

    # Pinned rogue key
    rogue_key_file = tmp_path / "rogue.pub"
    rogue_km = KeyManager(str(tmp_path / "rogue_keys"))
    rogue_key_file.write_text(rogue_km.public_key_hex)

    # Verifier with rogue key rejects chain signed by original key
    v_bad = LedgerVerifier(str(ledger_file), str(cp_file), trusted_pub_key_path=str(rogue_key_file))
    res_bad = v_bad.verify_chain()
    assert res_bad["valid"] is False
    assert "Untrusted public key" in res_bad["reason"]

def test_ledger_external_anchors(tmp_ledger, tmp_path):
    ledger_file, cp_file = tmp_ledger
    chain = LedgerChain(str(ledger_file), str(cp_file), checkpoint_interval=5)
    for i in range(5):
        chain.append("r1", "red", "STEP", {"data": i})

    anchor_file = tmp_path / "anchors.txt"
    trusted_key_file = tmp_path / "trusted.pub"
    trusted_key_file.write_text(chain.key_manager.public_key_hex)

    # Create anchor utility
    from ledger.anchor import create_anchor
    anchor_rec = create_anchor(str(ledger_file), str(cp_file), str(anchor_file))
    assert anchor_rec is not None
    assert anchor_rec["seq"] == 4

    verifier = LedgerVerifier(str(ledger_file), str(cp_file), trusted_pub_key_path=str(trusted_key_file), anchor_file=str(anchor_file))
    res = verifier.verify_anchors()
    assert res["valid"] is True
    assert res["anchors_verified"] == 1

    # Tamper with anchor file
    anchor_file.write_text("2026-10-27T00:00:00Z | seq:4 | root:0000000000000000000000000000000000000000000000000000000000000000 | hash:1111111111111111111111111111111111111111111111111111111111111111\n")
    res_bad = verifier.verify_anchors()
    assert res_bad["valid"] is False
    assert "External anchor mismatch" in res_bad["reason"]

