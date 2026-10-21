import shutil
import json
from pathlib import Path
from .chain import LedgerChain
from .verifier import LedgerVerifier

def run_tamper_demo(original_ledger: str = "data/ledger.jsonl", tampered_ledger: str = "data/ledger_tampered.jsonl"):
    orig_path = Path(original_ledger)
    tamp_path = Path(tampered_ledger)
    tamp_path.parent.mkdir(parents=True, exist_ok=True)

    # If original doesn't exist or is empty, create a sample chain
    if not orig_path.exists() or orig_path.stat().st_size == 0:
        chain = LedgerChain(ledger_file=str(orig_path), checkpoint_file="data/checkpoints.jsonl", checkpoint_interval=5)
        for i in range(12):
            chain.append(
                round_id="demo_round_1",
                actor="red" if i % 2 == 0 else "blue",
                event_type="PROMPT_SENT" if i % 2 == 0 else "GUARD_INSPECTED",
                payload={"step": i, "content": f"Sample payload data #{i}"},
                meta={"index": i},
            )

    # 1. Verify that original is 100% valid
    v_orig = LedgerVerifier(str(orig_path), "data/checkpoints.jsonl")
    res_orig = v_orig.verify_chain()
    print("=" * 60)
    print(" TriSeal Ledger Tamper Demonstration")
    print("=" * 60)
    print(f"Step 1: Auditing original ledger ({orig_path})...")
    print(f"        Status: {'VALID' if res_orig['valid'] else 'INVALID'}")
    assert res_orig["valid"], "Original ledger must be valid before tampering"

    # 2. Create tampered copy
    shutil.copyfile(orig_path, tamp_path)
    entries = []
    with open(tamp_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))

    # Tamper with entry at index 2 (modify payload_hash and meta)
    target_idx = 2
    if len(entries) > target_idx:
        tampered_entry = entries[target_idx]
        print(f"\nStep 2: Injecting unauthorized modification at sequence #{target_idx}...")
        print(f"        Original actor: {tampered_entry.get('actor')}")
        tampered_entry["actor"] = "malicious_actor"
        tampered_entry["meta"]["tampered"] = True
        entries[target_idx] = tampered_entry

        with open(tamp_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    # 3. Audit tampered ledger
    print(f"\nStep 3: Running cryptographic auditor on tampered ledger ({tamp_path})...")
    v_tamp = LedgerVerifier(str(tamp_path), None)
    res_tamp = v_tamp.verify_chain()

    if not res_tamp["valid"]:
        print("\n" + "#" * 60)
        print(" [SECURITY ALERT] CRYPTOGRAPHIC INTEGRITY VIOLATION DETECTED!")
        print(f" First broken sequence number: #{res_tamp.get('broken_seq')}")
        print(f" Detection reason: {res_tamp.get('reason')}")
        print(" Tamper evidence successfully isolated and reported to operator.")
        print("#" * 60)
        return True
    else:
        print("[ERROR] Verifier failed to catch tampering!")
        return False

if __name__ == "__main__":
    success = run_tamper_demo()
    exit(0 if success else 1)
