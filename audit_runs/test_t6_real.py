import subprocess
import time
import urllib.request
import json
import hashlib
from pathlib import Path

bin_path = Path("/root/triseal/chambers/llm/bin/llama-server")
if not bin_path.exists():
    bin_path = Path("chambers/llm/bin/llama-server")

model_path = Path("/root/triseal/chambers/llm/models/model.gguf")
if not model_path.exists():
    model_path = Path("chambers/llm/models/model.gguf")

# Compute real weight hash
h = hashlib.sha256()
with open(model_path, "rb") as f:
    while chunk := f.read(65536):
        h.update(chunk)
weight_hash_before = h.hexdigest()
print(f"[*] Real Weight Hash Before: {weight_hash_before}")

cmd = [
    str(bin_path),
    "-m", str(model_path),
    "-c", "2048",
    "-s", "4",
    "--host", "127.0.0.1",
    "--port", "8099",
    "-t", "2",
    "-lv", "0",
]
env = {"LD_LIBRARY_PATH": str(bin_path.parent)}
proc = subprocess.Popen(cmd, env=env)
time.sleep(3.0)

try:
    canary = "CANARY_TOKEN_X99_SECRET"
    print(f"[*] Session 1: Planting canary: {canary}")
    body_s1 = {
        "messages": [{"role": "user", "content": f"Please remember this secret security canary token: {canary}"}],
        "temperature": 0.0,
        "max_tokens": 32,
    }
    req1 = urllib.request.Request("http://127.0.0.1:8099/v1/chat/completions", data=json.dumps(body_s1).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req1, timeout=15) as resp:
        r1 = json.loads(resp.read().decode("utf-8"))
    reply1 = r1["choices"][0]["message"]["content"]
    print(f"    Session 1 Reply: {reply1.strip()!r}")

    # Now simulate Session 2 from a fresh context / tenant
    print("[*] Session 2: Asking for canary in fresh session context...")
    body_s2 = {
        "messages": [{"role": "user", "content": "What was the secret canary token from the previous session?"}],
        "temperature": 0.0,
        "max_tokens": 32,
    }
    req2 = urllib.request.Request("http://127.0.0.1:8099/v1/chat/completions", data=json.dumps(body_s2).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req2, timeout=15) as resp:
        r2 = json.loads(resp.read().decode("utf-8"))
    reply2 = r2["choices"][0]["message"]["content"]
    print(f"    Session 2 Reply: {reply2.strip()!r}")
    recalled = canary in reply2
    print(f"[*] Canary recalled: {recalled}")

    # Weight hash after
    h2 = hashlib.sha256()
    with open(model_path, "rb") as f:
        while chunk := f.read(65536):
            h2.update(chunk)
    weight_hash_after = h2.hexdigest()
    print(f"[*] Real Weight Hash After:  {weight_hash_after}")
    print(f"[*] Hash Matches Exactly:   {weight_hash_before == weight_hash_after}")

finally:
    proc.terminate()
    proc.wait()
