import subprocess
import time
import urllib.request
import json
import statistics
from pathlib import Path

bin_path = Path("/root/triseal/chambers/llm/bin/llama-server")
if not bin_path.exists():
    bin_path = Path("chambers/llm/bin/llama-server")

model_path = Path("/root/triseal/chambers/llm/models/model.gguf")
if not model_path.exists():
    model_path = Path("chambers/llm/models/model.gguf")

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
print("[*] Launching llama-server for p99 calibration...")
proc = subprocess.Popen(cmd, env=env)
time.sleep(3.0)

try:
    prompts = [
        "What is the capital of France?",
        "Explain what a firewall does in one sentence.",
        "Count from 1 to 10.",
        "Name three primary colors.",
        "What is the square root of 64?",
        "Translate 'hello world' into Spanish.",
        "What is the primary function of an operating system kernel?",
        "Define the word 'integrity' in computer security.",
        "How many days are in a leap year?",
        "What is DNS and why is it used?",
    ] * 3  # 30 prompts

    latencies = []
    print(f"[*] Running {len(prompts)} completion requests to measure latency distribution...")
    for i, p in enumerate(prompts):
        body = {
            "messages": [{"role": "user", "content": p}],
            "temperature": 0.0,
            "max_tokens": 32,
        }
        req = urllib.request.Request(
            "http://127.0.0.1:8099/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=30) as resp:
            _ = resp.read()
        elapsed = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed)
        if (i + 1) % 5 == 0:
            print(f"  [{i+1}/{len(prompts)}] Last: {elapsed:.1f} ms")

    sorted_lats = sorted(latencies)
    n = len(sorted_lats)
    p50 = sorted_lats[int(0.50 * n)]
    p90 = sorted_lats[int(0.90 * n)]
    p95 = sorted_lats[int(0.95 * n)]
    p99 = sorted_lats[min(int(0.99 * n), n - 1)]
    max_lat = max(sorted_lats)
    min_lat = min(sorted_lats)
    mean_lat = statistics.mean(sorted_lats)

    print("=" * 60)
    print("REAL INFERENCE LATENCY BENCHMARK RESULTS (Qwen2.5-0.5B-Instruct)")
    print("=" * 60)
    print(f"Total Requests: {n}")
    print(f"Min:            {min_lat:.2f} ms")
    print(f"Mean:           {mean_lat:.2f} ms")
    print(f"p50 (Median):   {p50:.2f} ms")
    print(f"p90:            {p90:.2f} ms")
    print(f"p95:            {p95:.2f} ms")
    print(f"p99:            {p99:.2f} ms")
    print(f"Max:            {max_lat:.2f} ms")
    print("=" * 60)

    # Save to json for AUDIT.md evidence
    cal_res = {
        "model": "Qwen2.5-0.5B-Instruct",
        "file": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
        "size_bytes": 491400032,
        "sample_size": n,
        "min_ms": round(min_lat, 2),
        "mean_ms": round(mean_lat, 2),
        "p50_ms": round(p50, 2),
        "p90_ms": round(p90, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "max_ms": round(max_lat, 2),
        "suggested_deadline_ms": round(p99 * 1.35, 0),
    }
    with open("audit_runs/calibration_data.json", "w") as f:
        json.dump(cal_res, f, indent=2)
    print(f"[+] Suggested REPLY_DEADLINE_MS (p99 + 35% margin): {cal_res['suggested_deadline_ms']} ms")

finally:
    proc.terminate()
    proc.wait()
