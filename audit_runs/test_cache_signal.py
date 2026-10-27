import subprocess
import time
import urllib.request
import json
from pathlib import Path

bin_path = Path("/root/triseal/chambers/llm/bin/llama-server")
if not bin_path.exists():
    bin_path = Path("chambers/llm/bin/llama-server")

model_path = Path("/root/triseal/chambers/llm/models/model.gguf")
if not model_path.exists():
    model_path = Path("chambers/llm/models/model.gguf")

# Launch with --prompt-cache-all
cmd = [
    str(bin_path),
    "-m", str(model_path),
    "-c", "2048",
    "--cache-prompt",
    "--cache-reuse", "8",
    "--host", "127.0.0.1",
    "--port", "8099",
    "-t", "2",
    "-lv", "0",
]
env = {"LD_LIBRARY_PATH": str(bin_path.parent)}
print("[*] Launching llama-server with --prompt-cache-all...")
proc = subprocess.Popen(cmd, env=env)
time.sleep(3.0)

def measure_ttft(prompt_text):
    req_body = {
        "messages": [{"role": "user", "content": prompt_text}],
        "temperature": 0.0,
        "max_tokens": 16,
        "stream": True,
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8099/v1/chat/completions",
        data=json.dumps(req_body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    ttft = None
    with urllib.request.urlopen(req, timeout=15) as resp:
        while line := resp.readline().decode("utf-8").strip():
            if line.startswith("data: ") and line != "data: [DONE]":
                if ttft is None:
                    ttft = (time.perf_counter() - t0) * 1000.0
                break
    return ttft or ((time.perf_counter() - t0) * 1000.0)

try:
    long_prefix = "The quick brown fox jumps over the lazy dog. In computer science and artificial intelligence research, secure execution environments are critical for adversarial testing. Security isolation requires container virtualization, memory scrubbing, and deterministic timing governors. " * 3

    # Warm-up / Tenant A primes the cache
    print("[*] Tenant A sends prompt with 120-token prefix...")
    t_prime = measure_ttft(long_prefix + " Question 1: What animal is brown?")
    print(f"    Prime request TTFT: {t_prime:.2f} ms")

    # Tenant B sends query with IDENTICAL prefix (Cache Hit candidate)
    print("[*] Tenant B sends query with cached prefix...")
    t_hit = measure_ttft(long_prefix + " Question 2: What animal is lazy?")
    print(f"    Cache Hit TTFT:     {t_hit:.2f} ms")

    # Tenant C sends query with DIFFERENT prefix (Cache Miss candidate)
    different_prefix = "Astronomy and astrophysics explore the origins and structure of galaxies, dark matter, stellar evolution, and cosmic microwave background radiation throughout the observable universe. " * 3
    print("[*] Tenant C sends query with uncached prefix...")
    t_miss = measure_ttft(different_prefix + " Question 3: What is dark matter?")
    print(f"    Cache Miss TTFT:    {t_miss:.2f} ms")

    delta = t_miss - t_hit
    print(f"==> Delta (TTFT_miss - TTFT_hit): {delta:.2f} ms")

finally:
    proc.terminate()
    proc.wait()
