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

cmd = [
    str(bin_path),
    "-m", str(model_path),
    "-c", "2048",
    "-s", "4",
    "--cache-prompt",
    "--cache-reuse", "1",
    "--host", "127.0.0.1",
    "--port", "8099",
    "-t", "2",
    "-lv", "0",
]
env = {"LD_LIBRARY_PATH": str(bin_path.parent)}
print("[*] Launching llama-server with prompt caching on port 8099...")
proc = subprocess.Popen(cmd, env=env)
time.sleep(3.0)

def measure_streaming_ttft(prompt_text):
    req_body = {
        "messages": [{"role": "user", "content": prompt_text}],
        "temperature": 0.0,
        "max_tokens": 10,
        "stream": True,
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8099/v1/chat/completions",
        data=json.dumps(req_body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    ttft = None
    first_tok = ""
    with urllib.request.urlopen(req, timeout=15) as resp:
        while line := resp.readline().decode("utf-8").strip():
            if line.startswith("data: ") and line != "data: [DONE]":
                now = time.perf_counter()
                if ttft is None:
                    ttft = (now - t0) * 1000.0
                try:
                    payload = json.loads(line[6:])
                    tok = payload["choices"][0]["delta"].get("content", "")
                    if tok and not first_tok:
                        first_tok = tok
                except Exception:
                    pass
    return ttft or ((time.perf_counter() - t0) * 1000.0), first_tok

try:
    prefix = "A quick movement of the enemy forces was observed near the northern perimeter. Surveillance systems logged thirty vehicles moving along the valley highway toward base camp alpha. " * 4

    print("[*] Running 5 iterations of Cache Hit vs Cache Miss...")
    hit_times = []
    miss_times = []

    for i in range(5):
        # 1. Prime cache with prefix
        ttft_prime, _ = measure_streaming_ttft(prefix + f" Iteration {i} prime.")
        time.sleep(0.1)

        # 2. Query with same prefix (Hit)
        ttft_hit, tok_h = measure_streaming_ttft(prefix + f" Query {i} hit: What base?")
        hit_times.append(ttft_hit)
        time.sleep(0.1)

        # 3. Query with fresh uncached prefix of same length (Miss)
        diff_prefix = f"Biological evolution round {i} operates through natural selection acting on genetic variation within reproducing populations across geological timescales on planet Earth #{i}. " * 4
        ttft_miss, tok_m = measure_streaming_ttft(diff_prefix + f" Query {i} miss: What planet?")
        miss_times.append(ttft_miss)
        time.sleep(0.1)

        print(f"  Round {i+1}: Hit TTFT = {ttft_hit:.2f} ms | Miss TTFT = {ttft_miss:.2f} ms | Delta = {ttft_miss - ttft_hit:.2f} ms")

    avg_hit = sum(hit_times) / len(hit_times)
    avg_miss = sum(miss_times) / len(miss_times)
    avg_delta = avg_miss - avg_hit
    print("=" * 60)
    print(f"Average Hit TTFT:  {avg_hit:.2f} ms")
    print(f"Average Miss TTFT: {avg_miss:.2f} ms")
    print(f"Average Delta:     {avg_delta:.2f} ms")
    print("=" * 60)

finally:
    proc.terminate()
    proc.wait()
