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
    "-c", "1024",
    "-s", "4",
    "--host", "127.0.0.1",
    "--port", "8099",
    "-t", "2",
    "-lv", "0",
]
env = {"LD_LIBRARY_PATH": str(bin_path.parent)}
print("[*] Launching real llama-server...")
proc = subprocess.Popen(cmd, env=env)
time.sleep(3.0)

try:
    # 1. Warm-up query
    req_body = {
        "messages": [{"role": "user", "content": "What is the capital of France? Answer in one word."}],
        "temperature": 0.0,
        "max_tokens": 16,
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8099/v1/chat/completions",
        data=json.dumps(req_body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode("utf-8"))
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    reply = res["choices"][0]["message"]["content"]
    print(f"[+] Real LLM Response: {reply.strip()!r}")
    print(f"[+] Total Latency:     {elapsed_ms:.2f} ms")

    # 2. Test streaming TTFT
    req_body_stream = {
        "messages": [{"role": "user", "content": "Count from 1 to 5."}],
        "temperature": 0.0,
        "max_tokens": 16,
        "stream": True,
    }
    req_stream = urllib.request.Request(
        "http://127.0.0.1:8099/v1/chat/completions",
        data=json.dumps(req_body_stream).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    ttft = None
    tokens = []
    with urllib.request.urlopen(req_stream, timeout=15) as resp:
        while line := resp.readline().decode("utf-8").strip():
            if line.startswith("data: ") and line != "data: [DONE]":
                if ttft is None:
                    ttft = (time.perf_counter() - t0) * 1000.0
                try:
                    payload = json.loads(line[6:])
                    tok = payload["choices"][0]["delta"].get("content", "")
                    if tok:
                        tokens.append(tok)
                except Exception:
                    pass
    print(f"[+] Real Streaming TTFT: {ttft:.2f} ms")
    print(f"[+] Streamed Output:     {''.join(tokens)!r}")

finally:
    print("[*] Terminating llama-server...")
    proc.terminate()
    proc.wait()
