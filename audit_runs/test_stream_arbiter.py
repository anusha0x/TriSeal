import urllib.request
import json
import time

def test_stream(prompt, actor="tenant_a"):
    data = json.dumps({"prompt": prompt, "actor": actor, "round_id": f"r_{actor}"}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:8000/v1/gateway/stream", data=data, headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    ttft = None
    with urllib.request.urlopen(req, timeout=25) as resp:
        while line := resp.readline().decode().strip():
            if line.startswith("data: ") and line != "data: [DONE]":
                ttft = (time.perf_counter() - t0) * 1000.0
                print(f"[{actor}] TTFT: {ttft:.1f}ms | {line[:60]}")
                break
    return ttft

p = "A quick movement of the defense forces was observed along the northern perimeter. Surveillance systems logged thirty vehicles moving along the valley highway toward base camp alpha. " * 4

print("1. Prime:")
test_stream(p + " Question 1: What perimeter?", actor="tenant_a")
time.sleep(0.2)

print("2. Hit:")
t_hit = test_stream(p + " Question 2: What highway?", actor="tenant_b")
time.sleep(0.2)

print("3. Miss:")
diff_p = "Biological evolution operates through natural selection acting on genetic variation within reproducing populations across geological timescales on planet Earth. " * 4
t_miss = test_stream(diff_p + " Question 3: What planet?", actor="tenant_c")

print(f"Delta: {t_miss - t_hit:.1f}ms")
