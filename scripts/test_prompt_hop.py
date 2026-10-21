import urllib.request
import json
import sys

prompt = sys.argv[1] if len(sys.argv) > 1 else "Hello TriSeal, verify end-to-end prompt hop."
url = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8003/v1/attack/send"

payload = {
    "prompt": prompt,
    "round_id": "phase1_acceptance",
}

req = urllib.request.Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=15.0) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        print("=== PROMPT HOP TEST RESULT ===")
        print(f"Status Code: {res.get('status_code')}")
        print(f"Duration:    {res.get('duration_ms')} ms")
        print(f"Error:       {res.get('error')}")
        print(f"Response:    {json.dumps(res.get('response'), indent=2)}")
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
