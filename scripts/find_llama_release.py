import urllib.request
import json

req = urllib.request.Request("https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=10", headers={"User-Agent": "TriSeal-Builder"})
try:
    with urllib.request.urlopen(req) as resp:
        releases = json.loads(resp.read().decode())
        for r in releases:
            tag = r.get("tag_name")
            assets = [a["browser_download_url"] for a in r.get("assets", []) if "ubuntu" in a["name"] or "linux" in a["name"] or "bin" in a["name"]]
            if assets:
                print(f"Tag: {tag}")
                for a in assets:
                    print(f"  {a}")
                break
except Exception as e:
    print(f"Error: {e}")
