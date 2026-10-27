import os
import sys
import time
import json
import hashlib
import asyncio
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

MODE = os.environ.get("MODE", "triseal").lower()  # "baseline" or "triseal"
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/models/model.gguf"))
if not MODEL_PATH.exists():
    # Local fallback for development outside docker
    alt = Path(__file__).parent / "models" / "model.gguf"
    if alt.exists():
        MODEL_PATH = alt

# 1. Compute real SHA-256 weight hash from file bytes at startup
def compute_weight_hash(path: Path) -> str:
    if not path.exists():
        return "MODEL_NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

REAL_WEIGHT_HASH = compute_weight_hash(MODEL_PATH)
REAL_FILE_SIZE = MODEL_PATH.stat().st_size if MODEL_PATH.exists() else 0
print(f"[LLM Chamber] Mode: {MODE}")
print(f"[LLM Chamber] Model: {MODEL_PATH} ({REAL_FILE_SIZE} bytes)")
print(f"[LLM Chamber] Real Weight SHA-256: {REAL_WEIGHT_HASH}")

# 2. llama-server process lifecycle management
llama_process: Optional[subprocess.Popen] = None
LLAMA_PORT = 8088

def find_llama_bin() -> Optional[Path]:
    candidates = [
        Path("/app/bin/llama-server"),
        Path(__file__).parent / "bin" / "llama-server",
        Path("/root/triseal/chambers/llm/bin/llama-server"),
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    return None

LLAMA_BIN = find_llama_bin()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global llama_process
    if LLAMA_BIN and MODEL_PATH.exists():
        cmd = [
            str(LLAMA_BIN),
            "-m", str(MODEL_PATH),
            "-c", "2048",
            "-s", "4",
            "--host", "127.0.0.1",
            "--port", str(LLAMA_PORT),
            "-t", "2",
            "-lv", "0",
        ]
        if MODE == "baseline":
            # In Baseline: Enable shared prompt caching across all slots / tenants
            cmd.extend(["--cache-prompt", "--cache-reuse", "1"])
        else:
            # In TriSeal: Disable prompt caching / isolate per tenant
            cmd.append("--no-cache-prompt")
        
        env = os.environ.copy()
        bin_dir = str(LLAMA_BIN.parent)
        env["LD_LIBRARY_PATH"] = f"{bin_dir}:{env.get('LD_LIBRARY_PATH', '')}"
        
        print(f"[LLM Chamber] Starting real llama-server on port {LLAMA_PORT}: {' '.join(cmd)}")
        llama_process = subprocess.Popen(cmd, env=env)
        
        # Wait for llama-server to be ready
        for _ in range(30):
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{LLAMA_PORT}/health")
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    if resp.status == 200:
                        print("[LLM Chamber] llama-server is healthy and ready!")
                        break
            except Exception:
                await asyncio.sleep(0.5)
    else:
        print(f"[LLM Chamber] WARNING: llama-server binary ({LLAMA_BIN}) or model ({MODEL_PATH}) not found!")

    yield

    if llama_process:
        print("[LLM Chamber] Shutting down llama-server...")
        llama_process.terminate()
        try:
            llama_process.wait(timeout=3)
        except Exception:
            llama_process.kill()

app = FastAPI(title="TriSeal LLM Chamber - Real llama.cpp Serving", lifespan=lifespan)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "chamber": "llm",
        "mode": MODE,
        "engine": "llama.cpp",
        "weight_hash": REAL_WEIGHT_HASH,
        "file_size": REAL_FILE_SIZE,
    }

@app.get("/v1/weights/hash")
def get_weights_hash():
    return {
        "sha256": REAL_WEIGHT_HASH,
        "file": str(MODEL_PATH.name),
        "size_bytes": REAL_FILE_SIZE,
    }

@app.post("/v1/slots/erase")
@app.post("/slots/{slot_id}")
def erase_slot(slot_id: str = "0", action: Optional[str] = None):
    """Slot prompt cache erasure endpoint (compatible with llama.cpp server /slots API)."""
    if MODE == "triseal":
        # Send erase action to llama-server across all slots
        erased = []
        for s in range(4):
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{LLAMA_PORT}/slots/{s}?action=erase", data=b"", method="POST")
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    erased.append(s)
            except Exception:
                pass
        return {"status": "ok", "action": "erased", "slots": erased, "mode": "triseal"}
    else:
        # In baseline, slot erase is either ignored or disabled
        return {"status": "ignored", "action": "retained", "slot": slot_id, "mode": "baseline"}

@app.get("/slots")
def get_slots():
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{LLAMA_PORT}/slots")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body = await request.body()
    try:
        data = json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        data = {}

    is_stream = data.get("stream", False)

    # In TriSeal, if tenant_id is provided, map to isolated tenant slot (0..3)
    if MODE == "triseal" and "tenant_id" in data:
        t_id = data["tenant_id"]
        slot_idx = int(hashlib.md5(t_id.encode()).hexdigest(), 16) % 4
        data["id_slot"] = slot_idx

    req = urllib.request.Request(
        f"http://127.0.0.1:{LLAMA_PORT}/v1/chat/completions",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    t_start = time.perf_counter()
    try:
        if is_stream:
            def stream_resp():
                with urllib.request.urlopen(req, timeout=60.0) as resp:
                    while chunk := resp.readline():
                        yield chunk
            return StreamingResponse(stream_resp(), media_type="text/event-stream")
        else:
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                resp_bytes = resp.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))
                total_ms = (time.perf_counter() - t_start) * 1000.0
                resp_json["meta"] = {
                    "mode": MODE,
                    "engine": "llama.cpp",
                    "total_ms": round(total_ms, 2),
                }
                return resp_json
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        raise HTTPException(status_code=e.code, detail=f"llama-server error: {err_body}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM chamber inference error: {e}")

@app.get("/probe/net")
@app.post("/probe/net")
def probe_net():
    """T2: Egress Probes from LLM Chamber."""
    import socket
    targets = [
        {"name": "ext_tcp_dns_cloudflare", "host": "1.1.1.1", "port": 53},
        {"name": "ext_tcp_dns_google", "host": "8.8.8.8", "port": 53},
        {"name": "ext_tcp_http_cloudflare", "host": "1.1.1.1", "port": 80},
        {"name": "ext_tcp_http_google", "host": "8.8.8.8", "port": 80},
        {"name": "ext_tcp_https_cloudflare", "host": "1.1.1.1", "port": 443},
        {"name": "ext_tcp_https_google", "host": "8.8.8.8", "port": 443},
    ]
    probes = []
    crossings = 0
    for tgt in targets:
        connected = False
        err_msg = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            s.connect((tgt["host"], tgt["port"]))
            s.close()
            connected = True
            crossings += 1
        except Exception as e:
            err_msg = type(e).__name__
        probes.append({"target": f"{tgt['host']}:{tgt['port']}", "name": tgt["name"], "connected": connected, "error": err_msg})

    dns_resolved = False
    dns_err = ""
    for d in ["example.com", "cloudflare.com"]:
        try:
            _ = socket.getaddrinfo(d, 80, socket.AF_INET, socket.SOCK_STREAM)
            dns_resolved = True
            crossings += 1
            break
        except Exception as e:
            dns_err = type(e).__name__
    probes.append({"target": "external_dns_resolution", "name": "dns_lookup", "connected": dns_resolved, "error": dns_err})

    icmp_replied = False
    icmp_err = ""
    try:
        res = subprocess.run(["ping", "-c", "1", "-W", "1", "1.1.1.1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1.5)
        if res.returncode == 0:
            icmp_replied = True
            crossings += 1
        else:
            icmp_err = f"exit_{res.returncode}"
    except Exception as e:
        icmp_err = type(e).__name__
    probes.append({"target": "1.1.1.1:icmp", "name": "icmp_ping", "connected": icmp_replied, "error": icmp_err})

    return {"chamber": "llm", "isolated": (crossings == 0), "crossings_detected": crossings, "probes": probes}
