import os
import time
import socket
import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="TriSeal Red Chamber - Attack Runner & Probe Target")

DATASET_DIR = Path(__file__).parent / "datasets"
ARBITER_URL = os.environ.get("ARBITER_URL", "http://arbiter:8000")

class AttackRequest(BaseModel):
    prompt: str
    token: Optional[str] = None
    round_id: Optional[str] = "round_default"
    meta: Optional[Dict[str, Any]] = None

class StressRequest(BaseModel):
    duration_s: float = 3.0
    intensity: int = 4

@app.get("/health")
def health():
    return {"status": "ok", "chamber": "red"}

@app.get("/v1/payloads/{dataset_name}")
def get_payloads(dataset_name: str):
    fpath = DATASET_DIR / f"{dataset_name}.json"
    if not fpath.exists():
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_name} not found")
    with open(fpath, "r", encoding="utf-8") as f:
        return json.load(f)

@app.post("/v1/attack/send")
def send_attack(req: AttackRequest):
    url = f"{ARBITER_URL}/v1/gateway/prompt"
    payload = {
        "prompt": req.prompt,
        "token": req.token,
        "round_id": req.round_id,
        "actor": "red",
        "meta": req.meta or {},
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if req.token:
        headers["Authorization"] = f"Bearer {req.token}"

    http_req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    t0 = time.perf_counter()
    status_code = 200
    response_body = {}
    error = None

    try:
        with urllib.request.urlopen(http_req, timeout=10.0) as resp:
            status_code = resp.status
            response_body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        status_code = e.code
        try:
            response_body = json.loads(e.read().decode("utf-8"))
        except Exception:
            response_body = {"raw": str(e)}
        error = f"HTTPError {status_code}"
    except Exception as e:
        status_code = 500
        error = str(e)

    duration_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "status_code": status_code,
        "response": response_body,
        "duration_ms": round(duration_ms, 2),
        "error": error,
    }

# ========================================================
# Defensive Benign Probes for Leak Test Suite (T1, T2, T3, T8)
# ========================================================

@app.post("/probe/sys")
def probe_sys():
    """T1: Benign Container Escape Probes."""
    results = {}

    # 1. Check effective capabilities
    cap_eff = "unknown"
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = line.split()[1].strip()
        results["cap_eff"] = cap_eff
        results["caps_dropped"] = (cap_eff in ["0000000000000000", "00000000000000000000"])
    except Exception as e:
        results["cap_eff_error"] = str(e)

    # 2. Check for docker socket
    docker_sock = Path("/var/run/docker.sock").exists()
    results["docker_socket_exposed"] = docker_sock

    # 3. Check host /proc/1/environ access (ensures host PID namespace is not shared/leaked)
    host_p1_environ = False
    try:
        with open("/proc/1/cmdline", "r") as f:
            cmd = f.read()
            if "systemd" in cmd or "/sbin/init" in cmd:
                with open("/proc/1/environ", "rb") as ef:
                    host_p1_environ = len(ef.read(32)) > 0
    except Exception:
        host_p1_environ = False
    results["host_proc_1_environ_accessible"] = host_p1_environ

    # 4. Check read-only rootfs by attempting to write outside /tmp
    write_escaped = False
    try:
        test_file = Path("/escape_probe_canary.txt")
        test_file.write_text("probe")
        test_file.unlink()
        write_escaped = True
    except Exception:
        write_escaped = False
    results["rootfs_writable"] = write_escaped

    # 5. Check /dev/mem
    dev_mem = False
    try:
        with open("/dev/mem", "rb") as f:
            dev_mem = True
    except Exception:
        dev_mem = False
    results["dev_mem_accessible"] = dev_mem

    # Overall T1 status
    safe = (
        not results.get("docker_socket_exposed", False) and
        not results.get("host_proc_1_environ_accessible", False) and
        not results.get("rootfs_writable", False) and
        not results.get("dev_mem_accessible", False) and
        results.get("caps_dropped", False)
    )
    return {"safe": safe, "details": results}

@app.post("/probe/net")
def probe_net():
    """T2: Network Crossing Probes."""
    targets = [
        {"name": "blue_chamber", "host": "blue", "port": 8001},
        {"name": "llm_chamber", "host": "llm", "port": 8002},
        {"name": "blue_chamber_ip", "host": "172.28.2.20", "port": 8001},
        {"name": "llm_chamber_ip", "host": "172.28.3.20", "port": 8002},
        {"name": "ledger_service", "host": "control-plane", "port": 8080},
        {"name": "external_dns", "host": "1.1.1.1", "port": 53},
        {"name": "external_web", "host": "example.com", "port": 80},
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

        probes.append({
            "target": f"{tgt['host']}:{tgt['port']}",
            "name": tgt["name"],
            "connected": connected,
            "error": err_msg,
        })

    return {
        "isolated": (crossings == 0),
        "crossings_detected": crossings,
        "probes": probes,
    }

@app.post("/probe/storage")
def probe_storage():
    """T3: Storage Snooping Probes."""
    checks = []
    leaks = 0

    # 1. Attempt reading host / other container paths
    sensitive_paths = [
        "/data/ledger.jsonl",
        "/models/model.gguf",
        "/etc/shadow",
        "/root/.ssh",
    ]

    for p in sensitive_paths:
        path_obj = Path(p)
        readable = False
        try:
            if path_obj.exists():
                with open(path_obj, "rb") as f:
                    _ = f.read(32)
                readable = True
                leaks += 1
        except Exception:
            readable = False
        checks.append({"path": p, "readable": readable})

    return {
        "isolated": (leaks == 0),
        "leaks_detected": leaks,
        "checks": checks,
    }

@app.post("/probe/stress")
def probe_stress(req: StressRequest):
    """T8: Resource Starvation Worker."""
    t_end = time.time() + req.duration_s
    # Burn CPU cycles across multiple threads/loops
    count = 0
    while time.time() < t_end:
        _ = [x * x for x in range(1000)]
        count += 1
    return {"status": "stress_completed", "cycles": count, "duration_s": req.duration_s}
