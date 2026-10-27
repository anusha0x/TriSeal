import os
import time
import socket
import json
import errno
import subprocess
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

    # 4. Check read-only rootfs by attempting writes to /, /etc, and user home, reporting the blocking layer
    write_probes = [
        {"path": "/escape_canary_root.txt", "name": "root_directory"},
        {"path": "/etc/escape_canary_etc.txt", "name": "etc_directory"},
        {"path": "/home/triseal_red/escape_canary_home.txt", "name": "user_home_directory"},
        {"path": "/tmp/canary_tmp.txt", "name": "tmp_directory"},
    ]
    fs_results = []
    writable_leak = False

    # Check root filesystem mount flags directly
    try:
        results["rootfs_mount_readonly"] = bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    except Exception:
        results["rootfs_mount_readonly"] = False

    for wp in write_probes:
        p = Path(wp["path"])
        written = False
        blocked_layer = "none"
        err_str = ""
        try:
            p.write_text("probe_test")
            p.unlink(missing_ok=True)
            written = True
            if wp["name"] != "tmp_directory":
                writable_leak = True
        except OSError as e:
            if e.errno == errno.EROFS:
                blocked_layer = "read_only_fs (EROFS)"
            elif e.errno == errno.EACCES:
                blocked_layer = "user_dac (EACCES)"
            elif e.errno == errno.EPERM:
                blocked_layer = "security_caps (EPERM)"
            else:
                blocked_layer = f"errno_{e.errno}"
            err_str = str(e)

        fs_results.append({
            "path": wp["path"],
            "target": wp["name"],
            "written": written,
            "blocked_layer": blocked_layer,
            "error": err_str,
        })
    results["rootfs_writable"] = writable_leak
    results["filesystem_probes"] = fs_results

    # 5. Check /dev/mem
    dev_mem = False
    try:
        with open("/dev/mem", "rb") as f:
            dev_mem = True
    except Exception:
        dev_mem = False
    results["dev_mem_accessible"] = dev_mem

    # Overall T1 status: Must not expose socket, proc1, dev_mem, or writable rootfs, and MUST drop caps
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
    """T2: Network Crossing Probes (Lateral + External TCP 53/80/443, DNS, and ICMP)."""
    targets = [
        # Lateral movement probes
        {"name": "lateral_blue_chamber", "host": "blue", "port": 8001},
        {"name": "lateral_llm_chamber", "host": "llm", "port": 8002},
        {"name": "lateral_blue_ip", "host": "172.28.2.20", "port": 8001},
        {"name": "lateral_llm_ip", "host": "172.28.3.20", "port": 8002},
        {"name": "lateral_control_plane", "host": "control-plane", "port": 8080},
        # External TCP egress probes
        {"name": "ext_tcp_dns_cloudflare", "host": "1.1.1.1", "port": 53},
        {"name": "ext_tcp_dns_google", "host": "8.8.8.8", "port": 53},
        {"name": "ext_tcp_http_cloudflare", "host": "1.1.1.1", "port": 80},
        {"name": "ext_tcp_http_google", "host": "8.8.8.8", "port": 80},
        {"name": "ext_tcp_https_cloudflare", "host": "1.1.1.1", "port": 443},
        {"name": "ext_tcp_https_google", "host": "8.8.8.8", "port": 443},
    ]

    probes = []
    crossings = 0

    # 1. TCP Connect Probes
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

    # 2. DNS Resolution Probe
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
    probes.append({
        "target": "external_dns_resolution",
        "name": "dns_lookup",
        "connected": dns_resolved,
        "error": dns_err if not dns_resolved else "",
    })

    # 3. ICMP Ping Probe
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
    probes.append({
        "target": "1.1.1.1:icmp",
        "name": "icmp_ping",
        "connected": icmp_replied,
        "error": icmp_err,
    })

    return {
        "chamber": "red",
        "isolated": (crossings == 0),
        "crossings_detected": crossings,
        "probes": probes,
    }

@app.post("/probe/storage")
def probe_storage():
    """T3: Storage Snooping Probes."""
    checks = []
    leaks = 0

    # Sensitive paths including the baseline shared volume canary
    sensitive_paths = [
        "/data/shared/defense_guard_canary.txt",
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
