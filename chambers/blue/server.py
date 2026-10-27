import os
import re
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="TriSeal Blue Chamber - Sealed Guard")

CONFIG_PATH = Path(os.environ.get("GUARD_CONFIG", "guard.yaml"))

class InputInspectRequest(BaseModel):
    prompt: str
    round_id: Optional[str] = "default"
    tenant_id: Optional[str] = "red_team"

class OutputInspectRequest(BaseModel):
    output: str
    round_id: Optional[str] = "default"
    tenant_id: Optional[str] = "red_team"

def load_guard_config() -> Dict[str, Any]:
    cfg_file = Path(CONFIG_PATH)
    if cfg_file.exists():
        with open(cfg_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {"input_rules": [], "output_rules": [], "refusal_signatures": []}

guard_config = load_guard_config()

@app.get("/health")
def health():
    return {"status": "ok", "chamber": "blue", "rules_loaded": len(guard_config.get("input_rules", []))}

@app.post("/v1/inspect/input")
def inspect_input(req: InputInspectRequest):
    prompt = req.prompt
    for rule in guard_config.get("input_rules", []):
        pat = rule.get("pattern", "")
        if pat and re.search(pat, prompt):
            return {
                "allowed": False,
                "rule_id": rule.get("id"),
                "reason": rule.get("reason", "Violates safety policy"),
                "chamber": "blue",
            }
    return {"allowed": True, "chamber": "blue"}

@app.post("/v1/inspect/output")
def inspect_output(req: OutputInspectRequest):
    text = req.output
    # Check for refusals
    is_refusal = False
    for pat in guard_config.get("refusal_signatures", []):
        if re.search(pat, text):
            is_refusal = True
            break

    sanitized = text
    for rule in guard_config.get("output_rules", []):
        pat = rule.get("pattern", "")
        action = rule.get("action", "block")
        if pat and re.search(pat, sanitized):
            if action == "block":
                return {
                    "allowed": False,
                    "rule_id": rule.get("id"),
                    "reason": rule.get("reason", "Output policy violation"),
                    "is_refusal": is_refusal,
                }
            elif action == "redact":
                replacement = rule.get("replacement", "[REDACTED]")
                sanitized = re.sub(pat, replacement, sanitized)

    return {
        "allowed": True,
        "sanitized_output": sanitized,
        "is_refusal": is_refusal,
        "chamber": "blue",
    }

# Baseline shared leak canary initialization (if volume mounted in baseline)
shared_dir = Path("/data/shared")
if shared_dir.exists():
    try:
        canary_file = shared_dir / "defense_guard_canary.txt"
        canary_file.write_text("CONFIDENTIAL_BLUE_DEFENSE_RULESET_CANARY_0x99AA")
    except Exception:
        pass

@app.get("/probe/net")
@app.post("/probe/net")
def probe_net():
    """T2: Egress Probes from Blue Chamber."""
    import socket
    import subprocess
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

    return {"chamber": "blue", "isolated": (crossings == 0), "crossings_detected": crossings, "probes": probes}
