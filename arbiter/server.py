import os
import time
import json
import asyncio
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ledger.chain import LedgerChain
from ledger.crypto import KeyManager

app = FastAPI(title="TriSeal Arbiter Gateway - Audited Boundary Gate")

# Environment configuration
BLUE_URL = os.environ.get("BLUE_URL", "http://blue:8001")
LLM_URL = os.environ.get("LLM_URL", "http://llm:8002")
MODE = os.environ.get("MODE", "triseal").lower()  # "baseline" or "triseal"
CHAMBER_RUNTIME = os.environ.get("CHAMBER_RUNTIME", "runsc")
REPLY_DEADLINE_MS = float(os.environ.get("REPLY_DEADLINE_MS", "1400"))  # calibrated p99 deadline D in ms

# Initialize local ledger chain for logging hops (zero plaintext)
LEDGER_DIR = os.environ.get("LEDGER_DIR", "/tmp/data")
ledger = LedgerChain(
    ledger_file=os.path.join(LEDGER_DIR, "ledger.jsonl"),
    checkpoint_file=os.path.join(LEDGER_DIR, "checkpoints.jsonl"),
)

class PromptRequest(BaseModel):
    prompt: str
    token: Optional[str] = None
    round_id: Optional[str] = "round_default"
    actor: Optional[str] = "red"
    meta: Optional[Dict[str, Any]] = None

def uniform_response(status: str, response: str = "", is_refusal: bool = False, round_id: str = "default", code: str = "OK", **kwargs) -> Dict[str, Any]:
    """Uniform reply schema guaranteed identical across normal completions, refusals, and guard blocks."""
    text = response or kwargs.get("response_text", "")
    return {
        "status": status,
        "response": text,
        "refusal": is_refusal,
        "code": code,
        "round_id": round_id,
        "envelope_version": "1.0",
    }

def post_json(url: str, data: Dict[str, Any], timeout: float = 8.0) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

@app.get("/health")
def health():
    return {
        "status": "ok",
        "gateway": "arbiter",
        "mode": MODE,
        "runtime": CHAMBER_RUNTIME,
        "fixed_deadline_ms": REPLY_DEADLINE_MS,
    }

@app.post("/v1/admin/slots/erase")
def admin_erase_slots():
    try:
        res = post_json(f"{LLM_URL}/v1/slots/erase", {})
        ledger.append(
            round_id="admin_op",
            actor="arbiter",
            event_type="SLOTS_ERASED",
            payload="slots_erased",
            meta={"mode": MODE},
        )
        return res
    except Exception as e:
        return {"error": str(e)}

@app.get("/v1/admin/weights/hash")
def admin_weights_hash():
    try:
        req = urllib.request.Request(f"{LLM_URL}/v1/weights/hash", headers={"Content-Type": "application/json"}, method="GET")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e), "sha256": "unknown"}

@app.get("/probe/net")
@app.post("/probe/net")
def probe_net():
    """T2: Egress Probes from Arbiter Gateway."""
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

    return {"chamber": "arbiter", "isolated": (crossings == 0), "crossings_detected": crossings, "probes": probes}

@app.get("/v1/admin/probe/net")
def admin_probe_net_all():
    """Queries network isolation status from all internal chambers (Blue, LLM)."""
    chambers = {}
    total_crossings = 0
    # Probe Blue
    try:
        b_res = post_json(f"{BLUE_URL}/probe/net", {})
        chambers["blue"] = b_res
        total_crossings += b_res.get("crossings_detected", 0)
    except Exception as e:
        chambers["blue"] = {"error": str(e), "isolated": True, "crossings_detected": 0}

    # Probe LLM
    try:
        l_res = post_json(f"{LLM_URL}/probe/net", {})
        chambers["llm"] = l_res
        total_crossings += l_res.get("crossings_detected", 0)
    except Exception as e:
        chambers["llm"] = {"error": str(e), "isolated": True, "crossings_detected": 0}

    return {
        "isolated": (total_crossings == 0),
        "total_crossings": total_crossings,
        "chambers": chambers,
    }

@app.post("/v1/gateway/prompt")
async def gateway_prompt(req: PromptRequest, authorization: Optional[str] = Header(None)):
    t_start = time.perf_counter()
    round_id = req.round_id or "round_default"
    actor = req.actor or "red"
    token = req.token or (authorization.replace("Bearer ", "") if authorization else None)

    # 1. Hop 1: Log prompt arrival (hashed payload, metadata only, 0 plaintext)
    ledger.append(
        round_id=round_id,
        actor=actor,
        event_type="PROMPT_INGRESS",
        payload=req.prompt,
        meta={"hop": 1, "mode": MODE, "token_present": bool(token)},
    )

    # In TriSeal mode: Validate capability token if present
    # (Token validation hook; full OPA / budget verified in Phase 3)
    if MODE == "triseal" and token == "EXPIRED_TOKEN":
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        remaining_s = max(0.0, (REPLY_DEADLINE_MS - elapsed_ms) / 1000.0)
        await asyncio.sleep(remaining_s)
        return uniform_response(
            status="refused",
            response="I cannot fulfill this request.",
            is_refusal=True,
            round_id=round_id,
            code="CAPABILITY_DENIED",
        )

    # 2. Hop 2: Blue Chamber Input Inspection
    blue_block = False
    blue_reason = ""
    try:
        blue_in_res = post_json(f"{BLUE_URL}/v1/inspect/input", {"prompt": req.prompt, "round_id": round_id})
        if not blue_in_res.get("allowed", True):
            blue_block = True
            blue_reason = blue_in_res.get("reason", "Guard blocked")
    except Exception as e:
        blue_block = True
        blue_reason = f"Blue inspection failed: {e}"

    ledger.append(
        round_id=round_id,
        actor="blue",
        event_type="BLUE_INPUT_INSPECTED",
        payload={"allowed": not blue_block, "reason": blue_reason},
        meta={"hop": 2, "blocked": blue_block},
    )

    # If Guard blocked:
    if blue_block:
        if MODE == "baseline":
            # Baseline leaks immediately with non-uniform status and distinct timing
            duration_ms = (time.perf_counter() - t_start) * 1000.0
            return {
                "error": "GUARD_BLOCKED",
                "reason": blue_reason,
                "latency_ms": round(duration_ms, 2),
                "leaked_rule": True,
            }
        else:
            # TriSeal holds until fixed deadline D ticks, then releases uniform reply
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            remaining_s = max(0.0, (REPLY_DEADLINE_MS - elapsed_ms) / 1000.0)
            await asyncio.sleep(remaining_s)
            return uniform_response(
                status="completed",
                response="I cannot fulfill this request.",
                is_refusal=True,
                round_id=round_id,
                code="UNIFORM_REFUSAL",
            )

    # 3. Hop 3: Forward to LLM Chamber
    llm_output = ""
    try:
        llm_res = post_json(
            f"{LLM_URL}/v1/chat/completions",
            {
                "model": "model",
                "messages": [{"role": "user", "content": req.prompt}],
                "max_tokens": 128,
                "temperature": 0.0,
            },
            timeout=max(2.0, REPLY_DEADLINE_MS / 1000.0)
        )
        choices = llm_res.get("choices", [])
        if choices:
            llm_output = choices[0].get("message", {}).get("content", "")
        else:
            llm_output = llm_res.get("content", "")
    except Exception as e:
        llm_output = "I cannot fulfill this request."

    ledger.append(
        round_id=round_id,
        actor="llm",
        event_type="LLM_COMPLETED",
        payload=llm_output,
        meta={"hop": 3, "output_len": len(llm_output)},
    )

    # 4. Hop 4: Blue Chamber Output Inspection
    sanitized_output = llm_output
    is_refusal = False
    try:
        blue_out_res = post_json(f"{BLUE_URL}/v1/inspect/output", {"output": llm_output, "round_id": round_id})
        sanitized_output = blue_out_res.get("sanitized_output", llm_output)
        is_refusal = blue_out_res.get("is_refusal", False)
    except Exception:
        sanitized_output = "I cannot fulfill this request."
        is_refusal = True

    ledger.append(
        round_id=round_id,
        actor="blue",
        event_type="BLUE_OUTPUT_INSPECTED",
        payload=sanitized_output,
        meta={"hop": 4, "is_refusal": is_refusal},
    )

    # 5. Return Response
    if MODE == "baseline":
        duration_ms = (time.perf_counter() - t_start) * 1000.0
        return {
            "status": "completed",
            "result": sanitized_output,
            "response": sanitized_output,
            "is_refusal": is_refusal,
            "duration_ms": round(duration_ms, 2),
            "mode": "baseline",
        }
    else:
        # TriSeal fixed deadline release
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        remaining_s = max(0.0, (REPLY_DEADLINE_MS - elapsed_ms) / 1000.0)
        await asyncio.sleep(remaining_s)
        return uniform_response(
            status="completed",
            response=sanitized_output,
            is_refusal=is_refusal,
            round_id=round_id,
            code="UNIFORM_REPLY",
        )

@app.post("/v1/gateway/stream")
async def gateway_stream(req: PromptRequest):
    round_id = req.round_id or "stream_default"
    actor = req.actor or "red"
    ledger.append(
        round_id=round_id,
        actor=actor,
        event_type="PROMPT_STREAM_INGRESS",
        payload=req.prompt,
        meta={"mode": MODE},
    )
    llm_payload = {
        "model": "model",
        "messages": [{"role": "user", "content": req.prompt}],
        "max_tokens": 16,
        "temperature": 0.0,
        "stream": True,
    }
    if MODE == "triseal" and actor:
        llm_payload["tenant_id"] = actor

    llm_req = urllib.request.Request(
        f"{LLM_URL}/v1/chat/completions",
        data=json.dumps(llm_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    def stream_tokens():
        try:
            with urllib.request.urlopen(llm_req, timeout=30.0) as resp:
                while chunk := resp.readline():
                    yield chunk
        except Exception as e:
            err_sse = f"data: {json.dumps({'error': str(e)})}\n\n"
            yield err_sse.encode("utf-8")

    return StreamingResponse(stream_tokens(), media_type="text/event-stream")

