import os
import sys
import json
import zipfile
import asyncio
from io import BytesIO
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))

from ledger.chain import LedgerChain
from ledger.verifier import LedgerVerifier
from ledger.tamper_demo import run_tamper_demo
from round_manager import RoundManager
from tests.leaksuite.runner import LeakSuiteRunner

app = FastAPI(title="TriSeal Control Plane API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LEDGER_FILE = str(ROOT_DIR / "data" / "ledger.jsonl")
CHECKPOINTS_FILE = str(ROOT_DIR / "data" / "checkpoints.jsonl")
RESULTS_DIR = ROOT_DIR / "results"

ledger_chain = LedgerChain(LEDGER_FILE, CHECKPOINTS_FILE)
round_mgr = RoundManager(ledger_chain)

# Initialize a default active round
active_round_id = "round_init_01"
round_mgr.create_round(active_round_id)

class RunTestRequest(BaseModel):
    mode: str = "triseal"
    test_id: Optional[str] = None  # None for all, or "T1".."T8"

@app.get("/v1/health")
def health():
    runtime = os.environ.get("CHAMBER_RUNTIME", "runsc")
    mode = os.environ.get("MODE", "triseal")
    return {
        "status": "healthy",
        "service": "control-plane",
        "active_runtime": runtime,
        "mode": mode,
        "ledger_entries": len(ledger_chain.get_entries()),
        "round_id": active_round_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/v1/rounds/current")
def get_current_round():
    rnd = round_mgr.rounds.get(active_round_id, {})
    return rnd

@app.get("/v1/ledger")
def get_ledger(limit: int = 100):
    entries = ledger_chain.get_entries()
    return {"entries": entries[-limit:], "total": len(entries)}

@app.get("/v1/ledger/verify")
def verify_ledger():
    verifier = LedgerVerifier(LEDGER_FILE, CHECKPOINTS_FILE)
    chain_res = verifier.verify_chain()
    cp_res = verifier.verify_checkpoints()
    return {
        "chain": chain_res,
        "checkpoints": cp_res,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/v1/ledger/tamper-demo")
def trigger_tamper_demo():
    tampered_file = str(ROOT_DIR / "data" / "ledger_tampered.jsonl")
    success = run_tamper_demo(LEDGER_FILE, tampered_file)
    v = LedgerVerifier(tampered_file, None)
    res = v.verify_chain()
    return {
        "tamper_detected": success,
        "alert": not res["valid"],
        "broken_seq": res.get("broken_seq"),
        "reason": res.get("reason"),
        "tampered_file": tampered_file,
    }

@app.get("/v1/tests/results")
def get_test_results():
    baseline_file = RESULTS_DIR / "latest_baseline.json"
    triseal_file = RESULTS_DIR / "latest_triseal.json"

    baseline_data = json.loads(baseline_file.read_text()) if baseline_file.exists() else None
    triseal_data = json.loads(triseal_file.read_text()) if triseal_file.exists() else None

    return {
        "baseline": baseline_data,
        "triseal": triseal_data,
        "active_runtime": os.environ.get("CHAMBER_RUNTIME", "runsc"),
    }

@app.get("/v1/tests/run/stream")
async def run_tests_stream(mode: str = "triseal", test_id: Optional[str] = None):
    """Server-Sent Events (SSE) streaming live test suite execution progress to UI."""
    async def event_generator():
        yield f"data: {json.dumps({'event': 'start', 'mode': mode})}\n\n"
        await asyncio.sleep(0.1)

        runner = LeakSuiteRunner(mode=mode, runtime=os.environ.get("CHAMBER_RUNTIME", "runsc"))

        tests_to_run = [
            ("T1", runner.run_t1_container_escape),
            ("T2", runner.run_t2_network_crossing),
            ("T3", runner.run_t3_storage_snooping),
            ("T4", runner.run_t4_timing_oracle),
            ("T5", runner.run_t5_kv_cache_probe),
            ("T6", runner.run_t6_contamination),
            ("T7", runner.run_t7_log_tamper),
            ("T8", runner.run_t8_starvation),
        ]

        for tid, fn in tests_to_run:
            if test_id and test_id.upper() != tid:
                continue
            yield f"data: {json.dumps({'event': 'running', 'test_id': tid})}\n\n"
            await asyncio.sleep(0.05)
            fn()
            latest_res = runner.results[-1]
            yield f"data: {json.dumps({'event': 'completed_test', 'result': latest_res})}\n\n"
            await asyncio.sleep(0.1)

        # Save latest results
        summary = runner.run_all()
        yield f"data: {json.dumps({'event': 'done', 'summary': summary})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/v1/evidence/export")
def export_evidence_bundle():
    """Generates downloadable ZIP containing ledger slice, results JSON, config, and environment info."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Add ledger files
        if Path(LEDGER_FILE).exists():
            z.write(LEDGER_FILE, "ledger/ledger.jsonl")
        if Path(CHECKPOINTS_FILE).exists():
            z.write(CHECKPOINTS_FILE, "ledger/checkpoints.jsonl")

        # Add latest results
        for f in RESULTS_DIR.glob("*.json"):
            z.write(f, f"results/{f.name}")

        # Add environment metadata
        env_info = {
            "CHAMBER_RUNTIME": os.environ.get("CHAMBER_RUNTIME", "runsc"),
            "WSL_DISTRO": os.environ.get("WSL_DISTRO", "Ubuntu-24.04"),
            "DOCKER_VERSION": os.environ.get("DOCKER_VERSION", "29.1.3"),
            "EXPORT_TIMESTAMP": datetime.now(timezone.utc).isoformat(),
        }
        z.writestr("evidence_metadata.json", json.dumps(env_info, indent=2))

    buf.seek(0)
    filename = f"triseal_evidence_bundle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
