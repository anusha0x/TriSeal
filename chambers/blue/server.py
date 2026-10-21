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
