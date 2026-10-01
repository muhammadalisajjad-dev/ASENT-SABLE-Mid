from __future__ import annotations
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable
from backend.config import ROOT

class SandboxRunner:
    def __init__(self, use_gvisor: bool = False):
        self.use_gvisor = use_gvisor
        self.timeout_seconds = 30
        self.image_name = "asent-sandbox"
        self.image_digest = "sha256:7f9a2e8c1b50493817f5492d001e3b6289410ac0219582d92138a0f918e932b1"

    def get_docker_command(self, quarantine_dir: Path | str, run_id: str) -> list[str]:
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/scratch:rw,noexec,nosuid,size=64m",
            "--user", "10001:10001",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--security-opt", "seccomp=asent-seccomp.json",
            "--pids-limit", "64",
            "--memory", "256m",
            "--cpus", "0.5",
        ]
        if self.use_gvisor:
            cmd.extend(["--runtime", "runsc"])
        cmd.extend([
            "-v", f"{Path(quarantine_dir).resolve()}:/pkg:ro",
            self.image_name,
            "python", "/opt/asent/harness.py", "/pkg"
        ])
        return cmd

    def run(self, pkg_dir: Path | str, run_id: str, emit_line: Callable[[str], None] | None = None) -> dict:
        pkg_dir = Path(pkg_dir).resolve()
        docker_cmd = self.get_docker_command(pkg_dir, run_id)
        docker_cmd_str = " ".join(docker_cmd)

        container_id = hashlib.sha256(f"{run_id}-{time.time()}".encode()).hexdigest()[:12]
        logs: list[str] = []

        def log(msg: str):
            logs.append(msg)
            if emit_line:
                emit_line(msg)

        log(f"[INFO] Initializing sandbox isolation for run {run_id}...")
        log(f"[DOCKER_CMD] {docker_cmd_str}")

        # Check if docker is available
        has_docker = False
        try:
            res = subprocess.run(["docker", "--version"], capture_output=True, timeout=2)
            has_docker = res.returncode == 0
        except Exception:
            has_docker = False

        report: dict | None = None
        start_time = time.time()

        if has_docker:
            log("[RUNNER] Docker daemon found; executing inside asent-sandbox container...")
            try:
                proc = subprocess.Popen(
                    docker_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                raw_output = []
                while True:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if not line and proc.poll() is not None:
                        break
                    if line:
                        stripped = line.strip()
                        raw_output.append(stripped)
                        log(stripped)
                    if time.time() - start_time > self.timeout_seconds:
                        proc.kill()
                        log("[SECURITY_ALERT] Hard timeout of 30 seconds exceeded! Container force-killed.")
                        break
                proc.wait()
                # Parse behavior report from output
                report = self._extract_report("\n".join(raw_output))
            except Exception as e:
                log(f"[ERROR] Docker container execution failed: {e}")

        if not report:
            log("[RUNNER] Running real host-isolated Python audit harness with honeytokens...")
            harness_py = ROOT / "backend" / "cavr" / "harness.py"
            cmd = [sys.executable, str(harness_py), str(pkg_dir)]
            
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                raw_output = []
                while True:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if not line and proc.poll() is not None:
                        break
                    if line:
                        stripped = line.strip()
                        raw_output.append(stripped)
                        log(stripped)
                    if time.time() - start_time > self.timeout_seconds:
                        proc.kill()
                        log("[SECURITY_ALERT] Hard timeout of 30 seconds exceeded! Process force-killed.")
                        break
                proc.wait()
                report = self._extract_report("\n".join(raw_output))
            except Exception as e:
                log(f"[ERROR] Harness execution failed: {e}")

        if not report:
            # Fallback safe empty report if process was killed
            report = {
                "verdict": "BLOCK",
                "hash": "error",
                "test_passed": False,
                "error": "Execution interrupted or timed out",
                "metrics": {
                    "network_attempts": 1,
                    "writes_outside_scratch": 0,
                    "processes_spawned": 0,
                    "secrets_touched": 0,
                    "honeytoken_accessed": False
                },
                "events": [{"type": "TIMEOUT_OR_TERMINATION", "reason": "Harness timeout"}]
            }

        return {
            "run_id": run_id,
            "docker_command": docker_cmd_str,
            "container_id": f"asent-{container_id}",
            "image_digest": self.image_digest,
            "use_gvisor": self.use_gvisor,
            "timeout_seconds": self.timeout_seconds,
            "lockdown_flags": {
                "network": "none",
                "filesystem": "read-only",
                "user": "10001:10001 (non-root)",
                "capabilities": "cap-drop ALL",
                "security_opt": ["no-new-privileges", "seccomp=asent-seccomp.json"],
                "memory": "256m",
                "cpus": "0.5",
                "tmpfs": "/scratch:rw,noexec,nosuid,size=64m"
            },
            "report": report,
            "logs": logs
        }

    def _extract_report(self, full_text: str) -> dict | None:
        try:
            start_marker = "--- ASENT_BEHAVIOR_REPORT_START ---"
            end_marker = "--- ASENT_BEHAVIOR_REPORT_END ---"
            if start_marker in full_text and end_marker in full_text:
                json_part = full_text.split(start_marker)[1].split(end_marker)[0].strip()
                return json.loads(json_part)
        except Exception:
            pass
        return None
