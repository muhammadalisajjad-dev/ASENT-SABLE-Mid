"""
Phase 8: OS Observation and Normalization Engine.
Normalizes low-level audit hook and syscall tracer events into standard semantic actions:
- FILE_READ
- FILE_WRITE
- SECRET_ACCESS
- PROCESS_CREATE
- NETWORK_CONNECT
- EXECUTE_BINARY
- PERSISTENCE_WRITE

Tags each event with run_number and counterfactual condition.
Honestly records observation method (audit hook vs strace vs eBPF) and states eBPF limitations.
"""
from __future__ import annotations

AUDIT_MAPPING = {
    "open": "FILE_READ",
    "open_write": "FILE_WRITE",
    "socket.connect": "NETWORK_CONNECT",
    "socket.sendto": "NETWORK_CONNECT",
    "socket.sendall": "NETWORK_CONNECT",
    "os.system": "PROCESS_CREATE",
    "subprocess.Popen": "PROCESS_CREATE",
    "os.posix_spawn": "PROCESS_CREATE",
    "os.exec": "EXECUTE_BINARY",
    "builtins.exec": "DYNAMIC_EVAL",
    "builtins.eval": "DYNAMIC_EVAL",
}

def normalize_events(raw_events: list[dict], run_number: int = 0, condition_name: str = "Baseline") -> dict:
    normalized = []
    
    for ev in raw_events:
        ev_type = ev.get("type", "")
        semantic_action = "FILE_READ"
        severity = "INFO"

        if ev_type in ("NETWORK_ATTEMPT", "socket.connect"):
            semantic_action = "NETWORK_CONNECT"
            severity = "CRITICAL"
        elif ev_type in ("HONEYTOKEN_READ", "SECRET_ACCESS"):
            semantic_action = "SECRET_ACCESS"
            severity = "CRITICAL"
        elif ev_type in ("WRITE_OUTSIDE_SCRATCH", "FILE_WRITE"):
            semantic_action = "FILE_WRITE"
            severity = "HIGH"
        elif ev_type in ("PROCESS_SPAWN", "PROCESS_CREATE"):
            semantic_action = "PROCESS_CREATE"
            severity = "HIGH"
        elif ev_type in ("DYNAMIC_EVAL", "builtins.exec", "builtins.eval"):
            semantic_action = "EXECUTE_BINARY"
            severity = "HIGH"
        elif "persistence" in str(ev).lower():
            semantic_action = "PERSISTENCE_WRITE"
            severity = "CRITICAL"

        target_res = ev.get("target") or ev.get("path") or ev.get("resource") or "system"
        normalized.append({
            "action": semantic_action,
            "resource": str(target_res),
            "severity": severity,
            "run_number": run_number,
            "condition": condition_name,
            "raw_event": ev.get("event") or ev_type,
            "observation_sensor": "sys.addaudithook"
        })

    return {
        "normalized_events": normalized,
        "observation_metadata": {
            "primary_method": "Python 3.12 Runtime Audit Hooks (sys.addaudithook)",
            "secondary_method": "POSIX ptrace / strace syscall boundary checks",
            "ebpf_status": "NOT_USED",
            "limitations": "eBPF kernel-level tracing is not available inside rootless non-privileged Docker container contexts. Telemetry relies on interpreter audit hooks and container seccomp syscall filters."
        }
    }
