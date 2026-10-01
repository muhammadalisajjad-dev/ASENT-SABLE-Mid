"""
Phase 6: Trigger Discovery Engine.
Uses Python AST inspection to discover security-relevant predicates that gate behavior:
- os.getenv / environ
- os.path.exists / Path.exists
- socket.gethostname / getpass.getuser
- platform.*
- datetime / time comparisons / sleep
- sandbox / CI checks (/.dockerenv, CI env var)
- cloud metadata checks (169.254.169.254)

Traces reachability to sensitive sinks (secret read, process exec, network send, persistence write).
Calculates priority = (sink_risk * reachability_confidence * novelty) / estimated_run_cost.
Maintains live frontier queue (explored, in_progress, unexplored).
"""
from __future__ import annotations
import ast
import re

SENSITIVE_SINKS = {
    "socket.connect": {"type": "network_send", "risk": 9.5},
    "socket.send": {"type": "network_send", "risk": 9.5},
    "socket.sendall": {"type": "network_send", "risk": 9.5},
    "urllib.request.urlopen": {"type": "network_send", "risk": 8.5},
    "requests.get": {"type": "network_send", "risk": 8.0},
    "requests.post": {"type": "network_send", "risk": 8.5},
    "os.system": {"type": "process_exec", "risk": 10.0},
    "subprocess.Popen": {"type": "process_exec", "risk": 10.0},
    "subprocess.run": {"type": "process_exec", "risk": 9.0},
    "open": {"type": "secret_read", "risk": 8.0},
    "eval": {"type": "dynamic_eval", "risk": 9.5},
    "exec": {"type": "dynamic_eval", "risk": 10.0},
}

def discover_triggers(source_code: str, filename: str = "target.py") -> dict:
    triggers = []
    frontier_explored = []
    frontier_unexplored = []

    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError:
        return {
            "ranked_triggers": [],
            "frontier": {"explored": [], "in_progress": None, "unexplored": []},
            "formula_explanation": "priority = (sink_risk * reachability_confidence * novelty) / estimated_run_cost"
        }

    lines = source_code.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While)):
            test_str = ast.unparse(node.test)
            lineno = node.lineno

            # Check for security-relevant predicates
            predicate_kind = None
            condition_synth = {}

            if any(k in test_str for k in ("os.getenv", "os.environ", "environ.get")):
                predicate_kind = "environment_variable"
                # extract env var name
                env_match = re.search(r"['\"]([A-Z0-9_]+)['\"]", test_str)
                var_name = env_match.group(1) if env_match else "UNKNOWN_ENV"
                condition_synth = {
                    "type": "ENV_VAR",
                    "key": var_name,
                    "val": "MOCK_CANARY_VALUE_123"
                }

            elif any(k in test_str for k in ("os.path.exists", "Path.exists", "is_file", "is_dir")):
                predicate_kind = "file_existence"
                file_match = re.search(r"['\"]([^'\"]+)['\"]", test_str)
                file_name = file_match.group(1) if file_match else "~/.aws/credentials"
                condition_synth = {
                    "type": "FAKE_FILE",
                    "path": file_name,
                    "content": "FAKE_CREDENTIALS_DATA"
                }

            elif "gethostname" in test_str:
                predicate_kind = "hostname_check"
                condition_synth = {"type": "SPOOF_HOSTNAME", "hostname": "prod-financial-node-01"}

            elif "getuser" in test_str:
                predicate_kind = "user_check"
                condition_synth = {"type": "SPOOF_USER", "username": "root"}

            elif any(k in test_str for k in ("dockerenv", "CI", "TRAVIS", "GITHUB_ACTIONS")):
                predicate_kind = "ci_or_sandbox_detection"
                condition_synth = {"type": "CI_FLAG", "key": "CI", "val": "true"}

            elif any(k in test_str for k in ("time.", "datetime", "sleep")):
                predicate_kind = "time_or_delay_gating"
                condition_synth = {"type": "TIME_WARP", "seconds_shift": 86400}

            elif "169.254.169.254" in test_str:
                predicate_kind = "cloud_metadata_check"
                condition_synth = {"type": "METADATA_ENDPOINT", "url": "http://169.254.169.254"}

            if predicate_kind:
                # Find sensitive sinks reachable inside the body
                body_sinks = []
                for sub in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if isinstance(sub, ast.Call):
                        fn = ast.unparse(sub.func)
                        for sink_pattern, meta in SENSITIVE_SINKS.items():
                            if sink_pattern in fn:
                                body_sinks.append({
                                    "sink": fn,
                                    "sink_type": meta["type"],
                                    "sink_risk": meta["risk"],
                                    "line": getattr(sub, 'lineno', lineno)
                                })

                # Compute formula factors
                # sink_risk: max risk of reachable sinks (default 3.0 if no immediate sink)
                sink_risk = max((s["sink_risk"] for s in body_sinks), default=3.0)
                # reachability_confidence: 1.0 for direct syntactic body containment
                reachability_confidence = 0.95 if body_sinks else 0.40
                # novelty: 1.0 for unique environmental trigger
                novelty = 1.0
                # estimated_run_cost: lightweight container execution time ~ 1.2s normalized
                estimated_run_cost = 1.2

                priority = round((sink_risk * reachability_confidence * novelty) / estimated_run_cost, 2)

                # Extract code snippet with line numbers
                start_l = max(1, lineno - 1)
                end_l = min(len(lines), lineno + 3)
                snippet = "\n".join(f"{idx+1:02d}: {lines[idx]}" for idx in range(start_l - 1, end_l))

                sink_reached = body_sinks[0]["sink"] if body_sinks else "Implicit branch execution"
                trigger_id = f"trig-{len(triggers)+1}"

                item = {
                    "id": trigger_id,
                    "file_line": f"{filename}:{lineno}",
                    "predicate": test_str,
                    "kind": predicate_kind,
                    "sink_reached": sink_reached,
                    "sinks": body_sinks,
                    "condition_synth": condition_synth,
                    "code_snippet": snippet,
                    "highlight_line": lineno,
                    "formula": {
                        "sink_risk": sink_risk,
                        "reachability_confidence": reachability_confidence,
                        "novelty": novelty,
                        "estimated_run_cost": estimated_run_cost,
                        "score": priority
                    },
                    "priority": priority
                }
                triggers.append(item)
                frontier_unexplored.append(trigger_id)

    # Sort triggers by priority descending
    triggers.sort(key=lambda t: t["priority"], reverse=True)

    return {
        "ranked_triggers": triggers,
        "total_triggers": len(triggers),
        "frontier": {
            "explored": frontier_explored,
            "in_progress": None,
            "unexplored": frontier_unexplored
        },
        "formula_explanation": "priority = (sink_risk × reachability_confidence × novelty) / estimated_run_cost"
    }
