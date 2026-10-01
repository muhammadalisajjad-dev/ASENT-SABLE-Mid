"""
SABLE Baselines B0–B4.

B0: Candidate-only policy check against obligation (no correspondence)
B1: Before/after policy diff comparison (no structural correspondence)
B2: Terraform moved block evidence only
B3: Graph/resource correspondence WITHOUT obligation projection
B4: Strongest reproducible combination of B0+B1+B2+B3 + policy-target relationship

Engine modules (this file, analyzer.py, correspondence.py, authorization.py) must
never import ground_truth.py.
"""
from __future__ import annotations
from backend.sable.hcl_parser import parse as hcl_parse
from backend.sable.authorization import evaluate_authorization
from backend.sable.correspondence import rank, choose


def _load_models(baseline_tf: dict, candidate_tf: dict) -> tuple[dict, dict, list[str]]:
    """Write TF content to a temp directory and parse both models."""
    import tempfile, os
    from pathlib import Path

    errors: list[str] = []

    def write_and_parse(tf_files: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, content in tf_files.items():
                fpath = Path(tmpdir) / fname
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(content, encoding="utf-8")
            try:
                return hcl_parse(tmpdir)
            except Exception as e:
                errors.append(f"Parse error: {e}")
                return {"resources": {}, "moves": [], "outputs": {}, "errors": [str(e)],
                        "graph": {"nodes": [], "edges": []}}

    bm = write_and_parse(baseline_tf)
    cm = write_and_parse(candidate_tf)
    return bm, cm, errors


def run_b0(baseline_tf: dict, candidate_tf: dict, obligation: dict) -> dict:
    """
    B0: Candidate-only policy check.
    Does the candidate grant the required obligation actions on the protected asset?
    Does NOT check whether the candidate asset is the correct logical successor.
    """
    bm, cm, errors = _load_models(baseline_tf, candidate_tf)
    principal = obligation["principal"]
    asset = obligation["protected_asset"]
    actions = obligation["actions"]

    result = evaluate_authorization(cm, principal, asset, actions)
    verdict = "PRESERVED" if result.holds else ("UNKNOWN" if not result.known else "REGRESSED")
    return {
        "baseline_name": "B0",
        "description": "Candidate-only policy check (no correspondence)",
        "verdict": verdict,
        "known": result.known,
        "holds": result.holds,
        "reason": result.reason,
        "actual_actions": result.actual_actions,
        "widening": result.widening,
        "weakening": result.weakening,
        "misbinding": result.misbinding,
        "outside_model": result.outside_model,
        "parse_errors": errors + bm.get("errors", []) + cm.get("errors", []),
        "reduced_strength": False,
    }


def run_b1(baseline_tf: dict, candidate_tf: dict, obligation: dict) -> dict:
    """
    B1: Before/after scan-result comparison.
    Compare the effective permission set for the principal in baseline vs candidate
    without correspondence — just compare authorizations on the same address.
    """
    bm, cm, errors = _load_models(baseline_tf, candidate_tf)
    principal = obligation["principal"]
    asset = obligation["protected_asset"]
    actions = obligation["actions"]

    b_result = evaluate_authorization(bm, principal, asset, actions)
    c_result = evaluate_authorization(cm, principal, asset, actions)

    # Compare action sets
    b_actions = set(b_result.actual_actions)
    c_actions = set(c_result.actual_actions)
    added = sorted(c_actions - b_actions)
    removed = sorted(b_actions - c_actions)

    if not c_result.known:
        verdict = "UNKNOWN"
    elif removed or c_result.misbinding:
        verdict = "REGRESSED"
    elif added or c_result.widening:
        verdict = "REGRESSED"
    elif c_result.holds:
        verdict = "PRESERVED"
    else:
        verdict = "UNKNOWN"

    return {
        "baseline_name": "B1",
        "description": "Before/after policy scan comparison (no structural correspondence)",
        "verdict": verdict,
        "baseline_actions": sorted(b_actions),
        "candidate_actions": sorted(c_actions),
        "actions_added": added,
        "actions_removed": removed,
        "reason": f"Added {added}, removed {removed}" if (added or removed) else c_result.reason,
        "parse_errors": errors + bm.get("errors", []) + cm.get("errors", []),
        "reduced_strength": False,
    }


def run_b2(baseline_tf: dict, candidate_tf: dict, obligation: dict) -> dict:
    """
    B2: Terraform plan / moved evidence only.
    Only uses explicit moved{} blocks to determine successor.
    No structural correspondence, no authorization evaluation.
    """
    _bm, cm, errors = _load_models(baseline_tf, candidate_tf)
    asset = obligation["protected_asset"]

    direct_moves = [m["to"] for m in cm["moves"] if m["from"] == asset]

    if len(direct_moves) == 1:
        verdict = "PRESERVED"
        reason = f"Unique explicit moved block: {asset} → {direct_moves[0]}"
        successor = direct_moves[0]
    elif len(direct_moves) > 1:
        verdict = "UNKNOWN"
        reason = f"Multiple moved blocks from {asset}: {direct_moves}"
        successor = None
    else:
        verdict = "UNKNOWN"
        reason = "No moved block evidence for this asset"
        successor = None

    return {
        "baseline_name": "B2",
        "description": "Terraform moved block evidence only",
        "verdict": verdict,
        "moved_to": direct_moves,
        "chosen_successor": successor,
        "reason": reason,
        "parse_errors": errors,
        "reduced_strength": False,
    }


def run_b3(baseline_tf: dict, candidate_tf: dict, obligation: dict) -> dict:
    """
    B3: Graph/resource correspondence WITHOUT obligation projection.
    Finds the best successor by structural signals but does NOT check authorization.
    """
    bm, cm, errors = _load_models(baseline_tf, candidate_tf)
    asset = obligation["protected_asset"]
    principal = obligation["principal"]
    actions = obligation["actions"]
    config_threshold = 6
    config_margin = 3

    if asset not in bm["resources"]:
        return {
            "baseline_name": "B3",
            "description": "Structural correspondence without authorization projection",
            "verdict": "UNKNOWN",
            "reason": f"Asset '{asset}' not found in baseline",
            "hypotheses": [],
            "parse_errors": errors + bm.get("errors", []),
            "reduced_strength": False,
        }

    hyp, conflicts = rank(bm, cm, asset)
    target, why = choose(hyp, conflicts, config_threshold, config_margin)

    verdict = "PRESERVED" if target else "UNKNOWN"
    return {
        "baseline_name": "B3",
        "description": "Structural correspondence without obligation projection",
        "verdict": verdict,
        "chosen_successor": target,
        "reason": why,
        "hypotheses": hyp[:5],
        "conflicts": conflicts,
        "parse_errors": errors + bm.get("errors", []) + cm.get("errors", []),
        "reduced_strength": False,
    }


def run_b4(baseline_tf: dict, candidate_tf: dict, obligation: dict,
           available_tools: dict | None = None) -> dict:
    """
    B4: Strongest reproducible combination.
    Runs B0 + B1 + B2 + B3 + full authorization evaluation on the best structural successor.
    Uses policy-target relationship and reference evidence from the correspondence step.
    Tags 'reduced_strength' if external tools were unavailable.
    """
    b0 = run_b0(baseline_tf, candidate_tf, obligation)
    b1 = run_b1(baseline_tf, candidate_tf, obligation)
    b2 = run_b2(baseline_tf, candidate_tf, obligation)
    b3 = run_b3(baseline_tf, candidate_tf, obligation)

    bm, cm, errors = _load_models(baseline_tf, candidate_tf)
    asset = obligation["protected_asset"]
    principal = obligation["principal"]
    actions = obligation["actions"]
    config_threshold = 6
    config_margin = 3

    hyp, conflicts = rank(bm, cm, asset)
    target, why = choose(hyp, conflicts, config_threshold, config_margin)

    if target:
        auth = evaluate_authorization(cm, principal, target, actions)
        if not auth.known:
            verdict = "UNKNOWN"
        elif auth.holds:
            verdict = "PRESERVED"
        else:
            verdict = "REGRESSED"
        auth_result = {
            "known": auth.known, "holds": auth.holds, "reason": auth.reason,
            "widening": auth.widening, "weakening": auth.weakening,
            "misbinding": auth.misbinding, "outside_model": auth.outside_model
        }
    else:
        verdict = "UNKNOWN"
        auth_result = None

    # Reduced strength if external tools were not run
    tools = available_tools or {}
    reduced = not tools.get("checkov", {}).get("available") and not tools.get("trivy", {}).get("available")

    return {
        "baseline_name": "B4",
        "description": "Strongest combination: B0+B1+B2+B3 + policy-relationship + reference evidence",
        "verdict": verdict,
        "chosen_successor": target,
        "correspondence_reason": why,
        "authorization": auth_result,
        "b0_verdict": b0["verdict"],
        "b1_verdict": b1["verdict"],
        "b2_verdict": b2["verdict"],
        "b3_verdict": b3["verdict"],
        "hypotheses": hyp[:5],
        "conflicts": conflicts,
        "parse_errors": errors,
        "reduced_strength": reduced,
        "reduced_strength_note": "Checkov/Trivy unavailable; using built-in approximations" if reduced else None,
    }
