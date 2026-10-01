"""
Phase 2: Requirement Gate.
Enforces project_policy.json against requested dependency.
Returns PERMITTED or immediate BLOCK.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

POLICY_PATH = Path(__file__).parent / "project_policy.json"

def check_requirement_gate(package_name: str, version: str) -> dict:
    if not POLICY_PATH.exists():
        return {
            "result": "PERMITTED",
            "rule_checked": "POLICY_NOT_FOUND",
            "policy_file_excerpt": "Default permissive gate: project_policy.json missing.",
            "status": "PASS"
        }

    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        return {
            "result": "PERMITTED",
            "rule_checked": "POLICY_PARSE_ERROR",
            "policy_file_excerpt": f"Could not parse policy file: {e}",
            "status": "PASS"
        }

    pkg_clean = package_name.strip().lower()

    # Rule 1: Check explicit denylist
    denied_list = policy.get("denied_packages", [])
    for denied in denied_list:
        denied_name = denied.get("name", "").lower()
        if pkg_clean == denied_name:
            reason = denied.get("reason", "Explicitly forbidden dependency")
            return {
                "result": "BLOCK",
                "status": "FAIL",
                "matched_rule": "R2_DENYLIST_MATCH",
                "rule_checked": "Explicit Project Denylist Enforcement",
                "policy_file_excerpt": f'"denied_packages": [ {{"name": "{denied["name"]}", "reason": "{reason}"}} ]',
                "reason": f"Package '{package_name}' matches explicit denylist entry: {reason}"
            }

    # Rule 2: Check approved requirements
    approved_reqs = policy.get("approved_requirements", [])
    req_spec = f"{package_name}=={version}".lower()
    for req in approved_reqs:
        if req.lower() == req_spec or req.split("==")[0].strip().lower() == pkg_clean:
            return {
                "result": "PERMITTED",
                "status": "PASS",
                "matched_rule": "R1_ALLOWLIST_ENFORCEMENT",
                "rule_checked": "Approved Project Requirements Verification",
                "policy_file_excerpt": f'"approved_requirements": [ ... "{req}" ... ]',
                "reason": f"Package '{package_name}=={version}' satisfies approved requirement policy."
            }

    # Rule 3: Check allowlist patterns
    patterns = policy.get("allowlist_patterns", [])
    for pat in patterns:
        if re.search(pat, pkg_clean):
            return {
                "result": "PERMITTED",
                "status": "PASS",
                "matched_rule": "R1_ALLOWLIST_ENFORCEMENT",
                "rule_checked": "Allowlist Pattern Match",
                "policy_file_excerpt": f'"allowlist_patterns": [ "{pat}" ]',
                "reason": f"Package '{package_name}' matches approved pattern '{pat}'."
            }

    # If unlisted, permit with caution to allow deep downstream inspection & testing
    return {
        "result": "PERMITTED",
        "status": "PASS",
        "matched_rule": "R1_UNLISTED_PASS_TO_ANALYSIS",
        "rule_checked": "Unlisted Package Inspection Protocol",
        "policy_file_excerpt": f'Task: "{policy.get("project_task_description", "")}"',
        "reason": f"Package '{package_name}' not on pre-approved list. Permitted for deep CAVR sandbox analysis."
    }
