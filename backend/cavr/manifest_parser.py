from __future__ import annotations
import re
from pathlib import Path
from packaging.requirements import Requirement

def parse_requirements_txt(content: str) -> list[dict]:
    results: list[dict] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            req = Requirement(line)
            results.append({
                "name": req.name,
                "specifier": str(req.specifier) if req.specifier else "*",
                "raw": line
            })
        except Exception:
            # Fallback regex for non-standard requirements
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)(.*)$", line)
            if m:
                results.append({
                    "name": m.group(1),
                    "specifier": m.group(2).strip(),
                    "raw": line
                })
    return results

def parse_pyproject_toml(content: str) -> list[dict]:
    results: list[dict] = []
    # Match dependencies = [ ... ]
    m = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if m:
        dep_lines = m.group(1).split(",")
        for line in dep_lines:
            clean = line.strip().strip("'\"")
            if clean:
                try:
                    req = Requirement(clean)
                    results.append({
                        "name": req.name,
                        "specifier": str(req.specifier) if req.specifier else "*",
                        "raw": clean
                    })
                except Exception:
                    pass
    return results

def detect_manifest_changes(before_content: str, after_content: str, manifest_type: str = "requirements.txt") -> list[dict]:
    parser = parse_requirements_txt if manifest_type == "requirements.txt" else parse_pyproject_toml
    before_deps = {d["name"].lower(): d for d in parser(before_content)}
    after_deps = {d["name"].lower(): d for d in parser(after_content)}

    changes: list[dict] = []
    for name, dep in after_deps.items():
        if name not in before_deps:
            changes.append({"action": "ADDED", "package": dep["name"], "specifier": dep["specifier"], "raw": dep["raw"]})
        elif before_deps[name]["specifier"] != dep["specifier"]:
            changes.append({
                "action": "VERSION_CHANGED",
                "package": dep["name"],
                "old_specifier": before_deps[name]["specifier"],
                "new_specifier": dep["specifier"],
                "raw": dep["raw"]
            })
    for name, dep in before_deps.items():
        if name not in after_deps:
            changes.append({"action": "REMOVED", "package": dep["name"], "specifier": dep["specifier"]})
    return changes
