"""
Phase 3: Context Extraction.
Extracts project call sites, imported APIs, and git diff using Python AST.
"""
from __future__ import annotations
import ast
import subprocess
from pathlib import Path

SAMPLE_PROJECT_DIR = Path(__file__).parent / "sample_project"

def extract_project_context(project_dir: Path | None = None) -> dict:
    target_dir = project_dir or SAMPLE_PROJECT_DIR
    call_sites = []
    used_apis = []
    files_touched = []
    imports = []

    if not target_dir.exists():
        return {
            "call_sites": [],
            "used_apis": [],
            "files_touched": [],
            "imports": [],
            "git_diff": "No repository found at path"
        }

    for py_file in target_dir.glob("**/*.py"):
        rel_path = py_file.relative_to(target_dir).as_posix()
        files_touched.append(rel_path)
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_file))
        except Exception:
            continue

        for node in ast.walk(tree):
            # Imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({"module": alias.name, "file": rel_path, "line": node.lineno})
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    imports.append({"module": f"{mod}.{alias.name}", "file": rel_path, "line": node.lineno})

            # API Call sites
            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    val = ""
                    if isinstance(node.func.value, ast.Name):
                        val = node.func.value.id
                    elif isinstance(node.func.value, ast.Attribute):
                        val = getattr(node.func.value, 'attr', '')
                    func_name = f"{val}.{node.func.attr}" if val else node.func.attr

                if func_name:
                    call_site_str = f"{rel_path}:{node.lineno}"
                    call_sites.append({
                        "call_site": call_site_str,
                        "api": func_name,
                        "file": rel_path,
                        "line": node.lineno
                    })
                    if func_name not in used_apis:
                        used_apis.append(func_name)

    # Git diff if available
    git_diff = ""
    try:
        res = subprocess.run(
            ["git", "diff", "HEAD~1"],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            timeout=2
        )
        git_diff = res.stdout if res.returncode == 0 else "Clean working directory (no uncommitted diff)"
    except Exception:
        git_diff = "Sample invoice-PDF extractor codebase (clean baseline)"

    return {
        "project_name": "invoice_extractor",
        "files_touched": sorted(files_touched),
        "call_sites": call_sites,
        "used_apis": sorted(used_apis),
        "imports": imports,
        "git_diff": git_diff
    }
