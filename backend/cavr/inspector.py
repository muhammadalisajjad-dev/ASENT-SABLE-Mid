from __future__ import annotations
import ast
import base64
import os
import re
from typing import Any

def levenshtein_distance(s1: str, s2: str) -> int:
    s1, s2 = s1.lower(), s2.lower()
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class AstSecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[dict] = []

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            val_name = ""
            if isinstance(node.func.value, ast.Name):
                val_name = node.func.value.id
            func_name = f"{val_name}.{node.func.attr}" if val_name else node.func.attr

        # Critical: eval / exec
        if func_name in ("eval", "exec"):
            self.findings.append({
                "category": "ast_dynamic_execution",
                "severity": "critical",
                "target": func_name,
                "line": getattr(node, "lineno", 0),
                "message": f"Direct invocation of dynamic code execution `{func_name}()`"
            })

        # High/Critical: os.system / subprocess
        if func_name in ("os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"):
            self.findings.append({
                "category": "ast_process_spawn",
                "severity": "critical",
                "target": func_name,
                "line": getattr(node, "lineno", 0),
                "message": f"Subprocess invocation `{func_name}()` detected in artifact source"
            })

        # High: Raw sockets
        if func_name in ("socket.socket", "socket.create_connection"):
            self.findings.append({
                "category": "ast_raw_socket",
                "severity": "high",
                "target": func_name,
                "line": getattr(node, "lineno", 0),
                "message": f"Raw socket instantiation `{func_name}()` detected"
            })

        # High: Base64 decode execution / obfuscation
        if func_name in ("base64.b64decode", "b64decode"):
            self.findings.append({
                "category": "ast_obfuscation",
                "severity": "high",
                "target": func_name,
                "line": getattr(node, "lineno", 0),
                "message": "Base64 decode operation detected; possible payload staging"
            })

        # High: __import__ dynamic loading
        if func_name in ("__import__", "importlib.import_module"):
            self.findings.append({
                "category": "ast_dynamic_import",
                "severity": "high",
                "target": func_name,
                "line": getattr(node, "lineno", 0),
                "message": f"Dynamic module loader `{func_name}()`"
            })

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            # Check for high-entropy long base64 strings
            val = node.value.strip()
            if len(val) > 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", val) and len(val) % 4 == 0:
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                    if any(kw in decoded for kw in ("import ", "os.", "socket", "http", "curl", "bash", "token", "secret", "aws")):
                        self.findings.append({
                            "category": "ast_obfuscated_payload",
                            "severity": "critical",
                            "target": "base64_payload",
                            "line": getattr(node, "lineno", 0),
                            "message": f"Decoded base64 payload containing sensitive execution keywords: '{decoded[:60]}...'"
                        })
                except Exception:
                    pass
        self.generic_visit(node)

def inspect_python_code(source_code: str, filename: str = "package.py") -> list[dict]:
    findings: list[dict] = []
    try:
        tree = ast.parse(source_code, filename=filename)
        visitor = AstSecurityVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError as e:
        findings.append({
            "category": "syntax_error",
            "severity": "high",
            "target": filename,
            "line": e.lineno or 0,
            "message": f"AST parse syntax error: {e.msg}"
        })
    except Exception as e:
        findings.append({
            "category": "ast_failure",
            "severity": "medium",
            "target": filename,
            "line": 0,
            "message": f"Failed to traverse AST: {str(e)}"
        })

    # Check setup.py install-time hooks
    if "setup.py" in filename.lower():
        if re.search(r"cmdclass\s*=", source_code):
            findings.append({
                "category": "setup_hook",
                "severity": "critical",
                "target": "cmdclass",
                "line": 0,
                "message": "Custom install/cmdclass hook in setup.py executes untrusted code on package install"
            })
        if re.search(r"class\s+\w+\((install|develop|build_py)\)", source_code):
            findings.append({
                "category": "setup_hook",
                "severity": "critical",
                "target": "install_override",
                "line": 0,
                "message": "Overridden install/develop command in setup.py"
            })

    return findings

def check_typosquatting(package_name: str, trusted_names: list[str]) -> list[dict]:
    findings: list[dict] = []
    pkg = package_name.strip().lower()
    
    # Exact match is not a typosquat
    if pkg in [t.lower() for t in trusted_names]:
        return findings

    # Lookalike characters map
    homoglyphs = {
        'o': '0', '0': 'o', 'l': '1', '1': 'l', 'i': '1', '1': 'i',
        'vv': 'w', 'w': 'vv', 'rn': 'm', 'm': 'rn'
    }

    for trusted in trusted_names:
        t_clean = trusted.strip().lower()
        dist = levenshtein_distance(pkg, t_clean)
        
        # Levenshtein distance 1 or 2
        if 1 <= dist <= 2:
            severity = "critical" if dist == 1 else "high"
            findings.append({
                "category": "typosquatting",
                "severity": severity,
                "target": package_name,
                "trusted_target": trusted,
                "distance": dist,
                "message": f"Package name '{package_name}' is within edit distance {dist} of trusted package '{trusted}'"
            })
            continue

        # Lookalike check
        norm_pkg = pkg
        norm_t = t_clean
        for k, v in homoglyphs.items():
            norm_pkg = norm_pkg.replace(k, v)
            norm_t = norm_t.replace(k, v)
        if norm_pkg == norm_t:
            findings.append({
                "category": "homoglyph_attack",
                "severity": "critical",
                "target": package_name,
                "trusted_target": trusted,
                "message": f"Package name '{package_name}' uses visual homoglyphs/lookalikes imitating '{trusted}'"
            })

    return findings

def check_metadata_sanity(metadata: dict) -> list[dict]:
    findings: list[dict] = []
    version = str(metadata.get("version", "1.0.0")).strip()
    license_info = metadata.get("license") or metadata.get("classifier_license")

    # Version jump check
    if re.match(r"^(\d+)", version):
        major = int(re.match(r"^(\d+)", version).group(1))
        if major >= 90:
            findings.append({
                "category": "metadata_sanity",
                "severity": "high",
                "target": "version",
                "message": f"Suspicious version number '{version}': major version jump indicates potential dependency confusion payload"
            })

    # Missing license check
    if not license_info or license_info.lower() in ("unknown", "none", ""):
        findings.append({
            "category": "metadata_sanity",
            "severity": "medium",
            "target": "license",
            "message": "Missing or undeclared license in package metadata"
        })

    # Unexpected external dependencies
    reqs = metadata.get("requires_dist", [])
    for req in reqs:
        if "@" in req or "http://" in req or "https://" in req or "git+" in req:
            findings.append({
                "category": "metadata_sanity",
                "severity": "critical",
                "target": "unpinned_url_dependency",
                "message": f"Package declares direct URL/git dependency: {req}"
            })

    return findings

def run_action_inspection(package_name: str, version: str, source_code: str, metadata: dict, trusted_names: list[str]) -> dict:
    ast_findings = inspect_python_code(source_code, filename=f"{package_name}.py")
    typosquat_findings = check_typosquatting(package_name, trusted_names)
    metadata_findings = check_metadata_sanity(metadata)

    all_findings = ast_findings + typosquat_findings + metadata_findings

    severities = [f["severity"] for f in all_findings]
    if "critical" in severities or any(f["severity"] == "high" for f in ast_findings):
        suggested_action = "BLOCK"
    elif "high" in severities or "medium" in severities:
        suggested_action = "NEEDS_REVIEW"
    else:
        suggested_action = "ALLOW"

    return {
        "package": package_name,
        "version": version,
        "suggested_action": suggested_action,
        "total_findings": len(all_findings),
        "findings": all_findings,
        "breakdown": {
            "critical": severities.count("critical"),
            "high": severities.count("high"),
            "medium": severities.count("medium"),
            "info": severities.count("info")
        }
    }
