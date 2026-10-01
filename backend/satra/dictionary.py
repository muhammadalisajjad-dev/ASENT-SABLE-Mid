"""
ASENT SATRA Security Dictionary Engine.
Contains trusted security rule specifications across the 8 core vulnerability families.
"""
from __future__ import annotations

RULES = [
    {
        "id": "AUTHZ.IDOR.001",
        "cwe": "CWE-639",
        "family": "Authorization / IDOR",
        "applicability": ["FastAPI", "Flask", "InvoiceHub", "REST APIs"],
        "preconditions": ["object ID from request", "authenticated user", "invoice ownership binding"],
        "security_obligation": "Enforce explicit owner matching before returning or modifying invoice resources",
        "safe_outcome": "HTTP 403 Forbidden with zero data disclosure and no state modification",
        "pytest_template": """def test_nonowner_denied(client, nonowner_token, sample_invoice):
    resp = client.get(f"/api/invoices/{sample_invoice['id']}", headers={"Authorization": f"Bearer {nonowner_token}"})
    assert resp.status_code == 403, "Non-owner user must receive HTTP 403 Forbidden"
    data = resp.json()
    assert "amount" not in data, "Sensitive invoice payload must not leak"
""",
        "broken_version": """def test_nonowner_denied(client, nonowner_token, sample_invoice):
    resp = client.get(f"/api/invoices/{sample_invoice['id']}", headers={"Authorization": f"Bearer {nonowner_token}"})
    # Broken oracle: weakened assertion accepting 200 or 403
    assert resp.status_code in [200, 403]
""",
        "input_classes": ["owner", "nonowner", "unauthenticated", "administrator"],
        "counterfactual_template": "AST replace `can_access_invoice` body with `return True`",
        "validation_rules": ["parses", "secure baseline passes", "valid mutant killed by assertion", "repeatable", "local", "bounded runtime"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "INJ.SQL.001",
        "cwe": "CWE-89",
        "family": "SQL Injection",
        "applicability": ["FastAPI", "Flask", "SQLAlchemy", "SQLite", "PostgreSQL"],
        "preconditions": ["user-supplied query parameter", "database lookup query", "search / filter"],
        "security_obligation": "All database operations must use parameterized queries or ORM bindings; raw string interpolation forbidden",
        "safe_outcome": "Tautological payloads treated as literal strings; 0 unintended records returned",
        "pytest_template": """def test_sql_injection_defense(client, owner_token):
    payload = "1' OR '1'='1"
    resp = client.get(f"/api/invoices/search?q={payload}", headers={"Authorization": f"Bearer {owner_token}"})
    assert resp.status_code in (200, 400), "Search query must safely handle SQL metacharacters"
    results = resp.json().get("items", [])
    assert len(results) == 0, "SQL injection tautology must not return unintended rows"
""",
        "broken_version": """# Broken / Vulnerable code in search route:
# cursor.execute(f"SELECT * FROM invoices WHERE description LIKE '%{query}%'")
# Allows attacker to extract all records via tautological quote escaping
""",
        "input_classes": ["standard text", "tautological string", "union select probe", "stacked query"],
        "counterfactual_template": "Replace parameterized execute with f-string string format concatenation",
        "validation_rules": ["parses", "secure baseline passes", "syntax compliant", "repeatable", "local"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "INJ.CMD.001",
        "cwe": "CWE-78",
        "family": "Command Injection",
        "applicability": ["FastAPI", "Flask", "CLI Utilities", "PDF Generators"],
        "preconditions": ["external tool invocation", "file conversion", "export parameter"],
        "security_obligation": "Never pass unvalidated user inputs to shell=True or system command interpreters",
        "safe_outcome": "HTTP 400 Validation Error; zero subprocess invocation containing shell metacharacters",
        "pytest_template": """def test_command_injection_defense(client, owner_token, sample_invoice):
    malicious_format = "pdf; id; cat /etc/passwd"
    resp = client.post(f"/api/invoices/{sample_invoice['id']}/export", json={"format": malicious_format}, headers={"Authorization": f"Bearer {owner_token}"})
    assert resp.status_code == 400, "Unrecognized or dangerous export format must be rejected"
""",
        "broken_version": """# Broken / Vulnerable code in export route:
# os.system(f"wkhtmltopdf /tmp/{inv_id}.html /tmp/{inv_id}.{format}")
# Executes arbitrary shell command injected via 'format' parameter
""",
        "input_classes": ["pdf", "csv", "json", "metacharacter shell string", "null-byte inject"],
        "counterfactual_template": "Replace subprocess array call `['tool', arg]` with `os.system('tool ' + arg)`",
        "validation_rules": ["parses", "secure baseline passes", "side-effect safety", "repeatable"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "PATH.TRAV.001",
        "cwe": "CWE-22",
        "family": "Path Traversal",
        "applicability": ["FastAPI", "Flask", "Static File Handlers", "Attachment Downloads"],
        "preconditions": ["file path parameter from request", "filesystem read / download"],
        "security_obligation": "Canonicalized file paths must be strictly contained within safe application upload directory",
        "safe_outcome": "HTTP 403 or 404; attempts to access parent directories via ../ traversal are rejected",
        "pytest_template": """def test_path_traversal_defense(client, owner_token):
    traversal_path = "../../etc/passwd"
    resp = client.get(f"/api/invoices/download?path={traversal_path}", headers={"Authorization": f"Bearer {owner_token}"})
    assert resp.status_code in (400, 403, 404), "Directory traversal pattern must be rejected"
    assert "root:x:0:0" not in resp.text, "System files must never be disclosed"
""",
        "broken_version": """# Broken / Vulnerable code in download route:
# file_path = os.path.join(UPLOAD_DIR, request.args['path'])
# return send_file(file_path) # Missing os.path.realpath containment check!
""",
        "input_classes": ["relative path", "absolute path", "dot-dot traversal", "url-encoded traversal"],
        "counterfactual_template": "Remove `path.resolve().is_relative_to(SAFE_DIR)` confinement assertion",
        "validation_rules": ["parses", "secure baseline passes", "local", "repeatable"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "XSS.STORED.001",
        "cwe": "CWE-79",
        "family": "Cross-Site Scripting (XSS)",
        "applicability": ["HTML Templates", "Jinja2", "React SSR", "Invoice PDF Rendering"],
        "preconditions": ["invoice customer note", "HTML rendering context"],
        "security_obligation": "User-supplied text rendered into HTML contexts must be contextual escaped or sanitized",
        "safe_outcome": "HTML metacharacters `<script>` escaped as `&lt;script&gt;`; no script execution context",
        "pytest_template": """def test_xss_sanitization(client, owner_token, sample_invoice):
    xss_payload = "<script>alert('xss')</script>"
    resp = client.put(f"/api/invoices/{sample_invoice['id']}/notes", json={"notes": xss_payload}, headers={"Authorization": f"Bearer {owner_token}"})
    assert resp.status_code == 200
    view_resp = client.get(f"/api/invoices/{sample_invoice['id']}/html", headers={"Authorization": f"Bearer {owner_token}"})
    assert "<script>alert" not in view_resp.text, "Raw script tags must not be reflected unescaped"
""",
        "broken_version": """# Broken / Vulnerable template rendering:
# {{ invoice.notes | safe }}
# Direct unescaped output into the rendered invoice HTML document
""",
        "input_classes": ["plain text", "script tags", "svg onload", "javascript pseudo-protocol"],
        "counterfactual_template": "Add `| safe` filter in Jinja template context",
        "validation_rules": ["parses", "secure baseline passes", "repeatable"],
        "runnable_counterfactual": False,
        "version": 1
    },
    {
        "id": "SSRF.WEBHOOK.001",
        "cwe": "CWE-918",
        "family": "Server-Side Request Forgery (SSRF)",
        "applicability": ["FastAPI", "Flask", "Webhook Deliveries", "URL Scrapers"],
        "preconditions": ["user-supplied webhook URL", "backend HTTP client dispatch"],
        "security_obligation": "Outbound HTTP dispatches must forbid loopback, RFC1918 private IPs, and cloud metadata (169.254.169.254)",
        "safe_outcome": "HTTP 400 Invalid Destination; connection to private infrastructure aborted before socket connect",
        "pytest_template": """def test_ssrf_destination_validation(client, admin_token):
    forbidden_targets = ["http://127.0.0.1:8000/internal", "http://169.254.169.254/latest/meta-data/"]
    for url in forbidden_targets:
        resp = client.post("/api/webhooks/test", json={"target_url": url}, headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 400, f"Private / metadata IP {url} must be rejected"
""",
        "broken_version": """# Broken / Vulnerable webhook dispatch:
# requests.post(user_url, json=data) # Direct dispatch with no IP range filter!
""",
        "input_classes": ["public domain", "localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0"],
        "counterfactual_template": "Remove IP resolution blacklist verification before `requests.post()`",
        "validation_rules": ["parses", "secure baseline passes", "side-effect safety"],
        "runnable_counterfactual": False,
        "version": 1
    },
    {
        "id": "AUTH.CSRF.001",
        "cwe": "CWE-352",
        "family": "Cross-Site Request Forgery (CSRF)",
        "applicability": ["Web Applications", "Cookie-based Authentication"],
        "preconditions": ["browser cookie session", "state-changing HTTP POST/PUT/DELETE"],
        "security_obligation": "State-changing mutations must validate anti-CSRF token or verify SameSite=Strict cookies",
        "safe_outcome": "HTTP 403 Forbidden when origin/referer is third-party and CSRF token is missing",
        "pytest_template": """def test_csrf_protection(client):
    # Cross-origin POST request without anti-CSRF header
    resp = client.post("/api/invoices/create", json={"amount": 100}, headers={"Origin": "https://attacker.evil.com"})
    assert resp.status_code in (401, 403), "Cross-origin mutation without CSRF token must be denied"
""",
        "broken_version": """# Broken configuration:
# app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
""",
        "input_classes": ["same-origin", "cross-origin", "missing header", "spoofed referer"],
        "counterfactual_template": "Disable CSRF validation middleware",
        "validation_rules": ["parses", "secure baseline passes"],
        "runnable_counterfactual": False,
        "version": 1
    },
    {
        "id": "DESER.INSEC.001",
        "cwe": "CWE-502",
        "family": "Insecure Deserialization",
        "applicability": ["Python Applications", "Data Importers", "Job Queues"],
        "preconditions": ["uploaded invoice file", "binary payload decoding"],
        "security_obligation": "Use safe data serialization formats (JSON, SafeLoader YAML); Python `pickle` or `yaml.load` forbidden",
        "safe_outcome": "HTTP 400 Bad Request; binary pickle payloads immediately rejected without deserialization",
        "pytest_template": """def test_insecure_deserialization_rejected(client, owner_token):
    # Simulated pickle gadget payload
    pickle_data = b"cos\\nsystem\\n(S'whoami'\\ntR."
    resp = client.post("/api/invoices/import", data=pickle_data, headers={"Authorization": f"Bearer {owner_token}", "Content-Type": "application/octet-stream"})
    assert resp.status_code == 400, "Arbitrary pickle object import must fail validation"
""",
        "broken_version": """# Broken importer:
# import pickle
# invoice_obj = pickle.loads(raw_uploaded_data) # Remote Code Execution via deserialization!
""",
        "input_classes": ["valid json", "corrupted json", "pickle bytecode", "unsafe yaml tag"],
        "counterfactual_template": "Replace json.loads() with pickle.loads()",
        "validation_rules": ["parses", "secure baseline passes", "side-effect safety"],
        "runnable_counterfactual": False,
        "version": 1
    },
    # Backward compatibility entries
    {
        "id": "AUTHN.001",
        "cwe": "CWE-306",
        "family": "Authentication",
        "applicability": ["FastAPI", "InvoiceHub"],
        "preconditions": ["private invoice route"],
        "security_obligation": "Require valid Bearer token for protected resources",
        "safe_outcome": "HTTP 401 Unauthorized without token",
        "pytest_template": "trusted_security.py::test_unauthenticated_denied",
        "broken_version": "# Missing Depends(get_current_user) in route decorator",
        "input_classes": ["missing bearer token"],
        "counterfactual_template": None,
        "validation_rules": ["parses", "baseline passes", "local"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "AUTHZ.ADMIN.001",
        "cwe": "CWE-862",
        "family": "Privilege Separation",
        "applicability": ["FastAPI", "InvoiceHub"],
        "preconditions": ["administrator route"],
        "security_obligation": "Verify admin role before granting access to tenant management",
        "safe_outcome": "HTTP 403 Forbidden for normal user",
        "pytest_template": "trusted_security.py::test_normal_user_not_admin",
        "broken_version": "# Removing role check `if user.role != 'admin': raise HTTPException(403)`",
        "input_classes": ["normal user", "admin"],
        "counterfactual_template": None,
        "validation_rules": ["baseline passes", "local"],
        "runnable_counterfactual": True,
        "version": 1
    },
    {
        "id": "INPUT.PDF.001",
        "cwe": "CWE-434",
        "family": "Unsafe Upload",
        "applicability": ["FastAPI", "InvoiceHub"],
        "preconditions": ["PDF upload route"],
        "security_obligation": "Verify magic header %PDF and reject non-PDF file contents",
        "safe_outcome": "Reject non-PDF content with HTTP 400",
        "pytest_template": "trusted_security.py::test_reject_non_pdf",
        "broken_version": "# Uploading HTML or script content masquerading as PDF",
        "input_classes": ["text masquerading as PDF"],
        "counterfactual_template": None,
        "validation_rules": ["baseline passes"],
        "runnable_counterfactual": True,
        "version": 1
    }
]

def get_coverage_matrix() -> list[dict]:
    """Returns coverage matrix for the 8 core vulnerability families."""
    core_ids = [
        "AUTHZ.IDOR.001", "INJ.SQL.001", "INJ.CMD.001", "PATH.TRAV.001",
        "XSS.STORED.001", "SSRF.WEBHOOK.001", "AUTH.CSRF.001", "DESER.INSEC.001"
    ]
    core_rules = [r for r in RULES if r["id"] in core_ids]
    matrix = []
    for r in core_rules:
        matrix.append({
            "id": r["id"],
            "cwe": r["cwe"],
            "family": r["family"],
            "runnable_counterfactual": r.get("runnable_counterfactual", False),
            "status": "Fully Runnable (Mutant Verified)" if r.get("runnable_counterfactual") else "Model-Only (Test Template)",
            "safe_outcome": r["safe_outcome"],
            "version": r["version"]
        })
    return matrix
