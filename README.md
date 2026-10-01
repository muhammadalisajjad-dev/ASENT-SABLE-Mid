# ASENT — Integrated Security Assurance

A runnable FAST-NUCES FYP proof of concept for **CAVR**, **SATRA-RV**, and **SABLE**, integrated around one InvoiceHub candidate workspace, evidence lifecycle, and final trust gate. Security results come from the Python backend. The React interface renders actual events and persisted results.

![Actual safe run](reports/dashboard-safe-accept.png)

## Start here

**Recommended:** Linux or Windows **WSL2 Ubuntu**, Python **3.12**, Git, and Node.js **20+ / npm**. Python 3.11+ is supported by setup; 3.12 was tested. Internet is needed for first-time dependency installation. No paid API, AWS account, or coding-agent subscription is required.

```bash
cd ASENT
bash scripts/setup.sh
bash scripts/start.sh
```

Open **http://127.0.0.1:8000**. The API serves the included compiled React dashboard. Open **Experiment library → Normal first build**, or click **Run safe scenario**. A normal build should produce CAVR VERIFIED, SATRA ACCEPT, SABLE PRESERVED, and ASENT ACCEPT with a reconstructed Git commit. Typical runs on the validation host took about 8–15 seconds; repairs take longer.

Setup creates `.venv`, installs `requirements.lock.txt`, and builds the frontend. If Node is absent, it uses the supplied `frontend/dist`. For separate frontend development:

```bash
# Terminal 1
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
# Terminal 2
cd frontend
npm ci
npm run dev
```

Vite proxies `/api` and `/invoicehub` to port 8000. Keep this local development service on loopback; it is not a multi-tenant hosted service. `ASENT_DATA` can point at a separate runtime directory. `ASENT_URL` changes the CLI's API URL.

**Windows:** WSL2 is the supported path for the full demonstration. `scripts/setup.ps1` and `scripts/start.ps1` also prepare/run the UI and API on native Windows with Python 3.12. The POSIX `resource`-limited execution fallback needs Linux; use Docker Desktop with the sandbox image for execution on native Windows. Native Windows and Docker Desktop were not executed in this environment.

## Demonstration

See [the exact six-minute sequence](docs/demo-sequence.md). All nine scenarios can also be run after starting the server:

```bash
.venv/bin/python -m backend.cli run --scenario safe --wait
.venv/bin/python -m backend.cli run --scenario cavr_canary --wait
.venv/bin/python -m backend.cli run --scenario satra_weak --wait
.venv/bin/python -m backend.cli run --scenario satra_bypass --wait
.venv/bin/python -m backend.cli run --scenario sable_preserved --wait
.venv/bin/python -m backend.cli run --scenario sable_regressed --wait
.venv/bin/python -m backend.cli run --scenario sable_unknown --wait
.venv/bin/python -m backend.cli run --scenario sable_widened --wait
.venv/bin/python -m backend.cli run --scenario cross_module --repair --wait
```

`bash scripts/demo.sh safe` is a convenience wrapper. **Reset:** stop the server and run `.venv/bin/python scripts/reset.py --yes`; this archives the default runtime instead of deleting it. Custom `ASENT_DATA` directories are not touched.

InvoiceHub is a real local FastAPI/SQLite application with registration, expiring bearer sessions, PDF upload/extraction, object ownership, admin access/deletion, and an admin-only archive operation for invoices older than 90 days. Sign in as `alice`, `bob`, or `admin`, password `demo-password`. Upload `demo_project/InvoiceHub/fixtures/invoice.pdf`. Objects move between local filesystem buckets; Terraform represents cloud infrastructure but no AWS resources are deployed. New uploads are not artificially old: the archive test creates and dates its own fixture to exercise the 90-day boundary.

## What runs

| Component | Implemented computation | Bounded coverage |
|---|---|---|
| Shared ASENT | SRS/plan/policy intake, local Git baseline and candidate worktree, immutable snapshots, file/event routing, concurrent analyzers, SQLite evidence, SHA-256 envelopes, hash-linked events, SSE, invalidation, reconstruction and final gate | Local single-user PoC, not a tamper-proof remote attestation service |
| CAVR | Exact locked artifacts, wheel metadata and registry digest, transitive constraints, advisory lookup, AST triage, capability contract, trigger frontier, real counterfactual runs, normalized events, NetworkX graph, knowledge correlation, cache, Z3-ranked bounded repair and re-verification | Python wheel/source PDF slice; automatic API replacement only for the explicit supplied adapter |
| SATRA-RV | AST/Git change localization, independent Security Change Contract, versioned dictionary, Bandit evidence, actual pytest/JUnit, valid ownership mutation, original/candidate oracle comparison, repeatability, isolated repair, differential verification | InvoiceHub/FastAPI authentication, ownership, admin, upload, login-input and archival checks; other families have knowledge records, not claimed universal dynamic coverage |
| SABLE | Actual HCL parsing, local-module/reference normalization, baseline verification, scored successor hypotheses, obligation projection, wrong binding and privilege widening | S3 objects + inline IAM role policies; unsupported semantics and ambiguous correspondence produce UNKNOWN |
| Threat Repository | Separate SQLite tables/database, 49 seeded knowledge/provenance records, immutable version snapshots/digests, source registry, validated JSON and OSV import/export, toggles and Research UI | Supporting knowledge, never a package-name blacklist or an executable imported template |
| InvoiceHub + dashboard | Real application flows, live timeline, module graphs/results, research details, rule explanations, evidence ledger, experiments, final gate and JSON report download | Local demonstration; no production deployment |

CAVR's ordinary PDF case does not run a deep sandbox merely because a package exists. It checks the exact artifact and context, and proves that the optional pypdf JBIG2 subprocess path is disabled at all supported call sites. Deep activation is reserved for suspicious supported predicates. Cache keys bind package/version, artifact, dependency subtree, capability context, project policy, advisories, analyzer version, and CAVR knowledge digest.

SATRA's requirements come from `SRS.md`, `policy.json`, route semantics and independent trusted tests. A test must pass the secure baseline twice and fail by assertion on an independently validated ownership bypass. Collection/import/runtime errors do not count as mutant kills. Deterministic templates supply the core tests and repairs. SABLE receives no automatic repair engine; its correction button applies a clearly labeled supplied developer revision and re-runs analysis.

## Three separate records

- **Threat Repository** (`backend/threat_repo`, `threat-repository.sqlite3`): reusable rules, vulnerability/package metadata and provenance. The nine Research tabs expose versions, enabled state, search, details, source records and JSON import/export. A curated public OSV record includes a genuine historical pypdf affected range; it is explicitly marked as reviewed web facts, not a fabricated API response.
- **Evidence Store** (`backend/db`, `asent.sqlite3` plus run artifacts): what was actually observed, with analyzer/version, candidate/input hashes, threat version/module digest, timings, uncertainty, JUnit and runtime trace references. Evidence bodies remain immutable; stale state is separate.
- **Experiment Library** (`scenarios` and the experiments table): reproduction inputs, ground truth where known, source labels, hashes and recorded provenance. Catalog expectations never feed the analyzers or final gate.

Changing CAVR knowledge invalidates CAVR evidence/cache; SATRA and SABLE knowledge changes affect their respective modules. Changing shared provenance affects every module that cites it. This is conservative module-level invalidation, not precise package-level dependency tracking. A changed global version can remain compatible with an unaffected module digest. Analysis detects knowledge/candidate changes before final acceptance. Imported executable-template changes outside the compiled bounded model produce uncertainty.

The final gate has **no majority vote**. Current rejection/regression blocks acceptance. Missing, stale, unsupported or inconclusive evidence yields REVIEW. RESTRICTED only passes if an enforcement record exists; this distribution does not claim a generic restriction synthesizer. Accepted source is reconstructed from a fresh Git clone and checked against the exact snapshot. An old reconstructed folder remains historical after revocation; it is no longer presented as a current trusted handoff.

## External coding agents and replay

ASENT is agent-neutral. It observes file changes and dependency proposals; event text does not supply security meaning.

```bash
.venv/bin/python -m backend.cli watch --repository /absolute/path/to/InvoiceHub --wait
.venv/bin/python -m backend.cli replay scenarios/replay/weak-oracle/bundle.json --wait
.venv/bin/python -m backend.cli dependency --run RUN_ID -- pip install pypdf==6.19.0
.venv/bin/python -m backend.cli report RUN_ID --output assurance.json
```

Project Intake accepts pasted text and uploaded UTF-8 TXT/MD or text PDFs (5 MiB, 50 pages). PDF extraction runs in a bounded disposable process. Review the extracted requirements before starting; scanned PDFs need OCR outside this PoC.

The watch adapter copies external source into the isolated candidate; it never edits the original repository. It polls every 1.5 seconds. Only affected module inputs are recomputed; byte-identical applicable evidence is revalidated to the new snapshot. For an initial external repository, that supplied state is the provisional baseline and must pass independent checks. To evaluate historical continuity, register a trusted baseline first, then edit the watched repository.

The replay bundle contains an initial repository, JSONL file-write events, provenance and SHA-256 hashes. The supplied replay is labeled **CONTROLLED REPRODUCTION**. It is not claimed to be a naturally occurring agent failure. Recorded agent identities are supplied metadata, not cryptographically authenticated identities. A research loader accepts local, hash-checked case manifests only with explicit `--opt-in`, provenance, usage notes and Docker/Podman. It never downloads research samples.

Optional PATH wrappers:

```bash
export ASENT_RUN_ID=RUN_ID
export PATH="$PWD/scripts/gateway:$PATH"
pip install pypdf==6.19.0
```

Wrappers hold the action and ask the same gateway to analyze it. They **do not install anything**, even when the proposal is approved. The gateway supports exact pinned PyPI install proposals. npm proposals are captured but fail closed because npm artifact analysis is outside this slice. These cooperative wrappers are not OS-level mandatory interception; an agent can bypass PATH. Use external OS/container controls if mandatory interception is required.

## Execution backends and optional tools

The dashboard shows actual executable availability. `/api/capabilities` includes operational strace detection, not just an installed binary.

| Tool | Setup / use | Validation-host result |
|---|---|---|
| Docker / Podman | `docker build -f docker/sandbox.Dockerfile -t asent-sandbox:local .` (replace docker with podman if needed) | Neither engine available; container paths implemented but unexecuted |
| strace | Ubuntu/WSL: `sudo apt-get update && sudo apt-get install -y strace` | Installed, but PTRACE denied by host; no invented syscall trace |
| Terraform | Install from https://developer.hashicorp.com/terraform/install and add to PATH | Unavailable; actual HCL analysis still runs. Optional adapter performs `fmt -check -recursive`, not live validation/deployment |
| Checkov | Install into a separate environment with `pipx install checkov`, make executable visible | Unavailable; optional CLI scan retains actual JSON/exit status |
| Bandit | Included in Python requirements | Executed; warnings are shown, not treated as authoritative final verdicts |
| Ollama | Install locally, run `ollama serve`, pull a code model, set `ASENT_OLLAMA_MODEL` before starting ASENT | Unavailable/disabled; deterministic SATRA core passed |
| bpftrace / Semgrep | Capability detection only | No eBPF or Semgrep analysis claimed |

Exact commands for every unavailable external path: [external-tool-checks.md](docs/external-tool-checks.md).

Container runs use network isolation, bounded resources, no host credentials, limited mounts, and disposable directories. Build the image before running cases when a container engine is installed; a missing image yields unavailable evidence, not silent fallback for unknown code. CAVR's container trace requires SYS_PTRACE, while other capabilities are dropped. Container execution itself is not a proof of arbitrary-code safety.

Without a usable container, only the shipped hash-pinned inert Python sources, known test configuration and known PDF fixture execute in a temporary subprocess with sanitized environment, memory/CPU/time/file limits and Python audit restrictions. Native additions and modified code are refused. When strace cannot operate, the inert canary demonstration uses **actual Python audit events** plus receiver observations, labeled **PINNED_INERT_LAB_PYTHON_AUDIT**. This observes selected Python APIs, not kernel syscalls. The fallback is never described as a hostile-code sandbox. Do not regenerate the builtin source allowlist against an untrusted candidate.

Ollama output is untrusted: it must pass syntax/locality checks and baseline, mutation, repeatability and candidate execution. New generated Python requires the container backend. Ollama never decides ACCEPT. Its endpoint is fixed to localhost; no paid hosted inference is used.

## Advisories and freshness

The bundle includes the exact pypdf wheel and a genuine dated PyPI release/advisory JSON response. Its payload hash and artifact SHA-256 are checked. Live OSV POST/GET calls timed out on the validation host; this is visible as a dated PyPI advisory fallback, not a successful OSV scan. Refresh before presentation if the bundled response is older than the configured **30 days**:

```bash
.venv/bin/python scripts/refresh_advisories.py
```

The Threat Repository can import genuine saved OSV JSON or query OSV when reachable. Exact PyPI versions and bounded ECOSYSTEM ranges are evaluated; unsupported ranges retain uncertainty. An empty advisory response never proves absence of hidden behavior. Source records cite public URLs and retrieval metadata.

## Verification and limits

```bash
.venv/bin/python -m pytest -q --junitxml=reports/pytest.xml
npm --prefix frontend run build
```

**Executed: 59 pytest tests passed, 15 HTTP acceptance checks passed, and browser checks passed with no page errors.** See [acceptance audit](docs/acceptance-audit.md), `reports/pytest-output.txt`, `reports/pytest.xml`, `reports/scenario-validation.json`, and `reports/browser-validation.json`. The scenario report is historical evidence from real tests; it is not loaded into new runs. Screenshots are from the actual running application. The ZIP was extracted and its manifest hashes verified; a safe run from that extracted copy reached ACCEPT. The setup/start scripts were also executed with a fresh Python environment. The optional browser QA scripts use Playwright (install separately); set `ASENT_PLAYWRIGHT` to its absolute module path and run `scripts/qa/run-browser-check.py` on Linux.

Key limits: bounded AST discovery rather than symbolic execution; fake-marker equality rather than general taint tracking; no broad Python-framework verification; fixed ownership mutation family; no generic package/API migration; no universal Terraform policy engine; no cloud deployment; no established prevalence, research novelty, or superiority against strong baselines. Unsupported cases stay UNRESOLVED/INCONCLUSIVE/UNKNOWN. Scope notes travel with each evidence record.

## Troubleshooting

- **Safe run is REVIEW:** inspect module reasons. Expired/missing advisory data, unavailable execution, modified builtin source or missing policy/SRS authority are explicit causes. Do not bypass the gate.
- **Container engine exists but tests fail:** build `asent-sandbox:local`; inspect stored stderr and JUnit. Rootless/SELinux mount permissions may need local configuration; these hosts were not tested.
- **strace is installed but denied:** the capability panel reports the error. Run the pinned inert audit mode or use a suitably configured local Linux container.
- **No frontend:** ensure `frontend/dist/index.html` exists, build the frontend, then restart the backend. Use Node 20+.
- **Code edited in the demo but native fallback refuses it:** use the container backend. The allowlist is a safety boundary, not an error to suppress.
- **Threat rule disabled:** re-enable the required rule and choose Reverify. Re-enabling does not resurrect old evidence automatically.
- **Source labels:** normal safe, live workspace, recorded, research and controlled reproduction are separate. None of the built-in cases claims that Claude or another agent selected a malicious package.

[Design-source mapping](docs/implementation-notes.md) records the supplied document authority and implementation choices. [API guide](docs/api.md) describes local integration endpoints.

---

## CAVR Deep Research Pipeline (P1 to P13)

The upgraded Continuous Artifact Verification & Runtime (CAVR) engine implements the full 13-phase pipeline mapped to the 8 interactive timeline steps:

### Pipeline Phases Mapping:
1. **P1: Capture (Timeline Step 1)**: Intercepts agent `pip install` commands at the local PEP 503 proxy (`/simple/`) before execution or host filesystem modification.
2. **P2: Requirement Gate (Timeline Step 2)**: Evaluates `project_policy.json` rules, project allowlists, and explicit denylists. Rejects unauthorized packages with immediate rule justifications.
3. **P3: Context Extraction (Timeline Step 5)**: Uses Python AST to inspect the project workspace (`sample_project/invoice_extractor`), extracting API call sites (`PdfReader`, `extract_text`), imports, and Git diffs.
4. **P4: Capability Contract Inference (Timeline Step 5)**: Deterministically maps call sites to capability vocabulary (`FILE_READ(scope)`, `FILE_WRITE(scope)`, `NETWORK_CONNECT(scope)`, `PROCESS_EXEC`, `SECRET_READ`, `PERSISTENCE_WRITE`, `NATIVE_EXEC`) with confidence scores.
5. **P5: Package Resolution & Transitive Tree (Timeline Step 3)**: Pins SHA-256 digests, builds full transitive dependency DAGs (`nodes` and `edges`), and queries the bundled offline OSV database snapshot.
6. **P6: Trigger Discovery (Timeline Step 5)**: AST visitor identifies security-relevant predicates (`os.getenv`, `os.path.exists`, `socket.gethostname`, `platform`, `time`, CI flags), traces reachability to sensitive sinks, and computes priority:
   $$\text{priority} = \frac{\text{sink\_risk} \times \text{reachability\_confidence} \times \text{novelty}}{\text{estimated\_run\_cost}}$$
7. **P7: Adaptive Counterfactual Activation (Timeline Step 6)**: Runs a multi-run frontier loop. Run 0 tests baseline execution; subsequent runs synthesize targeted fake credentials (`~/.aws/credentials`, `AWS_SECRET_ACCESS_KEY`), fake files, or time shims inside disposable containers (`asent-sandbox`).
8. **P8: OS Observation & Normalization (Timeline Step 6)**: Normalizes Python runtime audit hooks (`sys.addaudithook`) and syscall traces into semantic actions (`SECRET_ACCESS`, `NETWORK_CONNECT`, `FILE_WRITE`). Honestly records observation methods and eBPF limitations.
9. **P9: Causal Capability Graph & Policy (Timeline Step 7)**: Builds a NetworkX directed graph tracking source-to-sink paths (e.g. `canary -> secret_access -> network_send`). Maps observations to 4 policy states: `VERIFIED` (ALLOW), `RESTRICTED` (ALLOW with restrictions), `UNRESOLVED` (NEEDS_REVIEW fail closed), and `REJECTED` (BLOCK).
10. **P10: Minimal Safe Repair (Timeline Step 7)**: Weighted search across 4 repair levels (safe patch, safe parent/transitive, direct upgrade, supported replacement) minimizing disruption objective:
    $$\text{Cost} = w_1 \cdot (\text{deps}) + w_2 \cdot (\text{version distance}) + w_3 \cdot (\text{call sites}) + w_4 \cdot (\text{new risk})$$
    Requires explicit human operator approval.
11. **P11: Candidate Re-Verification (Timeline Step 7)**: Re-executes sample project unit tests and security obligations for chosen substitutes inside fresh containers.
12. **P12: Clean Reconstruction (Timeline Step 8)**: Discards all analysis sandboxes and reconstructs production environments from clean baseline digests plus pinned hashes.
13. **P13: Assurance Evidence Ledger (Timeline Step 8)**: Hash-chains every transition record into a Merkle-linked evidence chain. Issues official JSON and printable HTML certificates with bounded trust claims.

---

## 5 Seeded Scenarios

CAVR includes 5 synthetic scenarios located in `backend/cavr/fixtures/scenarios.py`:

| # | Scenario | Package | Key Observation | Expected Decision |
|---|---|---|---|---|
| **1** | **Approved Benign** | `pdf-clean-extractor==1.0.0` | Clean memory-only parsing, conforms to contract | `ALLOW` (VERIFIED) |
| **2** | **Known Vulnerable** | `reportlab-legacy==3.5.21` | Matches CVE-2023-33733 in offline OSV mirror | `BLOCK` (REJECTED) |
| **3** | **Trigger-Dependent (Dormant)** | `dormant-exfil==1.2.0` | Clean in Run 0; awakens exfiltration under fake AWS key | `BLOCK` (REJECTED) |
| **4** | **Transitive Risk** | `invoice-utils==2.0.1` | Root looks clean; nested `sub-telemetry-hook` steals canary | `BLOCK` (REJECTED) |
| **5** | **Typosquat / Slopsquat** | `requests-security==2.31.0` | Homoglyph match on `requests`; credential read | `BLOCK` (REJECTED) |

### How to Run:
- **Interactive UI**: Navigate to the **CAVR** tab and click any of the 5 scenario chips above the workflow box (`Approved Benign`, `Known Vulnerable`, `Trigger-Dependent`, `Transitive Risk`, or `Typosquat`).
- **REST API / CLI**:
  ```bash
  # Launch scenario execution
  curl -X POST "http://127.0.0.1:8000/api/cavr/run?scenario=trigger_dependent"
  
  # Verify cryptographic hash chain for a run
  curl "http://127.0.0.1:8000/api/cavr/evidence/<RUN_ID>/verify"
  
  # Retrieve metrics
  curl "http://127.0.0.1:8000/api/cavr/metrics"
  ```

---

## SABLE Module — Infrastructure Security Boundary Assurance

### Core Problem Statement
Did the least-privilege boundary follow the data after the refactor?
> "Terraform got restructured. We check whether the role that was allowed to touch the customer-data bucket is still allowed on the same data, no more and no less."

SABLE evaluates a single registered obligation:
- **Obligation ID**: `S3-APPROLE-CUSTOMERDATA`
- **Principal**: `aws_iam_role.app`
- **Actions**: `[s3:GetObject, s3:PutObject]`
- **Protected Asset**: `aws_s3_bucket.customer_data`
- **Resource Scope**: `arn:aws:s3:::customer-data/*`
- **Authority Source**: Benchmark IAM policy document

### Non-Negotiables & Honest Controlled Claims
- **LLM in Decision Path**: **NONE**. Deterministic AST / HCL semantics. Zero cloud API calls, zero AWS accounts, fully functional with network unplugged.
- **Controlled Honest Wording**:
  - **PRESERVED**: *"Within the supported Terraform / AWS S3 / IAM model, this obligation remained preserved on the identified successor."* (ASENT: **ACCEPT**)
  - **REGRESSED**: *"Demonstrated security-boundary regression under the stated policy model."* (ASENT: **BLOCK**)
  - **UNKNOWN**: *"Evidence is insufficient or conflicting. This does not mean the change is safe."* (ASENT: **REVIEW**)
  - SABLE never claims infrastructure is *"secure"* or *"safe"*.
  - SABLE is not a scanner, not a repair engine, and not a Terraform replacement. Reviewers receive *"what to check"* guidance only.

### 8 Pipeline Steps (Phases)
1. **Step 1: AI Agent Proposes Terraform Change (Phase A & B / ASENT Routing)**: Detects `.tf` / `.tf.json` files and routes change to SABLE.
2. **Step 2: Capture Baseline and Candidate (Phase Capture & Diff)**: Computes SHA-256 for all baseline/candidate files and generates unified diff.
3. **Step 3: Normalize and Model (Phase Normalization & Obligation Model)**: Parses HCL with pinned `python-hcl2`, resolves locals, flattens module addresses, normalizes IAM policies (jsonencode, aws_iam_policy_document, attachments), and outputs a normalized resource graph.
4. **Step 4: Find Successors (Phase Correspondence)**: Generates successor hypotheses and computes bounded signal scores (moved blocks, attribute similarity, references, module position, policy relationships) with fixed thresholds (`confidence=6`, `margin=3`).
5. **Step 5: Project Obligation (Phase Projection)**: Projects baseline obligation onto surviving candidate hypotheses. Checks whether the correct successor has weaker/wider authorization or if a valid boundary is attached to the wrong asset.
6. **Step 6: Verify (Phase Authorization & Local Evidence Tools)**: Evaluates Allow/Deny, action wildcards, resource ARN matching, and runs offline evidence tools (Terraform validate, Checkov, Trivy) inside locked-down environments, marking fallbacks as *"built-in approximation, not the real tool"*.
7. **Step 7: Attribute (Phase Decision)**: Executes deterministic attribution logic:
   $$\text{if no\_unique\_successor or evidence\_conflicts} \to \text{UNKNOWN}$$
   $$\text{elif obligation\_holds(security, successor)} \to \text{PRESERVED}$$
   $$\text{else} \to \text{REGRESSED}$$
8. **Step 8: Report & Release / Review / Block (Phase Evidence)**: Emits SHA-256 hash-chained JSON evidence records and SARIF reports. Records reviewer decisions in `audit_log`.

### 33 Benchmark Scenarios & 6 Hard Cases
The fixture library includes 33 real scenarios covering rename/move into modules, splits, merges, replacements, parallel assets, policy rewrites, and 6 canonical hard cases:
1. `hard_legitimate_move` → **PRESERVED** (moved block + physical identity + updated policy).
2. `hard_module_split_ambiguous` → **UNKNOWN** (genuinely ambiguous split without moved metadata).
3. `hard_wrong_binding` → **REGRESSED** (boundary satisfies local policy but targets wrong logical asset).
4. `hard_privilege_widening` → **REGRESSED** (correct successor identified, but wildcard `s3:*` added).
5. `hard_conflicting_evidence` → **UNKNOWN** (moved block points to A, but physical identity points to B).
6. `policy_rewrite_wrong_target` → **REGRESSED** (rewritten policy targets different bucket).

### Baselines B0 to B4
- **B0**: Candidate-only policy check (no baseline comparison).
- **B1**: Before/after scan-result comparison.
- **B2**: Terraform plan / moved evidence only.
- **B3**: Graph correspondence without obligation projection.
- **B4**: Strongest reproducible combination of B0–B3 plus reference evidence. Labeled *"reduced-strength baseline"* if Checkov/Trivy are absent.

### 6 Real Ablations & 6 Kill Tests (K1–K6)
Configured in `backend/sable/sable_config.json`:
- **Ablations**:
  1. Remove explicit move evidence (`no_move_evidence`)
  2. Remove dependency & reference context (`no_dependency_context`)
  3. Remove policy-resource relationship evidence (`no_policy_relationship`)
  4. Force best match / remove ambiguity handling (`no_ambiguity_handling`)
  5. Correspondence without obligation projection (`no_obligation_projection`)
  6. Obligation checking without correspondence (`no_correspondence`)
- **Kill Tests (Pre-specified Falsification Criteria)**:
  - **K1**: Strong-baseline equivalence ($B_4$ vs SABLE false-safe rate delta $\le 0.05$)
  - **K2**: Address evidence suffices ($B_2$ hard case recall $< 0.60$)
  - **K3**: Attribution ambiguity exists (benchmark hard case fraction $\ge 0.10$)
  - **K4**: UNKNOWN escape hatch safety (hard-case UNKNOWN rate $\ge 0.50$ or FSR $\le 0.05$)
  - **K5**: Security predicate non-trivial ($B_0$ false-safe rate $> 0.15$)
  - **K6**: Execution feasibility (runtime $\le 60\text{s}$)

### Running SABLE Scenarios & Benchmark

#### Interactive Web UI
1. Navigate to the **SABLE** tab at `http://127.0.0.1:8000` (or Vite dev port `5173`).
2. Select any scenario chip or click **Upload bundle** to paste custom Terraform files.
3. Click **Run scenario** to stream the 8-step SSE pipeline live.
4. Inspect the 11 evidence tabs:
   - **Overview**: Decision, ASENT mapping, fired branch, uncertainties.
   - **Specification**: Problem statement, obligation table, requirements traceability matrix.
   - **Terraform Diff**: Side-by-side diff with moved blocks, unsupported constructs, and **In-Browser Candidate Editor** with **Run again**.
   - **Resource Graph**: Interactive SVG dependency graphs with obligation path.
   - **Correspondence**: Signal heatmaps, stacked score bars, and uniqueness gap margin.
   - **Projection**: Principal $\to$ Actions $\to$ Resource delta matrices.
   - **Verification**: Local tool findings (real vs approximation).
   - **Decision**: Pseudocode trace diagram and reviewer check guidance.
   - **Benchmark**: Grouped bar charts, confusion matrices, and per-scenario matrix.
   - **Ablations & Kill Tests**: Measured metric deltas and K1–K6 pass/fail cards.
   - **Evidence**: Hash chain verification, SARIF and JSON export.
5. In the **Proof Drawer**, click **Re-run to verify determinism** to verify bit-for-bit identical decision hashes.

#### REST API & CLI
```bash
# List all 33 scenarios
curl.exe -s http://127.0.0.1:8000/api/sable/scenarios

# Run a scenario (e.g. rename_with_moved)
python -c "import urllib.request, json; data = json.dumps({'scenario_id': 'rename_with_moved', 'obligation_id': 'S3-APPROLE-CUSTOMERDATA'}).encode(); req = urllib.request.Request('http://127.0.0.1:8000/api/sable/runs', data=data, headers={'Content-Type': 'application/json'}); res = urllib.request.urlopen(req); print(res.read().decode())"

# Verify execution determinism
curl.exe -X POST http://127.0.0.1:8000/api/sable/runs/<RUN_ID>/verify-determinism

# Verify evidence hash chain
curl.exe -s http://127.0.0.1:8000/api/sable/evidence/<RUN_ID>/verify

# Run full benchmark and get metrics, ablations, and kill tests
python -c "import urllib.request; req = urllib.request.Request('http://127.0.0.1:8000/api/sable/benchmark/run', data=b''); res = urllib.request.urlopen(req); [print(l.decode()) for l in res if 'benchmark.complete' in l.decode()]"

# Retrieve cached benchmark results
curl.exe -s http://127.0.0.1:8000/api/sable/benchmark/result

# Run ground truth import isolation test
.\.venv\Scripts\python.exe -m pytest tests/test_sable_isolation.py -v
```

