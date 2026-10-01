import React from 'react';
import { CavrRunState } from './types';
import { Shield, Info, ArrowRight, CheckCircle2, AlertTriangle, XCircle, Search } from 'lucide-react';

interface StageDetailPanelProps {
  state: CavrRunState;
}

export const StageDetailPanel: React.FC<StageDetailPanelProps> = ({ state }) => {
  const { stepIndex, explainSimply, package: pkgName, version: pkgVer, verdict, policyState } = state;

  const stageDescriptions = [
    {
      title: "Step 1: Capture (P1 Intercept)",
      what: `AI coding agent attempted 'pip install ${pkgName}==${pkgVer}'. ASENT local proxy intercepted request before execution.`,
      why: "Preventing untrusted packages from running setup.py hooks or modifying the host operating system.",
      evidence: state.gateResult ? `Intercepted command targeting local PEP 503 proxy at port 8000.` : "Awaiting agent command interception.",
      next: "Evaluate against project requirement policy (P2 Requirement Gate)."
    },
    {
      title: "Step 2: Requirement Gate (P2 Gate)",
      what: state.gateResult 
        ? `Evaluated project_policy.json rule: ${state.gateResult.rule_checked} -> ${state.gateResult.result}.` 
        : "Checking project allowlist and denylist constraints.",
      why: "Ensuring all dependencies strictly match authorized requirements before dispatching to sandbox.",
      evidence: state.gateResult?.reason || "Pending policy evaluation.",
      next: state.gateResult?.result === "BLOCK" 
        ? "Package flagged on explicit denylist. Proceeding with forensic inspection and alternative repair."
        : "Quarantine artifact in read-only sandbox directory (P5 Resolution)."
    },
    {
      title: "Step 3: Quarantine & Transitive Resolution (P5)",
      what: state.resolution 
        ? `Quarantined artifact sha256:${state.resolution.sha256?.substring(0, 16)}... Built transitive tree (${state.resolution.tree?.nodes?.length || 1} packages).`
        : "Locked package into read-only isolation.",
      why: "Preventing filesystem alterations while analyzing the entire dependency DAG against the offline OSV database.",
      evidence: state.resolution?.known_risk_signals?.length 
        ? `Found ${state.resolution.known_risk_signals.length} vulnerability advisory in offline OSV snapshot (${state.resolution.known_risk_signals[0].cve}).`
        : "No known CVE matches in offline OSV snapshot.",
      next: "Check package against SQLite trusted cache store."
    },
    {
      title: "Step 4: Cache Verification (Cache Check)",
      what: state.cacheResult?.result === "HIT"
        ? "Pre-verified cache HIT! Cryptographic hash matches trusted database."
        : (state.cacheResult?.result === "HASH_MISMATCH" ? "HASH MISMATCH! Artifact bytes altered." : "Cache MISS: Package not previously verified."),
      why: "Fast-tracking known safe packages to save analysis budget while quarantining modified binaries.",
      evidence: state.cacheResult?.result === "HIT" 
        ? "Exact match in trusted_packages SQLite table." 
        : (state.cacheResult?.reason || "Proceeding to deep analysis."),
      next: state.cacheResult?.result === "HIT" ? "Release directly to agent environment." : "Dispatch to Static AST Action (P3, P4, P6)."
    },
    {
      title: "Step 5: Static Action Inspection (P3, P4, P6)",
      what: state.actionData
        ? `Inferred capability contract (${state.actionData.capability_contract?.summary?.required_count} required, ${state.actionData.capability_contract?.summary?.denied_count} denied). Discovered ${state.actionData.triggers_info?.total_triggers} environment predicates.`
        : "Analyzing Python AST syntax tree, sinks, and capability contracts.",
      why: "Deriving deterministic capabilities from real project call sites before running dynamic tests.",
      evidence: state.actionData?.triggers_info?.ranked_triggers?.length
        ? `Top trigger: ${state.actionData.triggers_info.ranked_triggers[0].predicate} (Priority Score: ${state.actionData.triggers_info.ranked_triggers[0].priority})`
        : "Zero dangerous AST sinks detected.",
      next: "Execute multi-run adaptive counterfactual exploration in hardened sandbox (P7, P8)."
    },
    {
      title: "Step 6: Hostile Environment Testing (P7, P8)",
      what: state.counterfactualResults
        ? `Completed ${state.counterfactualResults.total_runs} container runs. Stop reason: ${state.counterfactualResults.stop_reason}`
        : "Running adaptive counterfactual frontier loop in isolated container.",
      why: "Dormant malware evades single-run sandboxes by waiting for specific credentials or environment variables.",
      evidence: state.counterfactualResults?.comparison?.new_behaviors_revealed_by_counterfactual > 0
        ? `Counterfactual activation exposed ${state.counterfactualResults.comparison.new_behaviors_revealed_by_counterfactual} hidden behavior(s) invisible to baseline run!`
        : "Behavior remained stable and clean across synthesized conditions.",
      next: "Construct NetworkX causal capability graph and evaluate deterministic policy (P9)."
    },
    {
      title: "Step 7: Deterministic Verdict & Repair (P9, P10, P11)",
      what: verdict 
        ? `Assurance Gate Verdict: ${verdict} (Policy: ${policyState || 'EVALUATED'}).`
        : "Evaluating causal graph source-to-sink paths against capability contract.",
      why: "Applying fail-closed security rules: unauthorized network connects or credential accesses result in REJECTED.",
      evidence: state.repair?.chosen_candidate 
        ? `Minimal repair identified: ${state.repair.chosen_candidate.name}==${state.repair.chosen_candidate.version} (${state.repair.chosen_candidate.level_name}).`
        : (state.honestyWording || "Evaluation complete."),
      next: verdict === "ALLOW" ? "Clean reconstruction and release (P12, P13)." : "Awaiting human operator approval for repair substitute."
    },
    {
      title: "Step 8: Clean Reconstruction & Assurance (P12, P13)",
      what: state.reconstruction
        ? `Production environment reconstructed from clean baseline (${state.reconstruction.baseline_digest?.substring(0, 20)}...). Sandbox discarded.`
        : "Generating tamper-evident cryptographic hash chain and assurance certificate.",
      why: "Ensuring analysis sandboxes are never reused, and all evidence is cryptographically provable.",
      evidence: state.certificate 
        ? `Certificate ${state.certificate.certificate_id} issued. Root digest: ${state.certificate.evidence_chain_root?.substring(0, 16)}...`
        : "Ledger hash chain complete.",
      next: "Workflow finalized. Production environment secured."
    }
  ];

  const current = stageDescriptions[Math.min(stepIndex, stageDescriptions.length - 1)];

  return (
    <div className="stage-detail-panel">
      <div className="stage-detail-header">
        <div className="stage-title-wrap">
          <span className="stage-badge">ACTIVE STAGE REASONING</span>
          <h4>{current.title}</h4>
        </div>
        <div className="stage-status-indicator">
          {verdict === 'ALLOW' && <span className="status-chip good"><CheckCircle2 size={13} /> {state.honestyWording}</span>}
          {verdict === 'BLOCK' && <span className="status-chip bad"><XCircle size={13} /> Policy Violation Detected</span>}
          {verdict === 'NEEDS_REVIEW' && <span className="status-chip warn"><AlertTriangle size={13} /> Review Required (Fail Closed)</span>}
          {!verdict && <span className="status-chip neutral"><Search size={13} /> Stage in progress</span>}
        </div>
      </div>

      <div className="stage-grid">
        <div className="stage-col">
          <span className="col-label">WHAT IS HAPPENING</span>
          <p>{explainSimply ? state.currentPlainMessage : current.what}</p>
        </div>
        <div className="stage-col">
          <span className="col-label">WHY THIS MATTERS</span>
          <p>{explainSimply ? "We verify the code so no backdoors or data thieves get into your app." : current.why}</p>
        </div>
        <div className="stage-col">
          <span className="col-label">EVIDENCE FOUND</span>
          <p className="evidence-text">{current.evidence}</p>
        </div>
        <div className="stage-col">
          <span className="col-label">WHAT HAPPENS NEXT</span>
          <p>{current.next}</p>
        </div>
      </div>
    </div>
  );
};
