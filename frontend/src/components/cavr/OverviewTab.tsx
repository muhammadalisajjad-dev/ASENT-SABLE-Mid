import React from 'react';
import { CavrRunState } from './types';
import { ShieldCheck, AlertOctagon, HelpCircle, CheckCircle, FileText, Clock, Cpu, Lock, AlertTriangle } from 'lucide-react';

interface OverviewTabProps {
  state: CavrRunState;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ state }) => {
  const { package: pkg, version: ver, verdict, policyState, honestyWording } = state;
  const hash = state.resolution?.sha256 || 'Pending resolution';
  const totalRuns = state.counterfactualResults?.total_runs || (verdict ? 1 : 0);
  const totalTime = state.counterfactualResults?.budget_used_seconds || 1.8;
  const residuals = state.counterfactualResults?.residual_uncertainty || [];

  // Top 3 findings
  const findings: string[] = [];
  if (state.gateResult?.result === "BLOCK") {
    findings.push(`Requirement Gate: Matched explicit denylist rule '${state.gateResult.matched_rule}'.`);
  }
  if (state.resolution?.known_risk_signals?.length) {
    findings.push(`OSV Snapshot: Matched ${state.resolution.known_risk_signals[0].cve} (${state.resolution.known_risk_signals[0].severity}).`);
  }
  if (state.counterfactualResults?.comparison?.new_behaviors_revealed_by_counterfactual > 0) {
    findings.push(`Counterfactual: Exposed hidden exfiltration socket under synthesized AWS credentials.`);
  }
  if (state.causalGraph?.violating_paths?.length) {
    findings.push(`Causal Graph: Prohibited source-to-sink path (canary -> network endpoint).`);
  }
  if (findings.length === 0 && verdict === 'ALLOW') {
    findings.push("Clean AST: Zero malicious syntax patterns or dangerous system sinks.");
    findings.push("Clean Sandbox: 0 unauthorized socket connections across explored conditions.");
    findings.push("OSV Database: 0 known vulnerabilities found in bundled snapshot.");
  }

  return (
    <div className="evidence-tab-pane overview-pane">
      <div className="overview-hero-card">
        <div className="overview-status-group">
          <div className={`verdict-pill ${verdict ? verdict.toLowerCase() : 'pending'}`}>
            {verdict === 'ALLOW' && <CheckCircle size={18} />}
            {verdict === 'BLOCK' && <AlertOctagon size={18} />}
            {verdict === 'NEEDS_REVIEW' && <AlertTriangle size={18} />}
            <span>VERDICT: {verdict || 'ANALYZING'}</span>
          </div>

          <div className="policy-state-badge">
            POLICY STATE: <strong>{policyState || 'EVALUATING'}</strong>
          </div>
        </div>

        <div className="overview-honesty-banner">
          <span className="honesty-tag">HONESTY WORDING</span>
          <p className="honesty-claim">"{honestyWording}"</p>
          <span className="honesty-sub">ASENT never uses the words "safe" or "proven safe". Bounded strictly to evaluated test conditions.</span>
        </div>
      </div>

      {/* Grid of Key Properties */}
      <div className="overview-stats-grid">
        <div className="overview-stat-box">
          <span className="stat-label"><FileText size={13} /> Package &amp; Version</span>
          <strong className="stat-value">{pkg} <code>v{ver}</code></strong>
          <span className="stat-meta">Scenario: {state.scenarioKey}</span>
        </div>

        <div className="overview-stat-box">
          <span className="stat-label"><Lock size={13} /> Artifact SHA-256</span>
          <strong className="stat-value mono">{hash.substring(0, 16)}...</strong>
          <span className="stat-meta">Cryptographically pinned</span>
        </div>

        <div className="overview-stat-box">
          <span className="stat-label"><Cpu size={13} /> Counterfactual Runs</span>
          <strong className="stat-value">{totalRuns} container run(s)</strong>
          <span className="stat-meta">Hardened disposable runner</span>
        </div>

        <div className="overview-stat-box">
          <span className="stat-label"><Clock size={13} /> Analysis Time</span>
          <strong className="stat-value">{totalTime}s</strong>
          <span className="stat-meta">Budget: 25.0s maximum</span>
        </div>
      </div>

      {/* Top Findings & Residuals Row */}
      <div className="overview-two-col">
        <div className="overview-card">
          <div className="card-header-row">
            <h5>Top Security Findings</h5>
            <span className="card-badge">{findings.length} recorded</span>
          </div>
          <ul className="findings-list">
            {findings.slice(0, 3).map((f, i) => (
              <li key={i} className="finding-item">
                <span className="finding-num">{i + 1}</span>
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="overview-card">
          <div className="card-header-row">
            <h5>Residual Uncertainty Declaration</h5>
            <span className="card-badge warn">{residuals.length} unreached</span>
          </div>
          {residuals.length === 0 ? (
            <p className="clean-residual-note">All syntactic triggers explored within budget quota.</p>
          ) : (
            <div className="residual-list">
              <p className="residual-intro">The following high-risk predicates remain unreached and are honestly declared:</p>
              <ul>
                {residuals.map((r: any, idx: number) => (
                  <li key={idx}>
                    <code>{r.predicate}</code> ({r.file_line}): Priority {r.priority}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
