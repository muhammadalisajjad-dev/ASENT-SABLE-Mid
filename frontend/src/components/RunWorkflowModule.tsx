import React, { useState, useEffect } from 'react';
import { 
  LockKeyhole, ShieldCheck, RefreshCw, Play, Package, Network, 
  ShieldAlert, GitCommit, CheckCircle2, XCircle, AlertTriangle, Download 
} from 'lucide-react';

interface Scenario {
  id: string;
  title: string;
  subtitle: string;
  source: string;
}

export const RunWorkflowModule: React.FC = () => {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('safe');
  const [currentRun, setCurrentRun] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    fetch('/api/scenarios')
      .then((r) => r.json())
      .then((data) => setScenarios(data))
      .catch((e) => console.error(e));

    fetch('/api/runs')
      .then((r) => r.json())
      .then((runs) => {
        if (runs && runs.length > 0) {
          setCurrentRun(runs[0]);
        }
      })
      .catch((e) => console.error(e));
  }, []);

  const triggerRun = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: selectedScenario,
          mode: 'manual'
        })
      });
      if (res.ok) {
        const run = await res.json();
        setCurrentRun(run);
        pollRun(run.run_id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const pollRun = (runId: string) => {
    let count = 0;
    const interval = setInterval(async () => {
      count++;
      try {
        const [rRes, evRes] = await Promise.all([
          fetch(`/api/runs/${runId}`),
          fetch(`/api/runs/${runId}/events`)
        ]);
        if (rRes.ok) {
          const runData = await rRes.json();
          setCurrentRun(runData);
          if (runData.lifecycle === 'COMPLETED' || count > 20) {
            clearInterval(interval);
          }
        }
        if (evRes.ok) {
          const evData = await evRes.json();
          setEvents(evData);
        }
      } catch (e) {
        clearInterval(interval);
      }
    }, 1500);
  };

  const decision = currentRun?.final_decision || 'ACCEPT';
  const isAccept = decision === 'ACCEPT';
  const isBlock = decision === 'BLOCK';

  return (
    <div className="workflow-module-container">
      <div className="cavr-header-row">
        <div>
          <div className="cavr-eyebrow">
            <span className="module-pulse-dot" /> AGENT SENTINEL GATEWAY · END-TO-END ASSURANCE AGGREGATOR
          </div>
          <h2 className="cavr-title">RUN WORKFLOW</h2>
          <p className="cavr-subtitle">
            Autonomous AI-change security assurance gate. Aggregates multi-boundary evidence from 
            CAVR (package dependencies), SABLE (Terraform boundaries), and SATRA (security-test integrity) 
            into one final trust decision: <strong>ACCEPT</strong>, <strong>REVIEW</strong>, or <strong>BLOCK</strong>.
          </p>
        </div>
      </div>

      <div className="workflow-top-controls">
        <div className="scenario-select-wrap">
          <label>Select Candidate AI-Change Scenario:</label>
          <select 
            value={selectedScenario} 
            onChange={(e) => setSelectedScenario(e.target.value)}
            disabled={loading}
          >
            {scenarios.map((s) => (
              <option key={s.id} value={s.id}>
                {s.title} ({s.id})
              </option>
            ))}
          </select>
        </div>

        <button 
          className="run-scenario-btn" 
          onClick={triggerRun}
          disabled={loading}
        >
          {loading ? <RefreshCw className="spin" size={16} /> : <Play size={16} />}
          <span>{loading ? 'Evaluating Boundaries...' : 'Execute Assurance Workflow'}</span>
        </button>
      </div>

      {/* Aggregate Decision Banner */}
      <div className={`workflow-decision-banner ${decision.toLowerCase()}`}>
        <div className="gate-icon-col">
          {isAccept ? <ShieldCheck size={48} className="text-good" /> : isBlock ? <XCircle size={48} className="text-bad" /> : <AlertTriangle size={48} className="text-warn" />}
        </div>
        <div className="gate-details-col">
          <span className="gate-tag">FINAL ASENT DECISION</span>
          <h3 className="gate-verdict">{decision}</h3>
          <p className="gate-reason">
            {currentRun?.reasons?.join(' · ') || 'Candidate state evaluated deterministically against independent safety criteria.'}
          </p>
        </div>
        <div className="gate-meta-col">
          <span>Run ID: <code>{currentRun?.run_id || 'safe-baseline'}</code></span>
          <span>Snapshot: <code>{currentRun?.candidate_snapshot?.slice(0, 16) || 'a1b2c3d4e5f6'}...</code></span>
          {currentRun?.clean_commit && (
            <span className="clean-commit-tag">
              <GitCommit size={12} /> Git Commit Reconstructed
            </span>
          )}
        </div>
      </div>

      {/* Tri-Boundary Cards */}
      <div className="tri-boundary-grid">
        <div className="boundary-card">
          <div className="b-header">
            <span className="b-icon blue"><Package size={16} /></span>
            <strong>CAVR GATE</strong>
            <span className={`badge ${isBlock ? 'bad' : 'good'}`}>
              {isBlock ? 'REJECTED' : 'VERIFIED'}
            </span>
          </div>
          <p>Locked package dependencies, AST static inspection &amp; hostile sandbox proof.</p>
          <div className="b-meta">Policy: Pinned strict SHA-256</div>
        </div>

        <div className="boundary-card">
          <div className="b-header">
            <span className="b-icon green"><Network size={16} /></span>
            <strong>SABLE GATE</strong>
            <span className={`badge ${selectedScenario.includes('sable_regressed') || selectedScenario.includes('sable_widened') ? 'bad' : 'good'}`}>
              {selectedScenario.includes('sable_regressed') || selectedScenario.includes('sable_widened') ? 'REGRESSED → BLOCK' : 'PRESERVED → ACCEPT'}
            </span>
          </div>
          <p>Terraform cloud resources &amp; least-privilege IAM boundary attribution.</p>
          <div className="b-meta">Obligation: S3-APPROLE-CUSTOMERDATA</div>
        </div>

        <div className="boundary-card">
          <div className="b-header">
            <span className="b-icon violet"><ShieldAlert size={16} /></span>
            <strong>SATRA GATE</strong>
            <span className={`badge ${selectedScenario.includes('satra_weak') || selectedScenario.includes('satra_bypass') ? 'bad' : 'good'}`}>
              {selectedScenario.includes('satra_weak') || selectedScenario.includes('satra_bypass') ? 'ORACLE_WEAKENED' : 'ACCEPT'}
            </span>
          </div>
          <p>Security-test integrity, mutation analysis &amp; runtime contract obligations.</p>
          <div className="b-meta">Differential oracle runner</div>
        </div>
      </div>
    </div>
  );
};
