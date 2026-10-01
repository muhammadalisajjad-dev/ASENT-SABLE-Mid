import React, { useState } from 'react';
import { CavrRunState } from './types';
import { Crosshair, Play, Eye, Code2, AlertTriangle, Layers } from 'lucide-react';

interface TriggersTabProps {
  state: CavrRunState;
}

export const TriggersTab: React.FC<TriggersTabProps> = ({ state }) => {
  const triggersInfo = state.actionData?.triggers_info || {
    ranked_triggers: [],
    frontier: { explored: [], in_progress: null, unexplored: [] }
  };

  const triggers = triggersInfo.ranked_triggers || [];
  const [selectedTriggerId, setSelectedTriggerId] = useState<string | null>(triggers[0]?.id || null);

  const selectedTrigger = triggers.find((t: any) => t.id === selectedTriggerId) || triggers[0];

  const frontier = triggersInfo.frontier || { explored: [], in_progress: null, unexplored: [] };

  return (
    <div className="evidence-tab-pane triggers-pane">
      <div className="tab-intro-card">
        <div>
          <h5>Discovered Trigger Predicates &amp; Priority Ranking</h5>
          <p>Security-relevant predicates detected by AST inspection gating sensitive sinks (os.getenv, os.path.exists, etc.).</p>
        </div>
        <div className="formula-pill">
          <code>priority = (sink_risk × reachability_confidence × novelty) / estimated_run_cost</code>
        </div>
      </div>

      {triggers.length === 0 ? (
        <div className="empty-tab-state">
          <Crosshair size={32} className="text-gray-500" />
          <p>No gated environmental triggers detected in this package. AST inspection found pure linear logic.</p>
        </div>
      ) : (
        <div className="triggers-layout-grid">
          {/* Left: Ranked Bar Chart */}
          <div className="triggers-chart-card">
            <div className="chart-header">
              <h6>Ranked Trigger Priority Chart</h6>
              <span className="count-tag">{triggers.length} detected</span>
            </div>

            <div className="bars-list">
              {triggers.map((trig: any) => {
                const isSelected = trig.id === (selectedTrigger?.id);
                const score = trig.priority || 0;
                const maxScore = Math.max(...triggers.map((t: any) => t.priority || 1), 10);
                const pct = Math.min((score / maxScore) * 100, 100);

                return (
                  <div 
                    key={trig.id} 
                    className={`trigger-bar-row ${isSelected ? 'selected' : ''}`}
                    onClick={() => setSelectedTriggerId(trig.id)}
                  >
                    <div className="bar-meta-col">
                      <span className="bar-pred-text"><code>{trig.predicate}</code></span>
                      <span className="bar-file-text">{trig.file_line}</span>
                    </div>

                    <div className="bar-track-col">
                      <div className="bar-track">
                        <div 
                          className="bar-fill" 
                          style={{ width: `${pct}%`, background: score > 6 ? '#ef4444' : (score > 3 ? '#f59e0b' : '#38bdf8') }}
                        />
                      </div>
                      <span className="bar-score-num">{score}</span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Frontier Queue */}
            <div className="frontier-queue-box">
              <div className="frontier-title">
                <Layers size={13} /> <strong>Adaptive Exploration Frontier Queue:</strong>
              </div>
              <div className="frontier-badges">
                <span className="queue-chip explored">
                  Explored: {triggers.length > 0 ? (state.counterfactualResults?.total_runs ? Math.min(state.counterfactualResults.total_runs - 1, triggers.length) : 0) : 0}
                </span>
                <span className="queue-chip active">
                  Active Run: {state.counterfactualResults ? "Idle / Complete" : "Evaluating"}
                </span>
                <span className="queue-chip unexplored">
                  Unexplored: {state.counterfactualResults?.residual_count || 0}
                </span>
              </div>
            </div>
          </div>

          {/* Right: Selected Trigger Detail & Formula Factors */}
          {selectedTrigger && (
            <div className="trigger-detail-card">
              <div className="detail-header-row">
                <div>
                  <span className="detail-kind-pill">{selectedTrigger.kind}</span>
                  <h6>{selectedTrigger.predicate}</h6>
                </div>
                <div className="priority-badge">
                  <span>Score:</span>
                  <strong>{selectedTrigger.priority}</strong>
                </div>
              </div>

              {/* Formula Factors Breakdown */}
              <div className="factors-row">
                <div className="factor-box">
                  <span className="factor-k">Sink Risk</span>
                  <span className="factor-v red">{selectedTrigger.formula?.sink_risk || 9.5} / 10</span>
                </div>
                <div className="factor-box">
                  <span className="factor-k">Confidence</span>
                  <span className="factor-v">{int((selectedTrigger.formula?.reachability_confidence || 0.95) * 100)}%</span>
                </div>
                <div className="factor-box">
                  <span className="factor-k">Novelty</span>
                  <span className="factor-v">{selectedTrigger.formula?.novelty || 1.0}</span>
                </div>
                <div className="factor-box">
                  <span className="factor-k">Run Cost</span>
                  <span className="factor-v">{selectedTrigger.formula?.estimated_run_cost || 1.2}s</span>
                </div>
              </div>

              {/* Sink Reached */}
              <div className="sink-reached-box">
                <span className="sink-label">Sensitive Sink Reached:</span>
                <code>{selectedTrigger.sink_reached}</code>
              </div>

              {/* Code Snippet with Highlight */}
              <div className="snippet-container">
                <div className="snippet-topbar">
                  <Code2 size={13} />
                  <span>{selectedTrigger.file_line}</span>
                </div>
                <pre className="snippet-code">
                  <code>{selectedTrigger.code_snippet}</code>
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

function int(val: number) {
  return Math.round(val);
}
