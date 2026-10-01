import React from 'react';
import { SableRunState } from '../types';
import { Target } from 'lucide-react';

interface Props { runState: SableRunState; explainSimply: boolean; }

const SIGNAL_COLORS: Record<string, string> = {
  'explicit moved block': '#7c3aed',
  'unchanged address': '#2563eb',
  'physical bucket identity': '#0891b2',
  'stable Asset attribute': '#059669',
  'lifecycle role': '#84cc16',
  'same exported application reference': '#f59e0b',
  'module output preserves application reference': '#ea580c',
  'resource type': '#6b7280',
};

export const CorrespondenceTab: React.FC<Props> = ({ runState, explainSimply }) => {
  const { hypotheses, conflicts, successor, correspondenceReason } = runState;

  if (hypotheses.length === 0) {
    return (
      <div className="sable-tab-empty">
        <Target size={32} strokeWidth={1.2}/>
        <p>Run a scenario to see correspondence scoring.</p>
      </div>
    );
  }

  const maxScore = Math.max(...hypotheses.map(h => h.score), 1);
  const threshold = 6;
  const margin = 3;
  const winner = hypotheses[0];
  const runner_up = hypotheses[1];
  const uniquenessGap = runner_up ? winner.score - runner_up.score : winner.score;

  return (
    <div className="sable-tab-content">
      {conflicts.length > 0 && (
        <div className="sable-corr-conflicts">
          <strong>⚠ Conflicts detected:</strong>
          {conflicts.map((c, i) => <div key={i}>{c}</div>)}
        </div>
      )}

      {/* Threshold indicators */}
      <div className="sable-corr-thresholds">
        <span>Confidence threshold: <code>{threshold}</code></span>
        <span>Uniqueness margin: <code>{margin}</code></span>
        <span>Winner score: <code>{winner.score}</code></span>
        <span>Uniqueness gap: <code style={{ color: uniquenessGap >= margin ? '#16a34a' : '#dc2626' }}>{uniquenessGap}</code></span>
      </div>

      {/* Hypothesis heatmap bars */}
      <div className="sable-hyp-list">
        {hypotheses.slice(0, 8).map((hyp, i) => {
          const isChosen = hyp.address === successor;
          const pct = (hyp.score / maxScore) * 100;
          return (
            <div key={hyp.address} className={`sable-hyp-card ${isChosen ? 'chosen' : ''}`}>
              <div className="sable-hyp-header">
                <code className="sable-hyp-addr">{hyp.address}</code>
                <span className="sable-hyp-score">{hyp.score} pts</span>
                {isChosen && <span className="sable-hyp-winner">✓ Chosen</span>}
              </div>

              {/* Stacked bar */}
              <div className="sable-hyp-bar-container">
                <div className="sable-hyp-bar" style={{ width: `${pct}%` }}>
                  {hyp.signals.map((sig, j) => {
                    const sigPct = (sig.weight / hyp.score) * 100;
                    return (
                      <div key={j} className="sable-hyp-bar-segment"
                        style={{ width: `${sigPct}%`, background: SIGNAL_COLORS[sig.signal] ?? '#94a3b8' }}
                        title={`${sig.signal}: +${sig.weight}`}
                      />
                    );
                  })}
                </div>
                {/* Threshold line */}
                <div className="sable-threshold-line" style={{ left: `${(threshold / maxScore) * 100}%` }}
                  title={`Confidence threshold: ${threshold}`}/>
              </div>

              {/* Signals */}
              <div className="sable-hyp-signals">
                {hyp.signals.map((sig, j) => (
                  <span key={j} className="sable-signal-chip"
                    style={{ borderColor: SIGNAL_COLORS[sig.signal] ?? '#94a3b8', color: SIGNAL_COLORS[sig.signal] ?? '#94a3b8' }}>
                    {sig.signal} +{sig.weight}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <div className="sable-corr-decision">
        <strong>Correspondence decision:</strong>{' '}
        {successor ? (
          <span>Unique winner: <code>{successor}</code> — {correspondenceReason}</span>
        ) : (
          <span className="sable-corr-no-winner">No unique winner — {correspondenceReason}</span>
        )}
      </div>

      {explainSimply && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong> Each bar shows how much evidence points to a particular
          bucket being the logical successor. The taller the bar, the stronger the case. If two bars
          are too close, SABLE says it cannot decide.
        </div>
      )}
    </div>
  );
};
