import React from 'react';
import { SableRunState } from '../types';
import { ArrowRight, Layers } from 'lucide-react';

interface Props { runState: SableRunState; explainSimply: boolean; }

function ActionMatrix({ label, actions, resource, color }: { label: string; actions: string[]; resource: string; color: string }) {
  return (
    <div className="sable-proj-col">
      <div className="sable-proj-col-header" style={{ borderColor: color }}>
        <div className="sable-proj-col-label">{label}</div>
        <div className="sable-proj-col-resource"><code>{resource || '–'}</code></div>
      </div>
      <div className="sable-proj-actions">
        {actions.length > 0 ? actions.map((a, i) => (
          <div key={i} className="sable-proj-action" style={{ background: `${color}18`, color }}>
            {a}
          </div>
        )) : <div className="sable-proj-no-actions">No grants</div>}
      </div>
    </div>
  );
}

export const ProjectionTab: React.FC<Props> = ({ runState, explainSimply }) => {
  const { baselineAuth, candidateAuth, obligation, successor } = runState;

  if (!baselineAuth && !candidateAuth) {
    return (
      <div className="sable-tab-empty">
        <Layers size={32} strokeWidth={1.2}/>
        <p>Run a scenario to see the obligation projection.</p>
      </div>
    );
  }

  const baselineActions = baselineAuth?.actual_actions ?? obligation?.actions ?? [];
  const candidateActions = candidateAuth?.actual_actions ?? [];
  const requiredActions = obligation?.actions ?? [];

  const kept = candidateActions.filter(a => requiredActions.includes(a) && baselineActions.includes(a));
  const widening = candidateAuth?.widening ?? [];
  const weakening = candidateAuth?.weakening ?? [];
  const misbinding = candidateAuth?.misbinding ?? [];

  return (
    <div className="sable-tab-content">
      {/* Principal → Actions → Resource diagram */}
      <div className="sable-proj-diagram">
        <div className="sable-proj-entity">
          <div className="sable-proj-entity-label">PRINCIPAL</div>
          <code>{obligation?.principal ?? '–'}</code>
        </div>
        <ArrowRight size={20} color="#94a3b8"/>
        <div className="sable-proj-entity">
          <div className="sable-proj-entity-label">ACTIONS</div>
          <div className="sable-proj-cols">
            <ActionMatrix label="Baseline" actions={baselineActions} resource={baselineAuth?.expected_resource ?? ''} color="#2563eb"/>
            <ActionMatrix label={`Candidate (→${successor ?? '?'})`} actions={candidateActions} resource={candidateAuth?.expected_resource ?? ''} color="#7c3aed"/>
          </div>
        </div>
        <ArrowRight size={20} color="#94a3b8"/>
        <div className="sable-proj-entity">
          <div className="sable-proj-entity-label">RESOURCE</div>
          <code>{obligation?.protected_asset ?? '–'}</code>
          {successor && successor !== obligation?.protected_asset && (
            <div className="sable-proj-successor-note">→ candidate: <code>{successor}</code></div>
          )}
        </div>
      </div>

      {/* Delta analysis */}
      <div className="sable-proj-delta">
        {kept.length > 0 && (
          <div className="sable-proj-delta-row kept">
            <span className="sable-delta-label">Kept (correct)</span>
            {kept.map((a, i) => <code key={i} className="sable-delta-chip kept">{a}</code>)}
          </div>
        )}
        {weakening.length > 0 && (
          <div className="sable-proj-delta-row lost">
            <span className="sable-delta-label">Lost (weakening)</span>
            {weakening.map((a, i) => <code key={i} className="sable-delta-chip lost">{a}</code>)}
          </div>
        )}
        {widening.length > 0 && (
          <div className="sable-proj-delta-row widened">
            <span className="sable-delta-label">Widened (extra)</span>
            {widening.map((a, i) => <code key={i} className="sable-delta-chip widened">{a}</code>)}
          </div>
        )}
        {misbinding.length > 0 && (
          <div className="sable-proj-delta-row misbound">
            <span className="sable-delta-label">Misbound (wrong asset)</span>
            {misbinding.map((a, i) => <code key={i} className="sable-delta-chip misbound">{a}</code>)}
          </div>
        )}
      </div>

      {/* Failure type */}
      {(weakening.length > 0 || widening.length > 0 || misbinding.length > 0) && (
        <div className="sable-proj-failure-type">
          <strong>Failure type:</strong>{' '}
          {misbinding.length > 0 ? 'Misbinding — grant targets wrong successor asset'
           : weakening.length > 0 ? 'Weakening — required actions missing'
           : 'Widening — grant exceeds obligation scope'}
        </div>
      )}

      {/* Outside-model */}
      {(candidateAuth?.outside_model?.length ?? 0) > 0 && (
        <div className="sable-proj-outside">
          <strong>Outside supported model:</strong>
          <ul>{candidateAuth!.outside_model!.map((c, i) => <li key={i}><code>{c}</code></li>)}</ul>
        </div>
      )}

      {explainSimply && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong>{' '}
          {weakening.length > 0 ? `The role lost access to: ${weakening.join(', ')}. That means it can no longer do what the obligation requires.`
           : widening.length > 0 ? `The role got extra access: ${widening.join(', ')}. That is more than what the obligation allows.`
           : misbinding.length > 0 ? 'The role now has permissions on the wrong bucket — not the one the obligation is about.'
           : 'The role still has exactly the right permissions on the correct successor bucket.'}
        </div>
      )}
    </div>
  );
};
