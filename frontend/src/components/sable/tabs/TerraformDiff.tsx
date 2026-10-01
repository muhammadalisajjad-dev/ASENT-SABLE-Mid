import React, { useState, useEffect } from 'react';
import { SableRunState } from '../types';
import { AlertTriangle, GitCompare, Edit3, Play, RefreshCw, Check } from 'lucide-react';

interface Props {
  runState: SableRunState;
  explainSimply: boolean;
  onRerunCustom?: (candidateTf: Record<string, string>) => void;
}

export const TerraformDiffTab: React.FC<Props> = ({ runState, explainSimply, onRerunCustom }) => {
  const [editMode, setEditMode] = useState(false);
  const [customCode, setCustomCode] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    // If candidate text is in candidateResources or diff, initialize customCode
    const candidateLines = (runState.diffLines.length > 0 ? runState.diffLines : (runState.diff ?? '').split('\n'))
      .filter(l => !l.startsWith('-') || l.startsWith('---'))
      .map(l => l.startsWith('+') ? l.slice(1) : l)
      .join('\n');
    setCustomCode(candidateLines || '# main.tf\nresource "aws_s3_bucket" "customer_data_v2" {\n  bucket = "customer-data-prod-v2"\n}\n');
  }, [runState.diff, runState.diffLines]);

  if (!runState.diff && runState.diffLines.length === 0) {
    return (
      <div className="sable-tab-empty">
        <GitCompare size={32} strokeWidth={1.2}/>
        <p>Run a scenario to see the Terraform diff.</p>
      </div>
    );
  }

  const lines = runState.diffLines.length > 0 ? runState.diffLines : (runState.diff ?? '').split('\n');

  const handleRunAgain = async () => {
    if (!onRerunCustom) return;
    setIsSubmitting(true);
    try {
      await onRerunCustom({ "main.tf": customCode });
      setEditMode(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="sable-tab-content">
      <div className="sable-diff-header-row">
        <div>
          <strong style={{ fontSize: '1rem', color: '#0f172a' }}>Terraform Diff</strong>
          <span className="sable-diff-subtitle">Baseline vs. Candidate — unified diff</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div className="sable-diff-hashes">
            <span>Baseline SHA: <code>{runState.baselineSha?.slice(0, 12) ?? '–'}…</code></span>
            <span>Candidate SHA: <code>{runState.candidateSha?.slice(0, 12) ?? '–'}…</code></span>
          </div>
          <button
            className={`sable-btn ${editMode ? 'sable-btn-primary' : 'sable-btn-secondary'}`}
            style={{ fontSize: '0.75rem', padding: '5px 10px' }}
            onClick={() => setEditMode(m => !m)}
          >
            <Edit3 size={12}/> {editMode ? 'Hide Editor' : 'Edit Candidate'}
          </button>
        </div>
      </div>

      {runState.unsupportedConstructs?.length > 0 && (
        <div className="sable-diff-warn">
          <AlertTriangle size={13}/>
          <strong>Unsupported constructs detected:</strong>{' '}
          {runState.unsupportedConstructs.join('; ')}
        </div>
      )}

      {/* Optional Candidate In-Browser Editor */}
      {editMode && (
        <div style={{
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: '8px',
          padding: '14px',
          marginBottom: '1rem',
          boxShadow: '0 2px 4px rgba(0,0,0,0.04)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <div>
              <strong style={{ fontSize: '0.85rem', color: '#1e293b' }}>In-Browser Candidate Editor</strong>
              <span className="sable-small-note" style={{ display: 'block' }}>
                Modify candidate Terraform below and click "Run again" to test SABLE boundary preservation on your custom edit.
              </span>
            </div>
            <button
              className="sable-btn sable-btn-primary"
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              onClick={handleRunAgain}
              disabled={isSubmitting}
            >
              {isSubmitting ? <><RefreshCw size={13} className="spin"/> Running…</> : <><Play size={13}/> Run again</>}
            </button>
          </div>
          <textarea
            value={customCode}
            onChange={e => setCustomCode(e.target.value)}
            style={{
              width: '100%',
              height: '180px',
              fontFamily: 'monospace',
              fontSize: '0.8rem',
              padding: '10px',
              border: '1px solid #cbd5e1',
              borderRadius: '4px',
              background: '#f8fafc',
              color: '#0f172a',
              resize: 'vertical'
            }}
          />
        </div>
      )}

      {/* Diff View */}
      <div className="sable-diff-container">
        <div className="sable-diff-pane">
          <div className="sable-diff-pane-header">Baseline</div>
          <pre className="sable-diff-code">
            {lines
              .filter(l => !l.startsWith('+') || l.startsWith('+++'))
              .map((l, i) => (
                <div key={i} className={`sable-diff-line ${l.startsWith('-') ? 'removed' : l.startsWith('@@') ? 'hunk' : ''}`}>
                  {l}
                </div>
              ))}
          </pre>
        </div>
        <div className="sable-diff-pane">
          <div className="sable-diff-pane-header">Candidate</div>
          <pre className="sable-diff-code">
            {lines
              .filter(l => !l.startsWith('-') || l.startsWith('---'))
              .map((l, i) => (
                <div key={i} className={`sable-diff-line ${l.startsWith('+') ? 'added' : l.startsWith('@@') ? 'hunk' : ''}`}>
                  {l}
                </div>
              ))}
          </pre>
        </div>
      </div>

      {/* Moved blocks */}
      {runState.baselineGraph && (runState.candidateGraph as any)?.moves?.length > 0 && (
        <div className="sable-diff-moves">
          <strong>Explicit moved blocks:</strong>
          {((runState.candidateGraph as any)?.moves ?? []).map((m: any, i: number) => (
            <div key={i} className="sable-move-badge">
              <code>{m.from}</code> → <code>{m.to}</code>
            </div>
          ))}
        </div>
      )}

      {explainSimply && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong> The highlighted lines show what changed in the Terraform.
          Green lines were added, red lines were removed. SABLE checks whether these changes affect
          who can access the protected bucket.
        </div>
      )}
    </div>
  );
};
