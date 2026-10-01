import React from 'react';
import { Check, Clock, XCircle, AlertCircle, ChevronDown, ChevronUp } from 'lucide-react';

export interface SubStep {
  name: string;
  phase: string;
  status: 'pending' | 'running' | 'done' | 'skipped' | 'failed';
  timeTaken?: string;
  desc: string;
}

interface ExpandableStepProps {
  stepIndex: number;
  currentStepIndex: number;
  title: string;
  summary: string;
  substeps: SubStep[];
  isExpanded: boolean;
  onToggleExpand: () => void;
  onClickStep: () => void;
  explainSimply: boolean;
}

export const ExpandableStep: React.FC<ExpandableStepProps> = ({
  stepIndex,
  currentStepIndex,
  title,
  summary,
  substeps,
  isExpanded,
  onToggleExpand,
  onClickStep,
  explainSimply
}) => {
  const isPast = currentStepIndex > stepIndex;
  const isCurrent = currentStepIndex === stepIndex;

  return (
    <div className={`timeline-node-item ${isCurrent ? 'active-step' : ''} ${isPast ? 'completed-step' : ''}`}>
      <div className="node-click-area" onClick={onClickStep}>
        <div className="node-marker">
          {isPast ? <Check size={12} /> : <span>{stepIndex + 1}</span>}
        </div>
        <strong className="node-title">{title}</strong>
        <span className="node-desc">{summary}</span>
      </div>

      {/* Sub-stages toggle chevron */}
      <button 
        className="substages-toggle-btn"
        onClick={(e) => {
          e.stopPropagation();
          onToggleExpand();
        }}
        title="Toggle real sub-stages breakdown"
      >
        <span>{substeps.length} sub-stages</span>
        {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
      </button>

      {/* Sub-stages dropdown overlay */}
      {isExpanded && (
        <div className="substages-dropdown-panel" onClick={(e) => e.stopPropagation()}>
          <div className="dropdown-header">
            <span>Sub-Stages Breakdown</span>
            <button className="dropdown-close" onClick={onToggleExpand}>✕</button>
          </div>
          <div className="substages-list">
            {substeps.map((sub, idx) => (
              <div key={idx} className={`substage-row ${sub.status}`}>
                <div className="substage-icon">
                  {sub.status === 'done' && <Check size={12} className="text-emerald-400" />}
                  {sub.status === 'running' && <span className="substage-spinner" />}
                  {sub.status === 'failed' && <XCircle size={12} className="text-red-400" />}
                  {sub.status === 'skipped' && <AlertCircle size={12} className="text-gray-400" />}
                  {sub.status === 'pending' && <Clock size={12} className="text-gray-500" />}
                </div>

                <div className="substage-text">
                  <div className="substage-title-line">
                    <span className="substage-phase-tag">{sub.phase}</span>
                    <strong>{sub.name}</strong>
                    {sub.timeTaken && <span className="substage-time">{sub.timeTaken}</span>}
                  </div>
                  <p className="substage-desc">{sub.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
