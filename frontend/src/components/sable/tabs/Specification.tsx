import React from 'react';
import { SableRunState } from '../types';
import { CheckCircle2, XCircle, MinusCircle, Info } from 'lucide-react';

interface Props { runState: SableRunState; explainSimply: boolean; }

const REQUIREMENTS = [
  { id: 'R-CAP', name: 'Capture', module: 'api.py / hcl_parser.py', event: 'capture.complete' },
  { id: 'R-NORM', name: 'Normalization', module: 'hcl_parser.py', event: 'normalize.complete' },
  { id: 'R-OBL', name: 'Obligation model', module: 'storage.py / api.py', event: 'obligation.loaded' },
  { id: 'R-CORR', name: 'Correspondence', module: 'correspondence.py', event: 'correspondence.scored' },
  { id: 'R-PROJ', name: 'Projection', module: 'authorization.py', event: 'projection.complete' },
  { id: 'R-AUTH', name: 'Authorization evaluation', module: 'authorization.py', event: 'projection.complete' },
  { id: 'R-ATTR', name: 'Three-state attribution', module: 'api.py', event: 'decision.attributed' },
  { id: 'R-EVID', name: 'Evidence output', module: 'assurance.py / api.py', event: 'run.complete' },
  { id: 'R-DET', name: 'Determinism & offline', module: 'authorization.py / hcl_parser.py', event: 'N/A — verified by design' },
  { id: 'R-BM', name: 'Benchmark with hidden GT', module: 'benchmark.py / ground_truth.py', event: 'benchmark.complete' },
  { id: 'R-BL', name: 'Baselines B0-B4', module: 'baselines.py', event: 'benchmark.complete' },
  { id: 'R-ABL', name: 'Ablations', module: 'benchmark.py', event: 'benchmark.complete' },
  { id: 'R-KT', name: 'Kill tests K1-K6', module: 'benchmark.py', event: 'benchmark.complete' },
];

const NON_GOALS = [
  'Does not generate fixes or patched Terraform',
  'Does not claim infrastructure is "secure" or "safe"',
  'Does not use any LLM, AI API, or cloud service in the decision path',
  'Does not require network access — works fully offline',
  'Does not analyze EC2, RDS, Lambda or other resource types (S3+IAM only)',
  'Does not evaluate cross-account principals or service principals',
  'Does not evaluate Condition, NotAction, or NotResource IAM semantics',
];

const CLAIMS = [
  { claim: 'Can determine if exact obligation actions and resource scope are preserved', can: true },
  { claim: 'Can identify a unique logical successor using structural signals', can: true },
  { claim: 'Can classify regression as widening, weakening, or misbinding', can: true },
  { claim: 'Can produce UNKNOWN when evidence is genuinely insufficient', can: true },
  { claim: 'Can claim infrastructure is secure', can: false },
  { claim: 'Can evaluate deployed AWS state or runtime behavior', can: false },
  { claim: 'Can handle arbitrary IAM policy semantics (Condition, cross-account)', can: false },
  { claim: 'Can guarantee absence of other regressions outside the stated obligation', can: false },
];

export const SpecificationTab: React.FC<Props> = ({ runState, explainSimply }) => {
  const getStatus = (req: typeof REQUIREMENTS[0]): 'pass' | 'fail' | 'not-run' => {
    if (!runState.runId) return 'not-run';
    if (req.id === 'R-BM' || req.id === 'R-BL' || req.id === 'R-ABL' || req.id === 'R-KT') {
      return 'not-run';
    }
    // Map events to run state
    const hasEvidence = runState.evidence !== null;
    const hasVerdict = runState.verdict !== null;
    if (req.id === 'R-CAP') return runState.baselineSha ? 'pass' : 'not-run';
    if (req.id === 'R-NORM') return runState.baselineResources.length > 0 ? 'pass' : 'not-run';
    if (req.id === 'R-OBL') return runState.obligation ? 'pass' : 'not-run';
    if (req.id === 'R-CORR') return runState.hypotheses.length > 0 ? 'pass' : 'not-run';
    if (req.id === 'R-PROJ') return runState.candidateAuth ? 'pass' : 'not-run';
    if (req.id === 'R-AUTH') return runState.candidateAuth?.known !== undefined ? 'pass' : 'not-run';
    if (req.id === 'R-ATTR') return hasVerdict ? 'pass' : 'not-run';
    if (req.id === 'R-EVID') return hasEvidence ? 'pass' : 'not-run';
    if (req.id === 'R-DET') return 'pass'; // by design
    return 'not-run';
  };

  return (
    <div className="sable-tab-content">
      <div className="sable-spec-section">
        <h3>Problem Statement</h3>
        <p className="sable-spec-problem">
          After a structural Terraform change, does a previously verified least-privilege boundary
          (one application IAM role, an explicit set of S3 actions, one protected S3 asset) still
          govern the correct logical successor asset?
        </p>
        <p className="sable-spec-sub">
          Output states: <strong>PRESERVED</strong> / <strong>REGRESSED</strong> / <strong>UNKNOWN</strong>
        </p>
      </div>

      <div className="sable-spec-section">
        <h3>Obligation</h3>
        <div className="sable-obligation-table">
          <table>
            <thead><tr><th>Field</th><th>Value</th></tr></thead>
            <tbody>
              <tr><td>ID</td><td><code>S3-APPROLE-CUSTOMERDATA</code></td></tr>
              <tr><td>Principal</td><td><code>aws_iam_role.app</code></td></tr>
              <tr><td>Actions</td><td><code>s3:GetObject, s3:PutObject</code></td></tr>
              <tr><td>Protected Asset</td><td><code>aws_s3_bucket.customer_data</code></td></tr>
              <tr><td>Resource Scope</td><td><code>arn:aws:s3:::customer-data/*</code></td></tr>
              <tr><td>Authority Source</td><td>explicit benchmark policy + Terraform IAM policy document</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div className="sable-spec-section">
        <h3>Non-Goals</h3>
        <ul className="sable-nongoals">
          {NON_GOALS.map((g, i) => <li key={i}><XCircle size={13} color="#dc2626"/> {g}</li>)}
        </ul>
      </div>

      <div className="sable-spec-section">
        <h3>Claims SABLE Can and Cannot Make</h3>
        <div className="sable-claims-table">
          <table>
            <thead><tr><th>Claim</th><th>Status</th></tr></thead>
            <tbody>
              {CLAIMS.map((c, i) => (
                <tr key={i}>
                  <td>{c.claim}</td>
                  <td>
                    {c.can
                      ? <span className="sable-claim-can"><CheckCircle2 size={13}/> Can</span>
                      : <span className="sable-claim-cannot"><XCircle size={13}/> Cannot</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="sable-spec-section">
        <h3>Requirements Traceability</h3>
        <p className="sable-small-note"><Info size={12}/> Benchmark rows require running the benchmark separately.</p>
        <div className="sable-trace-table">
          <table>
            <thead>
              <tr><th>ID</th><th>Requirement</th><th>Module</th><th>Proving Event</th><th>Status (this run)</th></tr>
            </thead>
            <tbody>
              {REQUIREMENTS.map(req => {
                const status = getStatus(req);
                return (
                  <tr key={req.id}>
                    <td><code>{req.id}</code></td>
                    <td>{req.name}</td>
                    <td><code>{req.module}</code></td>
                    <td><code>{req.event}</code></td>
                    <td>
                      {status === 'pass' ? <span className="sable-trace-pass"><CheckCircle2 size={12}/> Pass</span>
                       : status === 'fail' ? <span className="sable-trace-fail"><XCircle size={12}/> Fail</span>
                       : <span className="sable-trace-notrun"><MinusCircle size={12}/> Not run</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
