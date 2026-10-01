import React, { useState } from 'react';
import { Network, ShieldCheck, AlertTriangle, ArrowRight, CheckCircle2, Lock, FileCode2 } from 'lucide-react';

export const SableModule: React.FC = () => {
  const [selectedScenario, setSelectedScenario] = useState<'preserved' | 'widened' | 'regressed'>('preserved');

  return (
    <div className="sable-module-container">
      <div className="cavr-header-row">
        <div>
          <div className="cavr-eyebrow">
            <span className="module-pulse-dot" /> SABLE MODULE · INFRASTRUCTURE SECURITY BOUNDARY ASSURANCE
          </div>
          <h2 className="cavr-title">SABLE</h2>
          <p className="cavr-subtitle">
            Terraform security-boundary assurance. Tracks cloud resource successor attribution, verifies 
            least-privilege preservation across IAM role policies, and detects boundary regressions before 
            infrastructure changes apply.
          </p>
        </div>
      </div>

      <div className="sable-scenario-picker">
        <button 
          className={`sable-pill ${selectedScenario === 'preserved' ? 'active' : ''}`}
          onClick={() => setSelectedScenario('preserved')}
        >
          <CheckCircle2 size={14} /> Preserved Least-Privilege
        </button>
        <button 
          className={`sable-pill ${selectedScenario === 'widened' ? 'active' : ''}`}
          onClick={() => setSelectedScenario('widened')}
        >
          <AlertTriangle size={14} /> Widened Boundary
        </button>
        <button 
          className={`sable-pill ${selectedScenario === 'regressed' ? 'active' : ''}`}
          onClick={() => setSelectedScenario('regressed')}
        >
          <Lock size={14} /> Regressed Access Control
        </button>
      </div>

      <div className="sable-grid">
        <div className="sable-card">
          <div className="card-tag">TERRAFORM STATE ATTRIBUTION</div>
          <h3>Successor Policy Mapping</h3>
          <p>Analyzing candidate infrastructure definitions for InvoiceHub S3 storage and compute roles.</p>
          
          <div className="policy-diff-box">
            <div className="diff-header">
              <FileCode2 size={13} />
              <span>iam_policy.tf (Candidate vs Baseline)</span>
            </div>
            <pre className="diff-code">
{selectedScenario === 'preserved' && `
 resource "aws_iam_role_policy" "invoice_worker" {
   name   = "InvoiceProcessingAccess"
   role   = aws_iam_role.worker.id
   policy = jsonencode({
     Version = "2012-10-17"
     Statement = [{
       Action   = ["s3:GetObject"]
       Effect   = "Allow"
       Resource = "\${aws_s3_bucket.invoices.arn}/incoming/*"
     }]
   })
 }
`}
{selectedScenario === 'widened' && `
 resource "aws_iam_role_policy" "invoice_worker" {
   name   = "InvoiceProcessingAccess"
   role   = aws_iam_role.worker.id
   policy = jsonencode({
     Version = "2012-10-17"
     Statement = [{
-      Action   = ["s3:GetObject"]
+      Action   = ["s3:*"]
       Effect   = "Allow"
-      Resource = "\${aws_s3_bucket.invoices.arn}/incoming/*"
+      Resource = "*"
     }]
   })
 }
`}
{selectedScenario === 'regressed' && `
 resource "aws_s3_bucket_public_access_block" "invoices" {
   bucket = aws_s3_bucket.invoices.id
-  block_public_acls   = true
+  block_public_acls   = false
-  block_public_policy = true
+  block_public_policy = false
 }
`}
            </pre>
          </div>
        </div>

        <div className="sable-card">
          <div className="card-tag">Z3 SMT VERIFICATION ENGINE</div>
          <h3>Boundary Formal Assurance</h3>
          
          <div className={`smt-result-card ${selectedScenario}`}>
            <div className="smt-badge">
              {selectedScenario === 'preserved' ? 'BOUNDARY PRESERVED · ACCEPT' : 'BOUNDARY VIOLATION · REJECT'}
            </div>
            <p>
              {selectedScenario === 'preserved' 
                ? 'Formal Z3 verification confirms that the proposed IAM policy is a strict subset or equivalent successor to the baseline security boundary.'
                : 'Z3 solver generated a counter-example satisfying unauthorized actions outside the baseline invariant.'}
            </p>
          </div>

          <div className="sable-invariants-list">
            <strong>Active Boundary Invariants:</strong>
            <ul>
              <li>Invoice storage bucket cannot allow unauthenticated public read.</li>
              <li>Worker compute role cannot assume AdministratorAccess credentials.</li>
              <li>Cross-account role assumption restricted to registered tenant ID.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
