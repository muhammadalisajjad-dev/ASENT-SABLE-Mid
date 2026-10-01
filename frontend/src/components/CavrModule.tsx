import React, { useState, useEffect, useRef } from 'react';
import { 
  Database, ShieldAlert, Cpu, CheckCircle2, XCircle, AlertTriangle, 
  Terminal, ExternalLink, Copy, Check, Play, RefreshCw, Eye, 
  Lock, ArrowRight, Download, ThumbsUp, ThumbsDown, Info, HelpCircle
} from 'lucide-react';

interface TrustedPackage {
  name: string;
  version: string;
  sha256: string;
  source: string;
  status: string;
  capabilities: string;
  added_at: string;
}

export const CavrModule: React.FC = () => {
  // Dialog visibility states
  const [showCacheDialog, setShowCacheDialog] = useState(false);
  const [showActionDialog, setShowActionDialog] = useState(false);
  const [showEnvDialog, setShowEnvDialog] = useState(false);
  const [showProofDrawer, setShowProofDrawer] = useState(false);

  // Trusted cache state
  const [packages, setPackages] = useState<TrustedPackage[]>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Workflow state
  const [explainSimply, setExplainSimply] = useState(false);
  const [activeWorkflowBox, setActiveWorkflowBox] = useState<'none' | 'cache' | 'action' | 'env'>('none');
  const [timelineStep, setTimelineStep] = useState<number>(0);
  const [isRunning, setIsRunning] = useState(false);
  const [currentScenario, setCurrentScenario] = useState<'typosquat' | 'safe' | 'hash_mismatch' | 'clean_new'>('typosquat');
  
  // Live run data
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [interceptedPackage, setInterceptedPackage] = useState<string>('requests-security');
  const [interceptedVersion, setInterceptedVersion] = useState<string>('2.31.0');
  const [currentStateMessage, setCurrentStateMessage] = useState<string>('Awaiting change trigger...');
  const [currentPlainMessage, setCurrentPlainMessage] = useState<string>('Ready to test package changes.');

  // Sandbox & Terminal state
  const [containerLifecycle, setContainerLifecycle] = useState<'idle' | 'created' | 'locked' | 'mounted' | 'running' | 'destroyed'>('idle');
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const terminalEndRef = useRef<HTMLDivElement | null>(null);
  const [meters, setMeters] = useState({
    network_attempts: 0,
    writes_outside_scratch: 0,
    processes_spawned: 0,
    secrets_touched: 0,
  });
  const [honeytokenFlashing, setHoneytokenFlashing] = useState(false);

  // Verdict state
  const [verdictData, setVerdictData] = useState<any>(null);
  const [alternativeDecision, setAlternativeDecision] = useState<'pending' | 'approved' | 'rejected'>('pending');
  const [proofData, setProofData] = useState<any>(null);

  // Fetch trusted packages
  const fetchCache = async () => {
    try {
      const res = await fetch('/api/cavr/cache');
      if (res.ok) {
        const data = await res.json();
        setPackages(data);
      }
    } catch (err) {
      console.error('Failed to load cache:', err);
    }
  };

  useEffect(() => {
    fetchCache();
  }, []);

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollTop = terminalEndRef.current.scrollHeight;
    }
  }, [terminalLogs]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Run Interception Pipeline
  const runInterception = async (scenarioType: 'typosquat' | 'safe' | 'hash_mismatch' | 'clean_new') => {
    if (isRunning) return;
    setIsRunning(true);
    setCurrentScenario(scenarioType);
    setTimelineStep(0);
    setActiveWorkflowBox('none');
    setTerminalLogs([]);
    setMeters({ network_attempts: 0, writes_outside_scratch: 0, processes_spawned: 0, secrets_touched: 0 });
    setHoneytokenFlashing(false);
    setVerdictData(null);
    setAlternativeDecision('pending');
    setProofData(null);
    setContainerLifecycle('idle');

    let pkg = 'requests-security';
    let ver = '2.31.0';
    if (scenarioType === 'safe') {
      pkg = 'requests';
      ver = '2.31.0';
    } else if (scenarioType === 'hash_mismatch') {
      pkg = 'pypdf';
      ver = '4.2.0';
    } else if (scenarioType === 'clean_new') {
      pkg = 'safe-math-utils';
      ver = '1.0.0';
    }

    setInterceptedPackage(pkg);
    setInterceptedVersion(ver);

    try {
      const res = await fetch('/api/cavr/intercept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: pkg,
          version: ver,
          scenario_type: scenarioType
        })
      });

      if (!res.ok) throw new Error('Interception initiation failed');
      const data = await res.json();
      setActiveRunId(data.run_id);

      // Connect to SSE stream
      const eventSource = new EventSource(data.stream_url);

      eventSource.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          handlePipelineEvent(payload);
        } catch (e) {
          // heartbeat
        }
      };

      eventSource.onerror = () => {
        eventSource.close();
        setIsRunning(false);
      };
    } catch (err: any) {
      console.error('Workflow error:', err);
      setIsRunning(false);
    }
  };

  const handlePipelineEvent = (ev: any) => {
    const { type, data } = ev;

    if (type === 'state_change') {
      setTimelineStep(data.step_index);
      setCurrentStateMessage(data.message);
      setCurrentPlainMessage(data.plain_explanation || data.message);

      if (data.state === 'INTERCEPTED') {
        setActiveWorkflowBox('none');
        setContainerLifecycle('idle');
      } else if (data.state === 'CACHE_CHECK') {
        setActiveWorkflowBox('cache');
      } else if (data.state === 'INSPECTING') {
        setActiveWorkflowBox('action');
      } else if (data.state === 'SANDBOXING') {
        setActiveWorkflowBox('env');
        setContainerLifecycle('created');
        setTimeout(() => setContainerLifecycle('locked'), 400);
        setTimeout(() => setContainerLifecycle('mounted'), 900);
        setTimeout(() => setContainerLifecycle('running'), 1400);
      } else if (data.state === 'ALLOWED' || data.state === 'RELEASED') {
        setActiveWorkflowBox('none');
        setContainerLifecycle('destroyed');
        setIsRunning(false);
      } else if (data.state === 'ALT_RECOMMENDED' || data.state === 'AWAITING_APPROVAL') {
        setActiveWorkflowBox('none');
        setContainerLifecycle('destroyed');
        setIsRunning(false);
      }
    } else if (type === 'sandbox_log') {
      setTerminalLogs((prev) => [...prev, data.line]);
    } else if (type === 'honeytoken_flash') {
      setHoneytokenFlashing(true);
      setMeters((m) => ({ ...m, secrets_touched: m.secrets_touched + 1 }));
    } else if (type === 'sandbox_metrics') {
      setMeters({
        network_attempts: data.network_attempts || 0,
        writes_outside_scratch: data.writes_outside_scratch || 0,
        processes_spawned: data.processes_spawned || 0,
        secrets_touched: data.secrets_touched || 0
      });
      if (data.honeytoken_accessed) {
        setHoneytokenFlashing(true);
      }
    } else if (type === 'verdict_computed') {
      setVerdictData(data);
      // Fetch proof drawer data
      if (ev.run_id) {
        fetch(`/api/cavr/proof/${ev.run_id}`)
          .then((r) => r.json())
          .then((proof) => setProofData(proof))
          .catch((e) => console.error(e));
      }
    }
  };

  const handleAlternativeChoice = async (approved: boolean) => {
    if (!activeRunId || !verdictData?.alternative_package) return;
    try {
      await fetch('/api/cavr/approve-alternative', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_id: activeRunId,
          package: interceptedPackage,
          alternative: verdictData.alternative_package.package,
          approved,
          user: 'Security Operator (You)',
          reason: approved ? 'Operator approved safe substitute' : 'Operator rejected substitute'
        })
      });
      setAlternativeDecision(approved ? 'approved' : 'rejected');
      setTimelineStep(7);
      setActiveWorkflowBox('none');
      if (approved) {
        setCurrentStateMessage(`Operator Approved: Verified substitute '${verdictData.alternative_package.package}' released to agent environment.`);
        setCurrentPlainMessage(`You approved the recommended alternative '${verdictData.alternative_package.package}'. The safe package was released to the agent environment!`);
      } else {
        setCurrentStateMessage(`Operator Rejected: Untrusted package '${interceptedPackage}' permanently quarantined.`);
        setCurrentPlainMessage(`You rejected the recommendation. The malicious package '${interceptedPackage}' remains quarantined and blocked.`);
      }
    } catch (err) {
      console.error('Alternative approval failed:', err);
    }
  };

  const timelineSteps = [
    { label: 'Agent runs pip install', desc: 'AI Coding Agent attempts dependency installation' },
    { label: 'ASENT index catches it', desc: 'Redirected via PIP_INDEX_URL local PEP 503 proxy' },
    { label: 'Quarantine', desc: 'Stored in read-only sandbox isolation folder' },
    { label: 'Cache Check', desc: 'Looked up against verified SHA-256 SQLite records' },
    { label: 'Action (AST Inspection)', desc: 'Static syntax tree & typosquatting analysis' },
    { label: 'Environment (Sandbox)', desc: 'Isolated container execution with honeytokens & telemetry' },
    { label: 'Verdict Decision', desc: 'Deterministic policy evaluation (ALLOW / BLOCK)' },
    { label: 'Release or Block', desc: 'Package passed to agent environment or quarantined' }
  ];

  return (
    <div className="cavr-module-container" id="cavr-section">
      {/* CAVR Header */}
      <div className="cavr-header-row">
        <div>
          <div className="cavr-eyebrow">
            <span className="module-pulse-dot" /> CAVR MODULE · CONTINUOUS ARTIFACT VERIFICATION & RUNTIME
          </div>
          <h2 className="cavr-title">CAVR</h2>
          <p className="cavr-subtitle">
            Dependency and package trust assurance gate. Intercepts untrusted agent packages, 
            verifies cryptographic hashes against cache, performs AST static inspection, and tests 
            hostile candidate artifacts in locked-down sandboxes before release.
          </p>
        </div>

        {/* Explain Simply Toggle */}
        <div className="explain-toggle-card">
          <span className="toggle-label">
            <HelpCircle size={14} /> Explain simply
          </span>
          <button 
            className={`toggle-switch ${explainSimply ? 'on' : ''}`}
            onClick={() => setExplainSimply(!explainSimply)}
            title="Switch between plain english explanations and technical security details"
          >
            <span className="switch-knob" />
          </button>
        </div>
      </div>

      {/* THE THREE BOXES */}
      <div className="cavr-three-boxes">
        {/* BOX 1: CACHE (Leftmost) */}
        <div className={`cavr-card-box ${activeWorkflowBox === 'cache' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap blue">
              <Database size={18} />
            </span>
            <span className="box-step-tag">STEP 1 · VERIFICATION</span>
          </div>
          <h3 className="box-name">Cache</h3>
          <p className="box-info">
            Stored packages and Dependencies to Check against
          </p>
          <div className="box-footer-row">
            <button 
              className="box-cta-button"
              onClick={() => setShowCacheDialog(true)}
              id="click-to-view-cache-btn"
            >
              <Eye size={14} />
              <span>Click to View</span>
            </button>
            <span className="box-metric-tag">{packages.length} pinned</span>
          </div>
        </div>

        {/* BOX 2: ACTION (Middle) */}
        <div className={`cavr-card-box ${activeWorkflowBox === 'action' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap amber">
              <ShieldAlert size={18} />
            </span>
            <span className="box-step-tag">STEP 2 · STATIC INSPECTION</span>
          </div>
          <h3 className="box-name">Action</h3>
          <p className="box-info">
            Deep Static Inspection &amp; AST Anomaly Analysis
          </p>
          <div className="box-footer-row">
            <button 
              className="box-cta-button"
              onClick={() => setShowActionDialog(true)}
              id="click-to-view-action-btn"
            >
              <Info size={14} />
              <span>Inspection Details</span>
            </button>
            <span className="box-metric-tag">AST · Typosquat</span>
          </div>
        </div>

        {/* BOX 3: ENVIRONMENT CHECKING (Rightmost) */}
        <div className={`cavr-card-box ${activeWorkflowBox === 'env' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap green">
              <Cpu size={18} />
            </span>
            <span className="box-step-tag">STEP 3 · HOSTILE SANDBOX</span>
          </div>
          <h3 className="box-name">Environment checking</h3>
          <p className="box-info">
            Isolated Multi-Layer Hostile Sandbox
          </p>
          <div className="box-footer-row">
            <button 
              className="box-cta-button"
              onClick={() => setShowEnvDialog(true)}
              id="click-here-env-btn"
            >
              <Terminal size={14} />
              <span>Click here</span>
            </button>
            <span className="box-metric-tag">Hardened 30s</span>
          </div>
        </div>
      </div>

      {/* WIDE WORKFLOW BOX */}
      <div className="wide-workflow-box">
        <div className="workflow-box-header">
          <div className="workflow-title-area">
            <span className="live-status-pill">
              <span className={`status-dot ${isRunning ? 'pulsing' : ''}`} />
              {isRunning ? 'PIPELINE ACTIVE' : 'WORKFLOW DEMONSTRATION'}
            </span>
            <h4>Real Multi-Layer Interception &amp; Sandboxing Workflow</h4>
            <p>
              {explainSimply
                ? 'Watch how ASENT safely intercepts package requests, inspects them, and stops malicious attacks in a real isolated sandbox.'
                : 'Deterministic run state machine: INTERCEPTED → CACHE_CHECK → INSPECTING → SANDBOXING → DETERMINISTIC VERDICT → RELEASE/BLOCK.'}
            </p>
          </div>

          {/* Test Scenario Buttons */}
          <div className="scenario-btn-group">
            <span className="scenario-label">Launch Demonstration:</span>
            <button 
              className={`scenario-btn ${currentScenario === 'typosquat' ? 'selected' : ''}`}
              onClick={() => runInterception('typosquat')}
              disabled={isRunning}
            >
              <Play size={12} />
              <span>Malicious Package (Typosquat)</span>
            </button>

            <button 
              className={`scenario-btn ${currentScenario === 'safe' ? 'selected' : ''}`}
              onClick={() => runInterception('safe')}
              disabled={isRunning}
            >
              <Play size={12} />
              <span>Trusted Package (Cache Hit)</span>
            </button>

            <button 
              className={`scenario-btn ${currentScenario === 'hash_mismatch' ? 'selected' : ''}`}
              onClick={() => runInterception('hash_mismatch')}
              disabled={isRunning}
            >
              <Play size={12} />
              <span>Tampered Hash Mismatch</span>
            </button>

            <button 
              className={`scenario-btn ${currentScenario === 'clean_new' ? 'selected' : ''}`}
              onClick={() => runInterception('clean_new')}
              disabled={isRunning}
            >
              <Play size={12} />
              <span>Clean New Package</span>
            </button>
          </div>
        </div>

        {/* Live Interception Prompt / Status Banner */}
        <div className="interception-prompt-card">
          <div className="prompt-meta-col">
            <span className="prompt-label">INTERCEPTED AGENT ACTION</span>
            <code className="prompt-code">
              pip install {interceptedPackage}=={interceptedVersion}
            </code>
          </div>

          <div className="prompt-narrative-col">
            <span className="narrative-tag">
              {explainSimply ? 'Simple Explanation' : 'Security State Transition'}
            </span>
            <p className="narrative-text">
              {explainSimply ? currentPlainMessage : currentStateMessage}
            </p>
          </div>

          {proofData && (
            <button 
              className="proof-drawer-btn"
              onClick={() => setShowProofDrawer(true)}
            >
              <Lock size={13} />
              <span>Proof Details</span>
            </button>
          )}
        </div>

        {/* HORIZONTAL INTERCEPTION TIMELINE */}
        <div className="timeline-horizontal-wrapper">
          <div className="timeline-track-line" />
          <div className="timeline-nodes-row">
            {timelineSteps.map((step, idx) => {
              const isPast = timelineStep > idx;
              const isCurrent = timelineStep === idx;
              return (
                <div 
                  key={idx} 
                  className={`timeline-node-item ${isCurrent ? 'active-step' : ''} ${isPast ? 'completed-step' : ''}`}
                >
                  <div className="node-marker">
                    {isPast ? <Check size={12} /> : <span>{idx + 1}</span>}
                  </div>
                  <strong className="node-title">{step.label}</strong>
                  <span className="node-desc">
                    {explainSimply
                      ? idx === 0 ? 'Agent requests code'
                      : idx === 1 ? 'Caught at gateway'
                      : idx === 2 ? 'Isolated safely'
                      : idx === 3 ? 'Known good check'
                      : idx === 4 ? 'Code inspection'
                      : idx === 5 ? 'Container testing'
                      : idx === 6 ? 'Decision made'
                      : 'Done safely'
                      : step.desc}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* SANDBOX CONSOLE & TELEMETRY PANEL (Shown when Environment is engaged or logs available) */}
        {(activeWorkflowBox === 'env' || terminalLogs.length > 0 || verdictData) && (
          <div className="sandbox-console-panel">
            {/* Lifecycle Bar */}
            <div className="lifecycle-bar-container">
              <span className="lifecycle-title">Sandbox Lifecycle:</span>
              <div className="lifecycle-stages">
                <span className={`lifecycle-stage ${['created', 'locked', 'mounted', 'running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>
                  1. Created
                </span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${['locked', 'mounted', 'running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>
                  2. Locked down
                </span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${['mounted', 'running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>
                  3. Package mounted
                </span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${['running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>
                  4. Tests running
                </span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${containerLifecycle === 'destroyed' ? 'active destroyed' : ''}`}>
                  5. Destroyed
                </span>
              </div>
            </div>

            {/* Lockdown Badges with Plain Word Tooltips */}
            <div className="lockdown-badges-row">
              <div className="lockdown-badge" title="Network isolation: all socket creation and internet connections are strictly blocked">
                <span className="badge-k">Network:</span> <span className="badge-v red">OFF</span>
              </div>
              <div className="lockdown-badge" title="Filesystem read-only: unauthorized modifications to container system are impossible">
                <span className="badge-k">Filesystem:</span> <span className="badge-v">read-only</span>
              </div>
              <div className="lockdown-badge" title="User non-root: runs under unprivileged UID 10001, blocking root exploits">
                <span className="badge-k">User:</span> <span className="badge-v">non-root (10001)</span>
              </div>
              <div className="lockdown-badge" title="Capabilities dropped: removes all Linux superuser privileges">
                <span className="badge-k">Capabilities:</span> <span className="badge-v">dropped (ALL)</span>
              </div>
              <div className="lockdown-badge" title="Memory limit: hard 256MB RAM quota blocks denial-of-service">
                <span className="badge-k">Memory:</span> <span className="badge-v">256 MB</span>
              </div>
              <div className="lockdown-badge" title="CPU quota: throttled to 0.5 CPU cores to prevent exhaustion">
                <span className="badge-k">CPU:</span> <span className="badge-v">0.5 cores</span>
              </div>
              <div className="lockdown-badge" title="Timeout: hard 30-second killswitch forcibly removes rogue containers">
                <span className="badge-k">Timeout:</span> <span className="badge-v">30 s</span>
              </div>
            </div>

            {/* Live Terminal & Behavior Meters Grid */}
            <div className="terminal-and-meters-grid">
              {/* Terminal */}
              <div className="sandbox-terminal-box">
                <div className="terminal-topbar">
                  <div className="terminal-dots">
                    <span className="tdot red" />
                    <span className="tdot yellow" />
                    <span className="tdot green" />
                  </div>
                  <span className="terminal-title">
                    <Terminal size={12} /> asent-sandbox stdout log stream (sys.addaudithook)
                  </span>
                  <span className="terminal-live-tag">LIVE FEED</span>
                </div>
                <div className="terminal-body" ref={terminalEndRef}>
                  {terminalLogs.length === 0 ? (
                    <div className="terminal-empty">Awaiting container execution...</div>
                  ) : (
                    terminalLogs.map((log, idx) => (
                      <div 
                        key={idx} 
                        className={`terminal-log-line ${
                          log.includes('CRITICAL_THREAT') || log.includes('SECURITY_ALERT') ? 'log-critical' :
                          log.includes('LIFECYCLE') ? 'log-lifecycle' :
                          log.includes('TEST_EXECUTION') ? 'log-test' : ''
                        }`}
                      >
                        {log}
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Behavior Meters */}
              <div className="behavior-meters-card">
                <div className="meters-header">
                  <h5>Behavioral Telemetry Meters</h5>
                  <span className="meters-subtitle">Live sys.addaudithook sensors</span>
                </div>

                <div className="meters-list">
                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Network Attempts</span>
                      <strong>{meters.network_attempts}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${meters.network_attempts > 0 ? 'red' : 'green'}`}
                        style={{ width: `${Math.min(meters.network_attempts * 100, 100)}%` }}
                      />
                    </div>
                  </div>

                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Writes Outside Scratch</span>
                      <strong>{meters.writes_outside_scratch}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${meters.writes_outside_scratch > 0 ? 'red' : 'green'}`}
                        style={{ width: `${Math.min(meters.writes_outside_scratch * 100, 100)}%` }}
                      />
                    </div>
                  </div>

                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Processes Spawned</span>
                      <strong>{meters.processes_spawned}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${meters.processes_spawned > 0 ? 'amber' : 'green'}`}
                        style={{ width: `${Math.min(meters.processes_spawned * 50, 100)}%` }}
                      />
                    </div>
                  </div>

                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Secrets Touched</span>
                      <strong>{meters.secrets_touched}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${meters.secrets_touched > 0 ? 'red' : 'green'}`}
                        style={{ width: `${Math.min(meters.secrets_touched * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Honeytoken Indicator */}
                <div className={`honeytoken-indicator-box ${honeytokenFlashing ? 'flashing-alert' : ''}`}>
                  <div className="indicator-icon">
                    <ShieldAlert size={18} />
                  </div>
                  <div>
                    <strong>Honeytoken Secret Trap</strong>
                    <p>
                      {honeytokenFlashing
                        ? 'CRITICAL ALERT: Fake AWS credentials file read by package!'
                        : 'Trap active at ~/.aws/credentials. Awaiting access attempts.'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VERDICT CARD */}
        {verdictData && (
          <div className={`verdict-card-container ${verdictData.verdict.toLowerCase()}`}>
            <div className="verdict-banner-row">
              <div className="verdict-status-block">
                {verdictData.verdict === 'ALLOW' && <CheckCircle2 size={32} className="v-icon good" />}
                {verdictData.verdict === 'BLOCK' && <XCircle size={32} className="v-icon bad" />}
                {verdictData.verdict === 'NEEDS_REVIEW' && <AlertTriangle size={32} className="v-icon warn" />}
                <div>
                  <span className="verdict-tag">ASSURANCE GATE VERDICT</span>
                  <h3 className="verdict-heading">{verdictData.verdict}</h3>
                </div>
              </div>

              <div className="verdict-honesty-note">
                <span className="honesty-title">Honesty Rule Statement:</span>
                <p>{verdictData.honesty_wording}</p>
              </div>
            </div>

            {/* Evidence Lines */}
            <div className="verdict-evidence-list">
              <strong>Verified Evidence Lines:</strong>
              <ul>
                {verdictData.evidence_lines?.map((line: string, idx: number) => (
                  <li key={idx}>{line}</li>
                ))}
              </ul>
            </div>

            {/* Alternative Recommendation if BLOCKED */}
            {verdictData.verdict === 'BLOCK' && verdictData.alternative_package && (
              <div className="alternative-package-card">
                <div className="alt-top-row">
                  <div className="alt-title-wrap">
                    <span className="alt-badge">SAFE ALTERNATIVE RECOMMENDED</span>
                    <h4>
                      {verdictData.alternative_package.package} <code>v{verdictData.alternative_package.version}</code>
                    </h4>
                  </div>
                  <span className="alt-confidence">
                    {verdictData.alternative_package.confidence}
                  </span>
                </div>

                <p className="alt-reason">{verdictData.alternative_package.reason}</p>
                
                <div className="alt-capabilities">
                  <span>Capabilities:</span> <code>{verdictData.alternative_package.capabilities}</code>
                </div>

                <div className="alt-action-bar">
                  <span className="alt-human-notice">
                    <Lock size={13} /> Requires explicit human approval. Never auto-installed.
                  </span>

                  <div className="alt-buttons">
                    <button 
                      className={`alt-btn approve ${alternativeDecision === 'approved' ? 'selected' : ''}`}
                      onClick={() => handleAlternativeChoice(true)}
                      disabled={alternativeDecision !== 'pending'}
                    >
                      <ThumbsUp size={14} />
                      <span>{alternativeDecision === 'approved' ? 'Approved & Logged' : 'Approve Alternative'}</span>
                    </button>

                    <button 
                      className={`alt-btn reject ${alternativeDecision === 'rejected' ? 'selected' : ''}`}
                      onClick={() => handleAlternativeChoice(false)}
                      disabled={alternativeDecision !== 'pending'}
                    >
                      <ThumbsDown size={14} />
                      <span>{alternativeDecision === 'rejected' ? 'Rejected & Quarantined' : 'Reject'}</span>
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* DIALOG 1: CACHE DIALOG */}
      {showCacheDialog && (
        <div className="modal-backdrop" onClick={() => setShowCacheDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">DEPENDENCY TRUST STORE</span>
                <h3>Trusted Packages &amp; Cryptographic Hashes</h3>
                <p>Pre-verified Python dependencies available for AI coding agents. Stored in SQLite.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowCacheDialog(false)}>✕</button>
            </div>

            <div className="modal-table-scroll">
              <table className="cache-table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>SHA-256 Hash</th>
                    <th>Capabilities</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map((pkg, idx) => (
                    <tr key={idx}>
                      <td><strong>{pkg.name}</strong></td>
                      <td><code>{pkg.version}</code></td>
                      <td>
                        <div className="hash-copy-cell">
                          <code>{pkg.sha256.slice(0, 16)}...</code>
                          <button 
                            className="copy-btn"
                            onClick={() => copyToClipboard(pkg.sha256, pkg.name)}
                            title="Click to copy full SHA-256 hash"
                          >
                            {copiedHash === pkg.name ? <Check size={12} className="text-green" /> : <Copy size={12} />}
                          </button>
                        </div>
                      </td>
                      <td><small>{pkg.capabilities}</small></td>
                      <td><span className="status-pill trusted">{pkg.status}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="modal-bottom-bar">
              <span className="table-count-note">{packages.length} packages pinned in SQLite trusted_packages table</span>
              <button className="btn-secondary" onClick={() => setShowCacheDialog(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* DIALOG 2: ACTION DIALOG */}
      {showActionDialog && (
        <div className="modal-backdrop" onClick={() => setShowActionDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">ACTION BOX · STATIC INSPECTION</span>
                <h3>Deep Python AST Inspection &amp; Anomaly Detection</h3>
                <p>Lexical parsing, dangerous primitive detection, and typosquatting analysis.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowActionDialog(false)}>✕</button>
            </div>

            <div className="modal-body-content">
              <div className="inspection-steps-grid">
                <div className="step-card">
                  <div className="step-num">01</div>
                  <strong>AST Dynamic Execution</strong>
                  <p>Catches eval(), exec(), and dynamic __import__() calls used for payload hiding.</p>
                </div>

                <div className="step-card">
                  <div className="step-num">02</div>
                  <strong>Process &amp; Sockets</strong>
                  <p>Flags os.system, subprocess.Popen, and raw socket.socket connections.</p>
                </div>

                <div className="step-card">
                  <div className="step-num">03</div>
                  <strong>Obfuscated Staging</strong>
                  <p>Detects base64 encoded strings, hex decoders, and reversed shell payloads.</p>
                </div>

                <div className="step-card">
                  <div className="step-num">04</div>
                  <strong>Setup.py Install Hooks</strong>
                  <p>Checks for custom cmdclass overrides and install-time backdoor triggers.</p>
                </div>

                <div className="step-card">
                  <div className="step-num">05</div>
                  <strong>Typosquatting &amp; Homoglyphs</strong>
                  <p>Levenshtein distance comparison against trusted names (e.g. reqeusts vs requests).</p>
                </div>

                <div className="step-card">
                  <div className="step-num">06</div>
                  <strong>Metadata Sanity</strong>
                  <p>Flags version jumps (&gt;90), missing licenses, and unpinned direct git dependencies.</p>
                </div>
              </div>

              <div className="outcomes-section">
                <h4>Three Deterministic Outcomes:</h4>
                <div className="outcomes-row">
                  <div className="outcome-pill good">
                    <strong>ALLOW</strong>
                    <span>Clean syntax tree, no suspicious sinks, legitimate metadata</span>
                  </div>
                  <div className="outcome-pill warn">
                    <strong>NEEDS_REVIEW</strong>
                    <span>Medium severity anomalies (e.g. missing license or undeclared minor flags)</span>
                  </div>
                  <div className="outcome-pill bad">
                    <strong>BLOCK</strong>
                    <span>Critical finding (eval/exec, subprocess, typosquatting, or honeytoken exfil)</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="modal-bottom-bar">
              <span className="table-count-note">Deterministic Python AST parser active</span>
              <button className="btn-secondary" onClick={() => setShowActionDialog(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* DIALOG 3: ENVIRONMENT CHECKING DIALOG */}
      {showEnvDialog && (
        <div className="modal-backdrop" onClick={() => setShowEnvDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">ENVIRONMENT BOX · HOSTILE CODE SANDBOX</span>
                <h3>Docker Sandbox Architecture &amp; Lockdown Controls</h3>
                <p>Disposable containerized testbed enforcing isolation, honeytoken detection, and syscall tracking.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowEnvDialog(false)}>✕</button>
            </div>

            <div className="modal-body-content">
              {/* Dockerfile Summary */}
              <div className="sandbox-info-panel">
                <h4>Dockerfile Summary (asent-sandbox)</h4>
                <div className="docker-summary-grid">
                  <div><strong>Base Image:</strong> <code>python:3.12-slim</code></div>
                  <div><strong>User:</strong> <code>sandbox (UID: 10001, unprivileged non-root)</code></div>
                  <div><strong>Observation:</strong> <code>sys.addaudithook + optional strace syscall tracer</code></div>
                  <div><strong>Harness Path:</strong> <code>/opt/asent/harness.py</code></div>
                </div>
              </div>

              {/* Lockdown Flags */}
              <div className="flags-section">
                <h4>Lockdown Command Flags:</h4>
                <div className="flags-list">
                  <div className="flag-row">
                    <code>--network none</code>
                    <span>Network is severed; no outbound connections or exfiltration possible.</span>
                  </div>
                  <div className="flag-row">
                    <code>--read-only</code>
                    <span>Root filesystem is read-only; no system files can be modified or written to.</span>
                  </div>
                  <div className="flag-row">
                    <code>--tmpfs /scratch:rw,noexec,nosuid,size=64m</code>
                    <span>Disposable in-memory storage only; execution from scratch is disabled.</span>
                  </div>
                  <div className="flag-row">
                    <code>--user 10001:10001 --cap-drop ALL</code>
                    <span>Drops all Linux capabilities; prevents privilege escalation.</span>
                  </div>
                  <div className="flag-row">
                    <code>--security-opt no-new-privileges --security-opt seccomp=asent-seccomp.json</code>
                    <span>Applies strict seccomp system call filtering.</span>
                  </div>
                  <div className="flag-row">
                    <code>--pids-limit 64 --memory 256m --cpus 0.5</code>
                    <span>Hard resource limits against fork bombs and compute exhaustion.</span>
                  </div>
                  <div className="flag-row">
                    <code>timeout 30s</code>
                    <span>Strict watchdog timeout terminating stalled or hostile loops.</span>
                  </div>
                </div>
              </div>

              {/* Tests Run & Limitations */}
              <div className="limitations-card">
                <h4>Honest Limitations Notice:</h4>
                <p>
                  ALLOW is worded as <strong>&ldquo;No malicious behavior observed under our tests&rdquo;</strong>. 
                  It never claims &ldquo;proven safe&rdquo;, acknowledging that bounded execution cannot guarantee 
                  safety against arbitrary unexercised logic.
                </p>
              </div>
            </div>

            <div className="modal-bottom-bar">
              <span className="table-count-note">Hostile code execution sandbox specification</span>
              <button className="btn-secondary" onClick={() => setShowEnvDialog(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* PROOF DRAWER MODAL */}
      {showProofDrawer && proofData && (
        <div className="modal-backdrop" onClick={() => setShowProofDrawer(false)}>
          <div className="modal-sheet proof-drawer" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">AUDIT &amp; EXECUTION EVIDENCE</span>
                <h3>Proof Drawer: Exact Execution Parameters</h3>
                <p>Answers the question: &ldquo;What did you actually run?&rdquo;</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowProofDrawer(false)}>✕</button>
            </div>

            <div className="modal-body-content">
              <div className="proof-field">
                <span className="p-label">EXACT DOCKER RUN COMMAND:</span>
                <pre className="proof-code-box">{proofData.docker_command}</pre>
              </div>

              <div className="proof-kv-grid">
                <div>
                  <span className="p-label">CONTAINER ID:</span>
                  <code>{proofData.container_id}</code>
                </div>
                <div>
                  <span className="p-label">IMAGE DIGEST:</span>
                  <code>{proofData.image_digest}</code>
                </div>
                <div>
                  <span className="p-label">RUN ID:</span>
                  <code>{proofData.run_id}</code>
                </div>
                <div>
                  <span className="p-label">HASH COMPARISON:</span>
                  <code>{proofData.hash_comparison?.matches ? 'MATCH (Valid)' : 'MISMATCH (Tampered)'}</code>
                </div>
              </div>

              <div className="proof-field">
                <span className="p-label">DOWNLOADABLE EVIDENCE JSON:</span>
                <pre className="proof-json-box">
                  {JSON.stringify(proofData.evidence_json, null, 2)}
                </pre>
              </div>
            </div>

            <div className="modal-bottom-bar">
              <a 
                className="btn-primary"
                href={`data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(proofData.evidence_json, null, 2))}`}
                download={`ASENT_evidence_${proofData.run_id}.json`}
              >
                <Download size={14} /> Download Evidence JSON
              </a>
              <button className="btn-secondary" onClick={() => setShowProofDrawer(false)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
