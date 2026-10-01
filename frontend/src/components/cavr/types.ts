export interface CavrRunState {
  runId: string | null;
  stepIndex: number;
  package: string;
  version: string;
  scenarioKey: string;
  explainSimply: boolean;
  verdict: 'ALLOW' | 'BLOCK' | 'NEEDS_REVIEW' | null;
  policyState: 'VERIFIED' | 'RESTRICTED' | 'REJECTED' | 'UNRESOLVED' | null;
  honestyWording: string;
  currentStateMessage: string;
  currentPlainMessage: string;
  
  // Phase Payloads
  gateResult: any | null;
  resolution: any | null;
  cacheResult: any | null;
  actionData: any | null;
  counterfactualResults: any | null;
  causalGraph: any | null;
  violatingPaths: any[] | null;
  repair: any | null;
  reverification: any | null;
  certificate: any | null;
  reconstruction: any | null;
  
  // Metrics & telemetry
  terminalLogs: string[];
  meters: {
    network_attempts: number;
    writes_outside_scratch: number;
    processes_spawned: number;
    secrets_touched: number;
  };
  honeytokenFlashing: boolean;
  proofData: any | null;
}
