export type ChamberColor = 'red' | 'blue' | 'llm' | 'arbiter' | 'control-plane';

export interface TestResult {
  test_id: string;
  name: string;
  mode: 'baseline' | 'triseal';
  runtime: string;
  status: 'PASS' | 'FAIL' | 'SKIPPED';
  measured_value: string;
  target: string;
  evidence: Record<string, any>;
  timestamp: string;
}

export interface TestSuiteSummary {
  mode: 'baseline' | 'triseal';
  runtime: string;
  timestamp: string;
  tests_total: number;
  passed: number;
  failed: number;
  skipped: number;
  results: TestResult[];
}

export interface LedgerEntry {
  seq: number;
  ts: string;
  round_id: string;
  actor: ChamberColor;
  event_type: string;
  payload_hash: string;
  meta: Record<string, any>;
  prev_hash: string;
  entry_hash: string;
  signature: string;
  pub_key: string;
}

export interface VerificationResult {
  valid: boolean;
  total_entries?: number;
  latest_seq?: number;
  latest_hash?: string;
  broken_seq?: number;
  reason?: string;
}

export interface SystemHealth {
  status: string;
  service: string;
  active_runtime: string;
  mode: string;
  ledger_entries: number;
  round_id: string;
  timestamp: string;
}
