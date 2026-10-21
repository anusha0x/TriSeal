import React, { useState, useEffect } from 'react';
import { Shield, Activity, FileCheck, Layers, Terminal, Sparkles, RefreshCw } from 'lucide-react';
import { ScoreboardView } from './components/ScoreboardView';
import { AuditVerifierView } from './components/AuditVerifierView';
import { RoundThreatModelView } from './components/RoundThreatModelView';
import { TestSuiteSummary, LedgerEntry, VerificationResult, SystemHealth } from './types';

const API_BASE = 'http://127.0.0.1:8080';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'scoreboard' | 'verifier' | 'threat-model'>('scoreboard');
  const [activeMode, setActiveMode] = useState<'baseline' | 'triseal'>('triseal');
  const [activeRuntime, setActiveRuntime] = useState<string>('runsc');
  const [health, setHealth] = useState<SystemHealth | null>(null);

  const [baselineResults, setBaselineResults] = useState<TestSuiteSummary | null>(null);
  const [trisealResults, setTrisealResults] = useState<TestSuiteSummary | null>(null);
  const [ledgerEntries, setLedgerEntries] = useState<LedgerEntry[]>([]);
  const [roundInfo, setRoundInfo] = useState<Record<string, any> | null>(null);

  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [runningTestId, setRunningTestId] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [tamperAlert, setTamperAlert] = useState<{ alert: boolean; brokenSeq?: number; reason?: string } | null>(null);

  // Fetch initial system data
  const fetchData = async () => {
    try {
      const [hRes, tRes, lRes, rRes] = await Promise.all([
        fetch(`${API_BASE}/v1/health`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/v1/tests/results`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/v1/ledger`).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/v1/rounds/current`).then(r => r.json()).catch(() => null),
      ]);

      if (hRes) {
        setHealth(hRes);
        setActiveRuntime(hRes.active_runtime || 'runsc');
      }
      if (tRes) {
        setBaselineResults(tRes.baseline);
        setTrisealResults(tRes.triseal);
      }
      if (lRes?.entries) {
        setLedgerEntries(lRes.entries);
      }
      if (rRes) {
        setRoundInfo(rRes);
      }
    } catch {
      // Fallback local defaults if control plane not yet connected
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  // Run Test Suite via SSE
  const handleRunAll = (mode: 'baseline' | 'triseal') => {
    setIsRunning(true);
    setRunningTestId('Initiating...');

    const eventSource = new EventSource(`${API_BASE}/v1/tests/run/stream?mode=${mode}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event === 'running') {
          setRunningTestId(data.test_id);
        } else if (data.event === 'completed_test') {
          // Update in-memory result
          const res = data.result;
          if (mode === 'baseline') {
            setBaselineResults(prev => {
              const prevResults = prev?.results || [];
              const updated = [...prevResults.filter(r => r.test_id !== res.test_id), res];
              return { mode: 'baseline', runtime: activeRuntime, timestamp: new Date().toISOString(), tests_total: 8, passed: updated.filter(r => r.status === 'PASS').length, failed: updated.filter(r => r.status === 'FAIL').length, skipped: updated.filter(r => r.status === 'SKIPPED').length, results: updated };
            });
          } else {
            setTrisealResults(prev => {
              const prevResults = prev?.results || [];
              const updated = [...prevResults.filter(r => r.test_id !== res.test_id), res];
              return { mode: 'triseal', runtime: activeRuntime, timestamp: new Date().toISOString(), tests_total: 8, passed: updated.filter(r => r.status === 'PASS').length, failed: updated.filter(r => r.status === 'FAIL').length, skipped: updated.filter(r => r.status === 'SKIPPED').length, results: updated };
            });
          }
        } else if (data.event === 'done') {
          setIsRunning(false);
          setRunningTestId(null);
          eventSource.close();
          fetchData();
        }
      } catch {
        // Parse error ignored
      }
    };

    eventSource.onerror = () => {
      setIsRunning(false);
      setRunningTestId(null);
      eventSource.close();
    };
  };

  // Ledger Verification Action
  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const res = await fetch(`${API_BASE}/v1/ledger/verify`).then(r => r.json());
      setVerificationResult(res.chain);
    } catch {
      // Ignored
    } finally {
      setIsVerifying(false);
    }
  };

  // Tamper Demo Action
  const handleTamperDemo = async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/ledger/tamper-demo`, { method: 'POST' }).then(r => r.json());
      setTamperAlert({
        alert: res.alert,
        brokenSeq: res.broken_seq,
        reason: res.reason,
      });
    } catch {
      // Ignored
    }
  };

  // Export Evidence Action
  const handleExportEvidence = () => {
    window.location.href = `${API_BASE}/v1/evidence/export`;
  };

  return (
    <div className="min-h-screen bg-console-bg text-console-text font-mono flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-console-border bg-console-surface/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded bg-chamber-blue/20 border border-chamber-blue/50 flex items-center justify-center text-chamber-blue font-bold">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-sm tracking-wider text-white">TRISEAL</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-chamber-blue/20 text-chamber-blue border border-chamber-blue/30 uppercase font-bold">
                  Track 04 · Bayora
                </span>
              </div>
              <span className="text-[10px] text-console-muted hidden sm:block">
                Adversarial AI Safety Infrastructure Sandbox
              </span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center space-x-1">
            <button
              onClick={() => setActiveTab('scoreboard')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs transition ${
                activeTab === 'scoreboard'
                  ? 'bg-console-card text-white border border-console-border'
                  : 'text-console-muted hover:text-white'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-chamber-blue" />
              <span>Scoreboard</span>
            </button>

            <button
              onClick={() => setActiveTab('verifier')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs transition ${
                activeTab === 'verifier'
                  ? 'bg-console-card text-white border border-console-border'
                  : 'text-console-muted hover:text-white'
              }`}
            >
              <FileCheck className="w-3.5 h-3.5 text-sec-pass" />
              <span>Audit Verifier</span>
            </button>

            <button
              onClick={() => setActiveTab('threat-model')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs transition ${
                activeTab === 'threat-model'
                  ? 'bg-console-card text-white border border-console-border'
                  : 'text-console-muted hover:text-white'
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-chamber-arbiter" />
              <span>Round & Threat Model</span>
            </button>
          </nav>

          {/* Mode Switcher */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveMode(m => m === 'triseal' ? 'baseline' : 'triseal')}
              className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider border transition ${
                activeMode === 'triseal'
                  ? 'bg-sec-pass/10 text-sec-pass border-sec-pass/40 hover:bg-sec-pass/20'
                  : 'bg-sec-fail/10 text-sec-fail border-sec-fail/40 hover:bg-sec-fail/20'
              }`}
            >
              Mode: {activeMode}
            </button>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        {activeTab === 'scoreboard' && (
          <ScoreboardView
            baselineResults={baselineResults}
            trisealResults={trisealResults}
            activeMode={activeMode}
            activeRuntime={activeRuntime}
            onRunAll={handleRunAll}
            isRunning={isRunning}
            runningTestId={runningTestId}
          />
        )}

        {activeTab === 'verifier' && (
          <AuditVerifierView
            entries={ledgerEntries}
            onVerify={handleVerify}
            onTamperDemo={handleTamperDemo}
            onExportEvidence={handleExportEvidence}
            verificationResult={verificationResult}
            tamperAlert={tamperAlert}
            isVerifying={isVerifying}
          />
        )}

        {activeTab === 'threat-model' && (
          <RoundThreatModelView roundInfo={roundInfo} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-console-border bg-console-surface/50 py-3 text-center text-[11px] text-console-muted font-mono">
        TriSeal Prototype · Hack in Hills '26 · Verified Isolation Sandbox · Zero Mocked Data
      </footer>
    </div>
  );
};
