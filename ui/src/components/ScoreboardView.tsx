import React, { useState } from 'react';
import { Play, Shield, AlertTriangle, CheckCircle, XCircle, ArrowUpRight, BarChart2, RefreshCw } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { TestResult, TestSuiteSummary } from '../types';

interface ScoreboardViewProps {
  baselineResults: TestSuiteSummary | null;
  trisealResults: TestSuiteSummary | null;
  activeMode: 'baseline' | 'triseal';
  activeRuntime: string;
  onRunAll: (mode: 'baseline' | 'triseal') => void;
  isRunning: boolean;
  runningTestId: string | null;
}

export const ScoreboardView: React.FC<ScoreboardViewProps> = ({
  baselineResults,
  trisealResults,
  activeMode,
  activeRuntime,
  onRunAll,
  isRunning,
  runningTestId,
}) => {
  const [selectedTest, setSelectedTest] = useState<TestResult | null>(null);

  const testDefinitions = [
    { id: 'T1', name: 'Container escape', desc: 'Benign probes (mount, ptrace, /proc/1/environ, docker.sock, effective capabilities, write outside rootfs, /dev/mem)' },
    { id: 'T2', name: 'Network crossing', desc: 'Socket connection probes from Red to Blue, LLM, Ledger, and external internet' },
    { id: 'T3', name: 'Storage snooping', desc: 'Cross-tenant volume reads, sensitive /proc snooping, and canary file inspection' },
    { id: 'T4', name: 'Timing oracle', desc: 'N guard-blocked vs N model-refused prompt latency distributions (p95 delta)' },
    { id: 'T5', name: 'KV-cache probe', desc: 'PromptPeek time-to-first-token (TTFT) cache hit vs cache miss differential' },
    { id: 'T6', name: 'Contamination', desc: 'Cross-session memory persistence, canary codeword recall, and weight hash match' },
    { id: 'T7', name: 'Log tamper', desc: 'Cryptographic hash-chain and Ed25519 signature audit upon ledger corruption' },
    { id: 'T8', name: 'Starvation', desc: 'Red container CPU stress worker vs Blue/LLM response latency variance' },
  ];

  const getResult = (summary: TestSuiteSummary | null, id: string): TestResult | undefined => {
    return summary?.results?.find(r => r.test_id === id);
  };

  const leaksFoundInBaseline = baselineResults?.results?.filter(r => r.status === 'FAIL').length || 0;
  const blockedInTriseal = trisealResults?.results?.filter(r => r.status === 'PASS').length || 0;

  return (
    <div className="space-y-6">
      {/* Top Status Bar */}
      <div className="bg-console-surface border border-console-border p-4 rounded-lg flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <span className="text-xs uppercase tracking-wider text-console-muted">Mode:</span>
            <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider ${
              activeMode === 'triseal' ? 'bg-sec-pass/20 text-sec-pass border border-sec-pass/40' : 'bg-sec-fail/20 text-sec-fail border border-sec-fail/40'
            }`}>
              {activeMode}
            </span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs uppercase tracking-wider text-console-muted">Chamber Runtime:</span>
            <span className="px-2.5 py-1 rounded text-xs font-mono bg-chamber-blue/20 text-chamber-blue border border-chamber-blue/40 font-bold">
              {activeRuntime}
            </span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs uppercase tracking-wider text-console-muted">Scoreboard:</span>
            <span className="text-xs font-mono text-console-text">
              Leaks in Baseline: <strong className="text-sec-fail">{leaksFoundInBaseline}/8</strong> · Blocked in TriSeal: <strong className="text-sec-pass">{blockedInTriseal}/8</strong>
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => onRunAll(activeMode)}
            disabled={isRunning}
            className="flex items-center space-x-2 px-4 py-2 bg-chamber-blue hover:bg-chamber-blue/80 disabled:opacity-50 text-white rounded font-mono text-xs font-semibold transition"
          >
            {isRunning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isRunning ? `Running ${runningTestId || 'Tests'}...` : `Run All (${activeMode.toUpperCase()})`}</span>
          </button>
        </div>
      </div>

      {/* Main Scoreboard Table */}
      <div className="bg-console-surface border border-console-border rounded-lg overflow-hidden">
        <div className="p-4 border-b border-console-border flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-wider flex items-center space-x-2 text-white">
            <Shield className="w-4 h-4 text-chamber-blue" />
            <span>Defensive Leak Test Suite · Scoreboard</span>
          </h2>
          <span className="text-xs text-console-muted font-mono">
            Comparing Unsealed Baseline vs Hardened TriSeal
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-console-card text-console-muted uppercase text-[10px] tracking-wider border-b border-console-border">
              <tr>
                <th className="py-3 px-4 w-12">ID</th>
                <th className="py-3 px-4">Defensive Test Probe</th>
                <th className="py-3 px-4">Target Criteria</th>
                <th className="py-3 px-4">Measured Outcome</th>
                <th className="py-3 px-4 text-center">Baseline</th>
                <th className="py-3 px-4 text-center">TriSeal</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-console-border">
              {testDefinitions.map((td) => {
                const bRes = getResult(baselineResults, td.id);
                const tRes = getResult(trisealResults, td.id);
                const activeRes = activeMode === 'triseal' ? tRes : bRes;

                return (
                  <tr
                    key={td.id}
                    onClick={() => setSelectedTest(activeRes || tRes || bRes || null)}
                    className="hover:bg-console-card/60 cursor-pointer transition"
                  >
                    <td className="py-3.5 px-4 font-bold text-chamber-arbiter">{td.id}</td>
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-white">{td.name}</div>
                      <div className="text-[11px] text-console-muted truncate max-w-xs">{td.desc}</div>
                    </td>
                    <td className="py-3.5 px-4 text-console-muted">{activeRes?.target || '—'}</td>
                    <td className="py-3.5 px-4">
                      <span className="text-console-text font-semibold">
                        {activeRes?.measured_value || (runningTestId === td.id ? 'Measuring...' : 'Pending execution')}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      {bRes ? (
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold ${
                          bRes.status === 'PASS' ? 'bg-sec-pass/20 text-sec-pass border border-sec-pass/30' :
                          bRes.status === 'FAIL' ? 'bg-sec-fail/20 text-sec-fail border border-sec-fail/30' : 'bg-sec-warn/20 text-sec-warn border border-sec-warn/30'
                        }`}>
                          {bRes.status}
                        </span>
                      ) : <span className="text-console-muted">—</span>}
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      {tRes ? (
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold ${
                          tRes.status === 'PASS' ? 'bg-sec-pass/20 text-sec-pass border border-sec-pass/30' :
                          tRes.status === 'FAIL' ? 'bg-sec-fail/20 text-sec-fail border border-sec-fail/30' : 'bg-sec-warn/20 text-sec-warn border border-sec-warn/30'
                        }`}>
                          {tRes.status}
                        </span>
                      ) : <span className="text-console-muted">—</span>}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button className="text-chamber-blue hover:text-white transition p-1">
                        <ArrowUpRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Slide-over / Drawer */}
      {selectedTest && (
        <div className="bg-console-surface border border-console-border rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-console-border pb-3">
            <div className="flex items-center space-x-3">
              <span className="text-xs font-bold px-2 py-1 bg-chamber-arbiter/20 text-chamber-arbiter rounded">
                {selectedTest.test_id}
              </span>
              <h3 className="text-base font-bold text-white">{selectedTest.name} Details</h3>
            </div>
            <button
              onClick={() => setSelectedTest(null)}
              className="text-xs text-console-muted hover:text-white px-2 py-1 bg-console-card rounded border border-console-border"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-console-card p-3 rounded border border-console-border">
              <span className="text-[10px] uppercase text-console-muted block">Status & Mode</span>
              <span className={`text-sm font-bold ${selectedTest.status === 'PASS' ? 'text-sec-pass' : 'text-sec-fail'}`}>
                {selectedTest.status} ({selectedTest.mode.toUpperCase()})
              </span>
            </div>
            <div className="bg-console-card p-3 rounded border border-console-border">
              <span className="text-[10px] uppercase text-console-muted block">Measured Value</span>
              <span className="text-sm font-bold text-white">{selectedTest.measured_value}</span>
            </div>
            <div className="bg-console-card p-3 rounded border border-console-border">
              <span className="text-[10px] uppercase text-console-muted block">Target Criteria</span>
              <span className="text-sm font-mono text-console-muted">{selectedTest.target}</span>
            </div>
          </div>

          {/* Histogram Chart for Timing / Starvation Tests */}
          {selectedTest.evidence && (selectedTest.test_id === 'T4' || selectedTest.test_id === 'T5' || selectedTest.test_id === 'T8') && (
            <div className="bg-console-card p-4 rounded border border-console-border space-y-2">
              <h4 className="text-xs font-bold text-white flex items-center space-x-2">
                <BarChart2 className="w-3.5 h-3.5 text-chamber-blue" />
                <span>Latency Distribution Comparison</span>
              </h4>
              <div className="h-44 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={
                      selectedTest.test_id === 'T4' ? [
                        { name: 'Guard Blocked (p95)', value: selectedTest.evidence.p95_blocked_ms || 0, fill: '#3b82f6' },
                        { name: 'Model Refused (p95)', value: selectedTest.evidence.p95_refused_ms || 0, fill: '#a855f7' },
                        { name: 'Delta', value: selectedTest.evidence.delta_ms || 0, fill: '#ef4444' }
                      ] : selectedTest.test_id === 'T5' ? [
                        { name: 'Cache Hit (TTFT)', value: selectedTest.evidence.time_hit_ms || 0, fill: '#10b981' },
                        { name: 'Cache Miss (TTFT)', value: selectedTest.evidence.time_miss_ms || 0, fill: '#f43f5e' },
                        { name: 'Delta', value: selectedTest.evidence.delta_ms || 0, fill: '#f59e0b' }
                      ] : [
                        { name: 'Idle Avg', value: selectedTest.evidence.avg_idle_ms || 0, fill: '#3b82f6' },
                        { name: 'Stressed Avg', value: selectedTest.evidence.avg_stressed_ms || 0, fill: '#f43f5e' }
                      ]
                    }
                  >
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} unit="ms" />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: '11px' }} />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Raw Evidence JSON */}
          <div className="bg-console-card p-3 rounded border border-console-border">
            <span className="text-[10px] uppercase text-console-muted block mb-1">Raw Evidence Log</span>
            <pre className="text-[11px] font-mono text-console-text overflow-x-auto p-2 bg-console-bg rounded max-h-48">
              {JSON.stringify(selectedTest.evidence, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
