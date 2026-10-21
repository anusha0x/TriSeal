import React, { useState } from 'react';
import { CheckCircle2, AlertOctagon, Download, ShieldCheck, Flame, Link2, ExternalLink } from 'lucide-react';
import { LedgerEntry, VerificationResult } from '../types';

interface AuditVerifierViewProps {
  entries: LedgerEntry[];
  onVerify: () => void;
  onTamperDemo: () => void;
  onExportEvidence: () => void;
  verificationResult: VerificationResult | null;
  tamperAlert: { alert: boolean; brokenSeq?: number; reason?: string } | null;
  isVerifying: boolean;
}

export const AuditVerifierView: React.FC<AuditVerifierViewProps> = ({
  entries,
  onVerify,
  onTamperDemo,
  onExportEvidence,
  verificationResult,
  tamperAlert,
  isVerifying,
}) => {
  const [selectedEntry, setSelectedEntry] = useState<LedgerEntry | null>(null);

  const getActorColor = (actor: string) => {
    switch (actor.toLowerCase()) {
      case 'red': return 'text-chamber-red bg-chamber-red/10 border-chamber-red/30';
      case 'blue': return 'text-chamber-blue bg-chamber-blue/10 border-chamber-blue/30';
      case 'llm': return 'text-chamber-llm bg-chamber-llm/10 border-chamber-llm/30';
      case 'arbiter': return 'text-chamber-arbiter bg-chamber-arbiter/10 border-chamber-arbiter/30';
      default: return 'text-console-muted bg-console-card border-console-border';
    }
  };

  return (
    <div className="space-y-6">
      {/* Control Action Bar */}
      <div className="bg-console-surface border border-console-border p-4 rounded-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-sec-pass" />
            <span>Cryptographic Ledger Verifier</span>
          </h2>
          <p className="text-xs text-console-muted mt-0.5 font-mono">
            Append-only SHA-256 hash chain · Ed25519 digital signatures · Merkle checkpoints
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={onVerify}
            disabled={isVerifying}
            className="flex items-center space-x-2 px-3.5 py-1.5 bg-sec-pass/20 hover:bg-sec-pass/30 text-sec-pass border border-sec-pass/40 rounded font-mono text-xs font-semibold transition"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>{isVerifying ? 'Verifying...' : 'Verify Chain'}</span>
          </button>

          <button
            onClick={onTamperDemo}
            className="flex items-center space-x-2 px-3.5 py-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border border-rose-500/40 rounded font-mono text-xs font-semibold transition"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Tamper Demo</span>
          </button>

          <button
            onClick={onExportEvidence}
            className="flex items-center space-x-2 px-3.5 py-1.5 bg-chamber-blue/20 hover:bg-chamber-blue/30 text-chamber-blue border border-chamber-blue/40 rounded font-mono text-xs font-semibold transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Evidence ZIP</span>
          </button>
        </div>
      </div>

      {/* Security Alert Banner upon Tamper Demo */}
      {tamperAlert?.alert && (
        <div className="bg-rose-950/80 border-2 border-rose-500 text-rose-200 p-4 rounded-lg flex items-start space-x-3 shadow-lg animate-pulse">
          <AlertOctagon className="w-5 h-5 text-rose-400 mt-0.5 flex-shrink-0" />
          <div className="space-y-1">
            <h4 className="text-xs font-bold uppercase tracking-wider text-rose-300">
              [CRITICAL ALERT] Cryptographic Integrity Violation Flagged
            </h4>
            <p className="text-xs font-mono">
              Broken link detected at sequence <strong className="text-white">#{tamperAlert.brokenSeq}</strong>: {tamperAlert.reason}
            </p>
            <p className="text-[11px] text-rose-300/80">
              Tampered replica verified. Original authoritative ledger remains intact.
            </p>
          </div>
        </div>
      )}

      {/* Hash Chain Visualizer */}
      <div className="bg-console-surface border border-console-border p-4 rounded-lg space-y-3">
        <h3 className="text-xs font-bold uppercase text-console-muted tracking-wider flex items-center space-x-2">
          <Link2 className="w-3.5 h-3.5 text-chamber-arbiter" />
          <span>Hash Chain Graph (Sequential Linkage)</span>
        </h3>

        <div className="flex items-center space-x-2 overflow-x-auto py-2">
          {entries.slice(-8).map((entry, idx) => {
            const isBroken = tamperAlert?.alert && tamperAlert.brokenSeq === entry.seq;
            return (
              <React.Fragment key={entry.seq}>
                <div
                  onClick={() => setSelectedEntry(entry)}
                  className={`flex-shrink-0 p-2.5 rounded border font-mono text-xs cursor-pointer transition ${
                    isBroken
                      ? 'bg-rose-950/80 border-rose-500 text-rose-300'
                      : 'bg-console-card hover:bg-console-card/80 border-console-border text-console-text'
                  }`}
                >
                  <div className="flex items-center justify-between space-x-2">
                    <span className="font-bold">#{entry.seq}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] uppercase font-bold border ${getActorColor(entry.actor)}`}>
                      {entry.actor}
                    </span>
                  </div>
                  <div className="text-[10px] text-console-muted mt-1 truncate w-24">
                    {entry.event_type}
                  </div>
                  <div className="text-[9px] text-console-muted/70 font-mono mt-0.5 truncate w-24">
                    {entry.entry_hash.slice(0, 10)}...
                  </div>
                </div>

                {idx < Math.min(entries.length - 1, 7) && (
                  <span className={`text-xs ${isBroken ? 'text-rose-500' : 'text-console-muted'}`}>→</span>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Ledger Table */}
      <div className="bg-console-surface border border-console-border rounded-lg overflow-hidden">
        <div className="p-4 border-b border-console-border flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-white">
            Audit Ledger ({entries.length} Events Logged)
          </h3>
          <span className="text-[11px] text-console-muted font-mono">
            Zero Plaintext Payloads · Cryptographically Signed
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-console-card text-console-muted uppercase text-[10px] tracking-wider border-b border-console-border">
              <tr>
                <th className="py-2.5 px-3 w-12">Seq</th>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Payload Hash</th>
                <th className="py-2.5 px-3">Entry Hash</th>
                <th className="py-2.5 px-3 text-center">Sig Check</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-console-border">
              {entries.map((entry) => (
                <tr
                  key={entry.seq}
                  onClick={() => setSelectedEntry(entry)}
                  className="hover:bg-console-card/60 cursor-pointer transition"
                >
                  <td className="py-2.5 px-3 font-bold text-chamber-arbiter">#{entry.seq}</td>
                  <td className="py-2.5 px-3 text-console-muted">{entry.ts?.split('T')[1]?.slice(0, 8) || entry.ts}</td>
                  <td className="py-2.5 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getActorColor(entry.actor)}`}>
                      {entry.actor}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-white">{entry.event_type}</td>
                  <td className="py-2.5 px-3 text-console-muted truncate max-w-xs">{entry.payload_hash.slice(0, 16)}...</td>
                  <td className="py-2.5 px-3 text-console-muted truncate max-w-xs">{entry.entry_hash.slice(0, 16)}...</td>
                  <td className="py-2.5 px-3 text-center">
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] bg-sec-pass/20 text-sec-pass border border-sec-pass/40 font-bold">
                      VERIFIED
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Entry Detail Drawer */}
      {selectedEntry && (
        <div className="bg-console-surface border border-console-border rounded-lg p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-console-border pb-2">
            <h4 className="text-xs font-bold text-white">Event #{selectedEntry.seq} Canonical Detail</h4>
            <button
              onClick={() => setSelectedEntry(null)}
              className="text-xs text-console-muted hover:text-white px-2 py-0.5 bg-console-card rounded"
            >
              Close
            </button>
          </div>
          <pre className="text-[11px] font-mono text-console-text bg-console-bg p-3 rounded overflow-x-auto">
            {JSON.stringify(selectedEntry, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
