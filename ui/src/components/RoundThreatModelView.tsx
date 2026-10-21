import React from 'react';
import { Layers, ShieldCheck, AlertTriangle, Lock, Eye, Key, CheckCircle } from 'lucide-react';

interface RoundThreatModelViewProps {
  roundInfo: Record<string, any> | null;
}

export const RoundThreatModelView: React.FC<RoundThreatModelViewProps> = ({ roundInfo }) => {
  const steps = [
    { name: 'COMMIT', desc: 'Pre-round cryptographic hashes committed to ledger', icon: Lock },
    { name: 'SEAL', desc: 'Chambers sealed, zero egress, capability tokens issued', icon: ShieldCheck },
    { name: 'RUN', desc: 'Attack runner submits payloads via Arbiter gateway', icon: Eye },
    { name: 'REVEAL', desc: 'Decryption keys released; materials audited against commits', icon: Key },
    { name: 'VERIFY', desc: 'Cryptographic ledger chain & Merkle checkpoints validated', icon: CheckCircle },
  ];

  const currentState = roundInfo?.state || 'COMMIT';

  return (
    <div className="space-y-6">
      {/* Round Lifecycle Stepper */}
      <div className="bg-console-surface border border-console-border p-5 rounded-lg space-y-4">
        <div className="flex items-center justify-between border-b border-console-border pb-3">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-chamber-blue" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">
              Round Lifecycle & State Machine
            </h2>
          </div>
          <span className="text-xs font-mono text-console-muted">
            Round ID: <strong className="text-white">{roundInfo?.round_id || 'round_init_01'}</strong>
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
          {steps.map((st, idx) => {
            const Icon = st.icon;
            const isCurrent = currentState === st.name;
            const isPast = ['COMMIT', 'SEAL', 'RUN', 'REVEAL', 'VERIFY', 'COMPLETED'].indexOf(currentState) >= idx;

            return (
              <div
                key={st.name}
                className={`p-3.5 rounded border font-mono transition ${
                  isCurrent
                    ? 'bg-chamber-blue/20 border-chamber-blue text-white ring-1 ring-chamber-blue/50'
                    : isPast
                    ? 'bg-console-card border-sec-pass/40 text-sec-pass'
                    : 'bg-console-card/40 border-console-border text-console-muted'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold tracking-widest text-console-muted">STEP 0{idx+1}</span>
                  <Icon className="w-3.5 h-3.5" />
                </div>
                <div className="font-bold text-xs mt-1">{st.name}</div>
                <div className="text-[10px] text-console-muted mt-1 leading-snug">{st.desc}</div>
              </div>
            );
          })}
        </div>

        {/* Current Round Commit Details */}
        <div className="bg-console-card p-3 rounded border border-console-border space-y-2 mt-4 text-xs font-mono">
          <span className="text-[10px] uppercase text-console-muted font-bold block">
            Cryptographic Commit Hashes (SHA-256)
          </span>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="p-2 bg-console-bg rounded border border-console-border">
              <span className="text-[10px] text-chamber-red font-bold uppercase block">Red Payload Commit</span>
              <span className="text-console-text text-[11px] truncate block font-mono">
                {roundInfo?.commits?.red || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
              </span>
            </div>
            <div className="p-2 bg-console-bg rounded border border-console-border">
              <span className="text-[10px] text-chamber-blue font-bold uppercase block">Blue Guard Commit</span>
              <span className="text-console-text text-[11px] truncate block font-mono">
                {roundInfo?.commits?.blue || '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Residual Risk Matrix */}
      <div className="bg-console-surface border border-console-border p-5 rounded-lg space-y-4">
        <div className="border-b border-console-border pb-3 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-sec-warn" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">
              Honest Threat Model & Residual Risk Matrix
            </h2>
          </div>
          <span className="text-xs text-console-muted font-mono">docs/threat-model.md</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Protects Against */}
          <div className="bg-console-card p-4 rounded border border-sec-pass/30 space-y-2.5">
            <h3 className="text-xs font-bold text-sec-pass uppercase tracking-wider flex items-center space-x-1.5">
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Protects Against</span>
            </h3>
            <ul className="text-xs text-console-text space-y-1.5 list-disc list-inside">
              <li>Direct network exfiltration & lateral movement (0 egress internal networks)</li>
              <li>Timing oracles via fixed-deadline uniform envelopes (D = p99 + margin)</li>
              <li>KV-cache snooping & PromptPeek side channels via per-tenant slot isolation</li>
              <li>Model context contamination & cross-session memory leaks</li>
              <li>Post-hoc audit tampering via Ed25519-signed SHA-256 hash chains</li>
            </ul>
          </div>

          {/* Does NOT Protect Against */}
          <div className="bg-console-card p-4 rounded border border-sec-fail/30 space-y-2.5">
            <h3 className="text-xs font-bold text-sec-fail uppercase tracking-wider flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Does NOT Protect Against</span>
            </h3>
            <ul className="text-xs text-console-text space-y-1.5 list-disc list-inside">
              <li>Malicious host operator with physical or root access to Linux host</li>
              <li>Linux kernel 0-day privilege escalations escaping gVisor/container runtimes</li>
              <li>Shared physical GPU side channels (N/A in current prototype; CPU-only build)</li>
              <li>Off-band human collusion across red and blue safety teams</li>
            </ul>
          </div>

          {/* When Guarantees Fail */}
          <div className="bg-console-card p-4 rounded border border-sec-warn/30 space-y-2.5">
            <h3 className="text-xs font-bold text-sec-warn uppercase tracking-wider flex items-center space-x-1.5">
              <Lock className="w-3.5 h-3.5" />
              <span>When Guarantees Fail</span>
            </h3>
            <ul className="text-xs text-console-text space-y-1.5 list-disc list-inside">
              <li>If the trusted Control Plane process is compromised (holds Docker socket)</li>
              <li>If Ed25519 signing keys are exfiltrated from the host key store</li>
              <li>If Red queries exhaust quota and attempt offline inference without Arbiter</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
