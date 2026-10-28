import React from 'react';
import { Layers, ShieldCheck, AlertTriangle, Lock, Eye, Key, CheckCircle, Clock } from 'lucide-react';

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
      {/* Round Lifecycle Stepper labeled 'Demo round' per Requirement 8 */}
      <div className="bg-console-surface border border-console-border p-5 rounded-lg space-y-4">
        <div className="flex items-center justify-between border-b border-console-border pb-3">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-chamber-blue" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">
              Demo round timeline
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-300">
            Round ID: <strong className="text-white">{roundInfo?.round_id || 'round_init_01'}</strong>
          </span>
        </div>

        {/* Cost callout per Requirement 8 */}
        <div className="flex items-center space-x-2 p-3 bg-amber-950/20 border border-amber-500/30 rounded text-xs font-mono text-amber-200">
          <Clock className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>Cost: fixed-time replies take about 1.4 s each.</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-1">
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
                    ? 'bg-console-card border-emerald-500/40 text-emerald-300'
                    : 'bg-console-card/40 border-console-border text-slate-400'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold tracking-widest text-slate-400">STEP 0{idx+1}</span>
                  <Icon className="w-3.5 h-3.5" />
                </div>
                <div className="font-bold text-xs mt-1 text-white">{st.name}</div>
                <div className="text-[11px] text-slate-300 mt-1 leading-snug">{st.desc}</div>
              </div>
            );
          })}
        </div>

        {/* Current Round Commit Details */}
        <div className="bg-console-card p-3 rounded border border-console-border space-y-2 mt-4 text-xs font-mono">
          <span className="text-[11px] uppercase text-slate-300 font-bold block">
            Cryptographic Commit Hashes (SHA-256)
          </span>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="p-2.5 bg-console-bg rounded border border-console-border">
              <span className="text-[10px] text-rose-400 font-bold uppercase block">Red Payload Commit</span>
              <span className="text-slate-200 text-xs break-all block font-mono mt-0.5">
                {roundInfo?.commits?.red || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
              </span>
            </div>
            <div className="p-2.5 bg-console-bg rounded border border-console-border">
              <span className="text-[10px] text-sky-400 font-bold uppercase block">Blue Guard Commit</span>
              <span className="text-slate-200 text-xs break-all block font-mono mt-0.5">
                {roundInfo?.commits?.blue || '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Honest Threat Model & Residual Risk Matrix per Requirement 8 */}
      <div className="bg-console-surface border border-console-border p-5 rounded-lg space-y-4">
        <div className="border-b border-console-border pb-3 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">
              Threat Model & Operational Boundaries
            </h2>
          </div>
          <span className="text-xs text-slate-400 font-mono">docs/threat-model.md</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Protects against */}
          <div className="bg-console-card p-4 rounded border border-emerald-500/40 space-y-3">
            <h3 className="text-xs font-bold text-emerald-300 uppercase tracking-wider flex items-center space-x-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              <span>Protects against</span>
            </h3>
            <ul className="text-xs text-slate-200 space-y-2 list-disc list-inside leading-relaxed">
              <li>Network access between chambers (no outbound connections)</li>
              <li>Timing clues that reveal which prompts were blocked (replies released at a fixed time)</li>
              <li>Prompt-cache reuse across tenants (cache off, memory wiped each session; timing test inconclusive on CPU)</li>
              <li>Secrets carried between sessions (none recalled in tests)</li>
              <li>Edited or deleted logs (signed hash chain with published anchor)</li>
            </ul>
          </div>

          {/* Does not protect against */}
          <div className="bg-console-card p-4 rounded border border-rose-500/40 space-y-3">
            <h3 className="text-xs font-bold text-rose-300 uppercase tracking-wider flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              <span>Does not protect against</span>
            </h3>
            <ul className="text-xs text-slate-200 space-y-2 list-disc list-inside leading-relaxed">
              <li>A malicious host administrator</li>
              <li>Kernel or sandbox zero-day bugs</li>
              <li>Hardware side channels (shared GPU not tested; this build is CPU-only)</li>
              <li>Red and blue teams colluding</li>
            </ul>
          </div>

          {/* When guarantees fail */}
          <div className="bg-console-card p-4 rounded border border-amber-500/40 space-y-3">
            <h3 className="text-xs font-bold text-amber-300 uppercase tracking-wider flex items-center space-x-1.5">
              <Lock className="w-3.5 h-3.5 text-amber-400" />
              <span>When guarantees fail</span>
            </h3>
            <ul className="text-xs text-slate-200 space-y-2 list-disc list-inside leading-relaxed">
              <li>The control plane is compromised (it holds the Docker socket)</li>
              <li>The signing key is stolen (only the published anchor limits the damage)</li>
              <li>Someone bypasses the Arbiter</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
