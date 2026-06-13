'use client';

import { useEffect, useState } from 'react';
import { fetchChainStats, ChainStats } from '@/lib/contracts';

// Static defaults shown while loading or when chain is unreachable
const DEFAULTS = {
  audits: 3,
  hashes: 3,
  memories: 14,
  erc7857: 3,
  exploits: 782,
};


export function StatsSection() {
  const [chain, setChain] = useState<ChainStats | null>(null);

  useEffect(() => {
    fetchChainStats().then(setChain).catch(() => {/* stay on defaults */});
  }, []);

  const audits   = chain?.online ? chain.auditsCompleted  : DEFAULTS.audits;
  const hashes   = chain?.online ? chain.rootHashesStored : DEFAULTS.hashes;
  const erc7857  = chain?.online ? chain.erc7857Updates   : DEFAULTS.erc7857;

  const STATS = [
    {
      value: String(audits),
      label: 'Audits Completed',
      sub: 'ERC-8183 finalized audit reports',
      accent: 'var(--cyan)',
    },
    {
      value: String(audits),
      label: 'Agent Memory',
      sub: 'ERC-7857 on-chain audits memory',
      accent: '#00ff88',
    },
    {
      value: String(DEFAULTS.memories),
      label: 'Historical Memories',
      sub: 'cognition entries loaded',
      accent: '#ffd60a',
    },
    {
      value: String(DEFAULTS.exploits),
      label: 'Exploit Patterns',
      sub: 'on-chain',
      accent: 'var(--blue)',
    },
  ];

  return (
    <section className="section">
      <div className="section-inner">
        <div style={{ marginBottom: 52 }}>
          <div className="section-label">Runtime Statistics</div>
          <h2 className="section-title">Cognition Metrics</h2>
          <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16 }}>
            <p className="section-desc" style={{ margin: 0, whiteSpace: 'nowrap' }}>
              Live infrastructure metrics from the RAXCLAW autonomous execution runtime.
            </p>
            {chain && (
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: chain.online ? '#00ff88' : 'var(--text-dim)', whiteSpace: 'nowrap', flexShrink: 0 }}>
                ● {chain.online ? 'Arbitrum Sepolia live' : 'chain unreachable'}
              </span>
            )}
          </div>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
            gap: 16,
          }}
        >
          {STATS.map((s) => (
            <div
              key={s.label}
              className="glass-card"
              style={{ padding: '26px 22px', position: 'relative', overflow: 'hidden' }}
            >
              {/* Bottom glow accent */}
              <div
                aria-hidden
                style={{
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  right: 0,
                  height: 2,
                  background: `linear-gradient(90deg, transparent, ${s.accent}44, transparent)`,
                }}
              />
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 40,
                  fontWeight: 700,
                  color: s.accent,
                  marginBottom: 8,
                  lineHeight: 1,
                  letterSpacing: '-0.02em',
                }}
              >
                {s.value}
              </div>
              <div
                style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}
              >
                {s.label}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{s.sub}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
