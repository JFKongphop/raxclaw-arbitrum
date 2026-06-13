'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ADDRESSES } from '@/lib/contracts';

const RPC_PROXY = '/api/rpc';
const TOPIC_AUDIT_FINALIZED = '0x75bbe3dc8e0f2f58150426e10f769081aec81ccca23597719a02ce258bb4ea46';
const RISK_LABELS = ['None', 'Low', 'Medium', 'High', 'Critical'];

function isTxHash(h: string): boolean { return /^0x[0-9a-fA-F]{64}$/.test(h); }

async function rpcCall(method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(RPC_PROXY, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message);
  return json.result;
}

async function fetchReportFromStylus(txHash: string) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const receipt = await rpcCall('eth_getTransactionReceipt', [txHash]) as Record<string, unknown> | null;
      if (!receipt || !receipt.logs) return null;
      const logs = receipt.logs as Array<{ address: string; topics: string[]; data: string }>;
      const log = logs.find(l => l.address.toLowerCase() === ADDRESSES.auditReport.toLowerCase() && l.topics[0] === TOPIC_AUDIT_FINALIZED);
      if (!log) return null;

      const taskId = BigInt(log.topics[1]);
      const data = log.data.slice(2);
      const riskLevel = parseInt(data.slice(0, 64), 16);
      const confidence = parseInt(data.slice(64, 128), 16);
      const reportHash = '0x' + data.slice(128, 192);
      const timestamp = parseInt(data.slice(192, 256), 16);

      const selector = '0x4e7f9b19'; // getReport(uint256)
      const callData = selector + taskId.toString(16).padStart(64, '0');
      const resultHex = await rpcCall('eth_call', [{ to: ADDRESSES.auditReport, data: callData }, 'latest']) as string;

      const hex = resultHex.slice(2);
      const offset = parseInt(hex.slice(0, 64), 16) * 2;
      const len = parseInt(hex.slice(offset, offset + 64), 16) * 2;
      const dataHex = hex.slice(offset + 64, offset + 64 + len);
      const bytes = new Uint8Array(dataHex.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(dataHex.slice(i * 2, i * 2 + 2), 16);

      return {
        report: new TextDecoder().decode(bytes),
        taskId: taskId.toString(),
        riskLevel: RISK_LABELS[riskLevel] ?? 'Unknown',
        confidence,
        reportHash,
        completedAt: new Date(timestamp * 1000),
      };
    } catch {
      if (attempt < 2) await new Promise(r => setTimeout(r, (attempt + 1) * 1500));
    }
  }
  return null;
}

export default function RootHashPage() {
  const router = useRouter();
  const params = useParams<{ hash: string }>();
  const hash = params.hash;
  const tx = isTxHash(hash);

  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [meta, setMeta] = useState<{ taskId: string; reportHash: string; riskLevel: string; confidence: number; completedAt: Date } | null>(null);

  const load = useCallback(async () => {
    if (!tx) { setLoading(false); return; }
    setLoading(true);
    const result = await fetchReportFromStylus(hash);
    if (result) {
      setContent(result.report);
      setMeta({ taskId: result.taskId, reportHash: result.reportHash, riskLevel: result.riskLevel, confidence: result.confidence, completedAt: result.completedAt });
    } else {
      setFailed(true);
    }
    setLoading(false);
  }, [hash]);

  useEffect(() => { load(); }, [load]);

  return (
    <main style={{ minHeight: '100vh', background: 'var(--bg)', color: 'var(--text)' }}>
      <div style={{ borderBottom: '1px solid rgba(0,212,255,0.1)', padding: '16px 32px', display: 'flex', alignItems: 'center', gap: 20 }}>
        <button onClick={() => router.push('/#audits')} style={{ background: 'none', border: '1px solid rgba(0,212,255,0.2)', color: 'var(--cyan)', borderRadius: 6, padding: '6px 16px', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          &#8592; Back
        </button>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
          {tx ? 'Arbitrum Stylus · Audit Report' : 'Root Hash'}
        </div>
      </div>

      <div style={{ maxWidth: 900, margin: '0 auto', padding: '40px 32px 80px' }}>
        {/* Header card */}
        <div className="glass-card" style={{ padding: '20px 24px', marginBottom: 32 }}>
          <div style={{ fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--cyan)', fontFamily: 'var(--font-mono)', marginBottom: 10 }}>
            {tx ? 'On-Chain Audit Report' : 'Root Hash'}
          </div>

          {tx && meta ? (
            <a
              href={`https://sepolia.arbiscan.io/tx/${hash}`}
              target="_blank"
              rel="noopener noreferrer"
              style={{ display: 'flex', flexDirection: 'column', gap: 8, textDecoration: 'none', color: 'inherit' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>Task #{meta.taskId}</span>
                <span style={{ color: 'rgba(255,255,255,0.15)' }}>|</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: meta.riskLevel === 'High' || meta.riskLevel === 'Critical' ? 'var(--red)' : 'var(--yellow)' }}>{meta.riskLevel}</span>
                <span style={{ color: 'rgba(255,255,255,0.15)' }}>|</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)' }}>{meta.confidence}%</span>
                <span style={{ color: 'rgba(255,255,255,0.15)' }}>|</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{meta.completedAt.toLocaleString()}</span>
              </div>
              <div className="hash" style={{ fontSize: 12, wordBreak: 'break-all' }}>{hash}</div>
            </a>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="hash" style={{ fontSize: 12, wordBreak: 'break-all', flex: 1 }}>{hash}</span>
            </div>
          )}

          {failed && (
            <div style={{ marginTop: 14, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--yellow)' }}>
              {tx ? '⚠ Could not read report from Stylus contract.' : '⚠ Hash not found.'}
            </div>
          )}
        </div>

        {/* Report content */}
        {tx && loading && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
            Fetching report from Arbitrum Sepolia…
          </div>
        )}
        {tx && content && (
          <div className="report-content">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
          </div>
        )}
      </div>
    </main>
  );
}
