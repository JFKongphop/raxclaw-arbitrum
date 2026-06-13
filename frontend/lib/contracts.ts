import { JsonRpcProvider, Contract } from 'ethers';

// ── Arbitrum Sepolia Stylus ────────────────────────────────────────────────────
export const RPC_URL = '/api/rpc'; // Next.js API proxy → Arbitrum Sepolia
export const CHAIN_ID = 421614;

// ── Deployed contract addresses (Stylus on Arbitrum Sepolia) ──────────────────
export const ADDRESSES = {
  agentMemory: '0xa56b7ebf77b8cb70ed7f276f1c9fb19d98ddc3c1',
  auditReport: '0xb30dfe68645217fcba0f29b4cdc515ef558422e2',
} as const;

// ── Stylus contract ABIs & event topics ───────────────────────────────────────
const AGENT_MEMORY_ABI = [
  'function memoryCount(uint256 tokenId) view returns (uint256)',
  'function getMemoryData(uint256 tokenId, uint256 index) view returns (bytes)',
];
const AUDIT_REPORT_ABI = [
  'function recordCount() view returns (uint256)',
  'function getReport(uint256 index) view returns (bytes)',
  'event AuditCreated(uint256 indexed taskId, address indexed requester, string contractName, uint256 timestamp)',
  'event AuditFinalized(uint256 indexed taskId, uint8 riskLevel, uint64 confidence, bytes32 reportHash, uint256 timestamp)',
];

export interface ChainStats {
  auditsCompleted: number;
  replayTraces: number;
  rootHashesStored: number;
  erc7857Updates: number;
  online: boolean;
}

/**
 * Read live stats from Stylus contracts via API proxy.
 */
export async function fetchChainStats(): Promise<ChainStats> {
  try {
    const rpc = (method: string, params: unknown[]) =>
      fetch(RPC_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })
        .then(r => r.json()).then(j => j.result);

    // memoryCount(uint256) selector = 0x6588424b, recordCount() = 0x900407bc
    const memData = '0x6588424b' + '0'.padStart(64, '0');
    const [memResult, audResult] = await Promise.all([
      rpc('eth_call', [{ to: ADDRESSES.agentMemory, data: memData }, 'latest']).catch(() => '0x0'),
      rpc('eth_call', [{ to: ADDRESSES.auditReport, data: '0x900407bc' }, 'latest']).catch(() => '0x0'),
    ]);

    const mc = parseInt(memResult, 16) || 0;
    const ac = parseInt(audResult, 16) || 0;

    return { auditsCompleted: ac, replayTraces: ac, rootHashesStored: mc, erc7857Updates: mc, online: true };
  } catch {
    return { auditsCompleted: 0, replayTraces: 0, rootHashesStored: 0, erc7857Updates: 0, online: false };
  }
}

// ── Stylus audit fetchers ─────────────────────────────────────────────────────

export interface OnChainAudit {
  taskId: string;
  rootHash: string;
  verdict: string;
  replayId: string;
  completedAt: Date;
  txHash?: string;
  contractName?: string;
  confidence?: number;
  traceHash?: string;
  requester?: string;
}

const RISK_LABELS = ['None', 'Low', 'Medium', 'High', 'Critical'];

// Event topic hashes (keccak256 of the event signature)
const TOPIC_AUDIT_CREATED   = '0x98ec50daa398632fde60b2f0d8113a7ec54d478642fccccc3d9b252be7c9fd5f';
const TOPIC_AUDIT_FINALIZED = '0x75bbe3dc8e0f2f58150426e10f769081aec81ccca23597719a02ce258bb4ea46';

/**
 * Fetch finalized audit records by querying raw eth_getLogs via the API proxy.
 * No ethers.js — raw fetch avoids CORS and Stylus ABI issues.
 */
export async function fetchAuditTasks(): Promise<OnChainAudit[]> {
  try {
    const body = (method: string, params: unknown[]) =>
      JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });

    const [createdLogs, finalizedLogs] = await Promise.all([
      fetch(RPC_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: body('eth_getLogs', [{ address: ADDRESSES.auditReport, topics: [TOPIC_AUDIT_CREATED], fromBlock: '0x0', toBlock: 'latest' }]) })
        .then(r => r.json()).then(j => j.result || []).catch(() => []),
      fetch(RPC_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: body('eth_getLogs', [{ address: ADDRESSES.auditReport, topics: [TOPIC_AUDIT_FINALIZED], fromBlock: '0x0', toBlock: 'latest' }]) })
        .then(r => r.json()).then(j => j.result || []).catch(() => []),
    ]);

    // Index AuditCreated by taskId (topics[1])
    const createdByTask = new Map<string, { contractName: string; requester: string }>();
    for (const log of createdLogs) {
      const taskId = BigInt(log.topics[1]).toString();
      const data = log.data;
      const offset = parseInt(data.slice(2, 66), 16) * 2;
      const strLen = parseInt(data.slice(2 + offset, 2 + offset + 64), 16) * 2;
      const strHex = data.slice(2 + offset + 64, 2 + offset + 64 + strLen);
      const contractName = decodeURIComponent(strHex.replace(/[0-9a-f]{2}/g, '%$&'));
      createdByTask.set(taskId, {
        contractName,
        requester: '0x' + log.topics[2].slice(26),
      });
    }

    const tasks: OnChainAudit[] = [];
    for (const log of finalizedLogs.reverse()) {
      const taskId = BigInt(log.topics[1]).toString();
      const created = createdByTask.get(taskId);
      const data = log.data.slice(2);
      const riskLevel = parseInt(data.slice(0, 64), 16);
      const confidence = parseInt(data.slice(64, 128), 16);
      const reportHash = '0x' + data.slice(128, 192);
      const timestamp = parseInt(data.slice(192, 256), 16);

      tasks.push({
        taskId,
        rootHash: reportHash,
        verdict: RISK_LABELS[riskLevel] ?? 'Unknown',
        replayId: '',
        completedAt: new Date(timestamp * 1000),
        txHash: log.transactionHash,
        contractName: created?.contractName ?? `Audit #${taskId}`,
        confidence,
        requester: created?.requester ?? '',
      });
    }
    return tasks;
  } catch {
    return [];
  }
}

export async function fetchAuditTask(_taskId: string): Promise<OnChainAudit | null> {
  return null; // Stylus getReport returns raw bytes, not structured data
}

function verdictToSeverity(verdict: string): 'critical' | 'high' | 'medium' | 'low' {
  const v = verdict.toUpperCase();
  if (v.includes('CRITICAL')) return 'critical';
  if (v.includes('HIGH'))     return 'high';
  if (v.includes('MEDIUM'))   return 'medium';
  return 'low';
}

export { verdictToSeverity };

export const OG_STORAGE_GATEWAY = 'https://sepolia.arbiscan.io';

export interface RootHashEntry {
  rootHash: string;
  dataKey: string;
  tokenId: string;
}

export async function fetchERC7857RootHashes(): Promise<RootHashEntry[]> {
  // Stylus AgentMemory doesn't emit ERC-7857 events — return empty
  return [];
}
