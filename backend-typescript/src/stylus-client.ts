/*!
Stylus Contract Client — on-chain long-context memory via Arbitrum Sepolia.
Matches stylus/caller/src/bin/ pattern exactly.
*/

import {
  createPublicClient,
  createWalletClient,
  http,
  type PublicClient,
  type WalletClient,
  type TransactionReceipt,
} from "viem";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { arbitrumSepolia } from "viem/chains";

// ─── AgentMemory ABI ─────────────────────────────────────────────────────────

const AGENT_MEMORY_ABI = [
  {
    type: "function",
    name: "pushMemory",
    inputs: [
      { type: "uint256", name: "tokenId" },
      { type: "bytes", name: "summaryJson" },
      { type: "string", name: "description" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getMemoryData",
    inputs: [
      { type: "uint256", name: "tokenId" },
      { type: "uint256", name: "index" },
    ],
    outputs: [{ type: "bytes", name: "" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "memoryCount",
    inputs: [{ type: "uint256", name: "tokenId" }],
    outputs: [{ type: "uint256", name: "" }],
    stateMutability: "view",
  },
] as const;

// ─── AuditReport ABI ─────────────────────────────────────────────────────────

const AUDIT_REPORT_ABI = [
  {
    type: "function",
    name: "createAudit",
    inputs: [{ type: "string", name: "contractName" }],
    outputs: [{ type: "uint256", name: "taskId" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "finalizeAudit",
    inputs: [
      { type: "uint256", name: "taskId" },
      { type: "uint8", name: "riskLevel" },
      { type: "uint64", name: "confidence" },
      { type: "string", name: "vulnType" },
      { type: "bytes", name: "reportMarkdown" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getReport",
    inputs: [{ type: "uint256", name: "taskId" }],
    outputs: [{ type: "bytes", name: "" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "recordCount",
    inputs: [],
    outputs: [{ type: "uint256", name: "" }],
    stateMutability: "view",
  },
] as const;

// ─── Client ───────────────────────────────────────────────────────────────────

export class StylusClient {
  private account: PrivateKeyAccount;
  private rpcUrl: string;
  private agentMemoryAddr: `0x${string}`;
  private auditReportAddr: `0x${string}`;
  private agentTokenId: bigint;
  private walletClient: WalletClient;
  private publicClient: PublicClient;

  constructor(
    privateKey: `0x${string}`,
    rpcUrl: string,
    agentMemoryAddr: `0x${string}`,
    auditReportAddr: `0x${string}`,
    agentTokenId: bigint,
  ) {
    this.account = privateKeyToAccount(privateKey);
    this.rpcUrl = rpcUrl;
    this.agentMemoryAddr = agentMemoryAddr;
    this.auditReportAddr = auditReportAddr;
    this.agentTokenId = agentTokenId;
    // Create clients ONCE — they track nonce internally
    this.walletClient = createWalletClient({
      chain: arbitrumSepolia,
      transport: http(rpcUrl),
      account: this.account,
    });
    this.publicClient = createPublicClient({
      chain: arbitrumSepolia,
      transport: http(rpcUrl),
    });
  }

  static async fromEnv(): Promise<StylusClient> {
    const rpc = process.env["ARBITRUM_SEPOLIA"];
    if (!rpc) throw new Error("ARBITRUM_SEPOLIA not set");
    const pk = process.env["PRIVATE_KEY"];
    if (!pk) throw new Error("PRIVATE_KEY not set");
    const agentMemory = process.env["AGENT_MEMORY"];
    if (!agentMemory) throw new Error("AGENT_MEMORY not set");
    const auditReport = process.env["AUDIT_REPORT"];
    if (!auditReport) throw new Error("AUDIT_REPORT not set");
    const tokenId = BigInt(process.env["AGENT_TOKEN_ID"] ?? "0");

    return new StylusClient(
      pk as `0x${string}`,
      rpc,
      agentMemory as `0x${string}`,
      auditReport as `0x${string}`,
      tokenId,
    );
  }

  /** Push JSON summary to AgentMemory on-chain. Returns tx hash. */
  async pushMemory(json: string, desc: string): Promise<string> {
    const jsonBytes = new TextEncoder().encode(json);
    const hexBytes = `0x${Array.from(jsonBytes, (b) => b.toString(16).padStart(2, "0")).join("")}` as `0x${string}`;

    const hash = await this.walletClient.writeContract({
      account: this.account,
      chain: arbitrumSepolia,
      address: this.agentMemoryAddr,
      abi: AGENT_MEMORY_ABI,
      functionName: "pushMemory",
      args: [this.agentTokenId, hexBytes, desc],
    });

    // Wait for receipt so the nonce is consumed before the next tx
    await this.publicClient.waitForTransactionReceipt({ hash });

    console.log(`\x1b[94m[Memory]\x1b[0m         Pushed             | TX: ${hash}`);
    return hash;
  }

  /** Read all past memory entries from AgentMemory (up to 50). */
  async readAllMemory(): Promise<Array<{ index: bigint; data: string }>> {
    const total = await this.publicClient.readContract({
      address: this.agentMemoryAddr,
      abi: AGENT_MEMORY_ABI,
      functionName: "memoryCount",
      args: [this.agentTokenId],
    });

    const count = total as bigint;
    const maxRead = count < 50n ? Number(count) : 50;
    const entries: Array<{ index: bigint; data: string }> = [];

    for (let i = 0; i < maxRead; i++) {
      try {
        const bytes = await this.publicClient.readContract({
          address: this.agentMemoryAddr,
          abi: AGENT_MEMORY_ABI,
          functionName: "getMemoryData",
          args: [this.agentTokenId, BigInt(i)],
        });
        entries.push({
          index: BigInt(i),
          data: new TextDecoder().decode(
            Uint8Array.from(
              ((bytes as string).slice(2).match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16)),
            ),
          ),
        });
      } catch {
        // skip failed reads
      }
    }

    return entries;
  }

  /** Create an audit task in AuditReport. Returns task ID. */
  async createAuditTask(name: string): Promise<bigint> {
    const current = (await this.publicClient.readContract({
      address: this.auditReportAddr,
      abi: AUDIT_REPORT_ABI,
      functionName: "recordCount",
    })) as bigint;

    const hash = await this.walletClient.writeContract({
      account: this.account,
      chain: arbitrumSepolia,
      address: this.auditReportAddr,
      abi: AUDIT_REPORT_ABI,
      functionName: "createAudit",
      args: [name],
    });

    // Wait for receipt so the nonce is consumed before the next tx
    await this.publicClient.waitForTransactionReceipt({ hash });

    console.log(
      `\x1b[35m[AuditReport]\x1b[0m    Task #${current} created   | TX: ${hash}`,
    );
    return current;
  }

  /** Finalize an audit with full markdown report. */
  async finalizeAudit(
    taskId: bigint,
    risk: number,
    confidence: bigint,
    vulnType: string,
    report: string,
  ): Promise<string> {
    const reportBytes = new TextEncoder().encode(report);
    const hexBytes = `0x${Array.from(reportBytes, (b) => b.toString(16).padStart(2, "0")).join("")}` as `0x${string}`;

    const hash = await this.walletClient.writeContract({
      account: this.account,
      chain: arbitrumSepolia,
      address: this.auditReportAddr,
      abi: AUDIT_REPORT_ABI,
      functionName: "finalizeAudit",
      args: [taskId, risk, confidence, vulnType, hexBytes],
    });

    // Wait for receipt
    await this.publicClient.waitForTransactionReceipt({ hash });

    console.log(
      `\x1b[35m[AuditReport]\x1b[0m    Task #${taskId} finalized | TX: ${hash}`,
    );
    return hash;
  }

  /** Read a finalized report from AuditReport. */
  async getReport(taskId: bigint): Promise<string> {
    const result = await this.publicClient.readContract({
      address: this.auditReportAddr,
      abi: AUDIT_REPORT_ABI,
      functionName: "getReport",
      args: [taskId],
    });

    return new TextDecoder().decode(
      Uint8Array.from(
        ((result as string).slice(2).match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16)),
      ),
    );
  }
}
