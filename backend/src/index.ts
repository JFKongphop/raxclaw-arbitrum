/*!
RAXC — RAG-based smart contract vulnerability analysis with Qdrant + OpenAI.

Simplified architecture:
1. Embed contract code (OpenAI text-embedding-3-small)
2. Query Qdrant for similar exploits (fast cosine similarity via HNSW)
3. Build RAG context and prompt
4. Send to OpenAI for LLM analysis
*/

import * as dotenv from "dotenv";
import * as path from "path";
import { fileURLToPath } from "url";
import { OpenAiClient } from "./openai-client.ts";
import { QdrantStorageClient, type QdrantExploitResult } from "./qdrant-storage.ts";

// ─── Re-exports ───────────────────────────────────────────────────────────────

export { OpenAiClient } from "./openai-client.ts";
export { QdrantStorageClient } from "./qdrant-storage.ts";
export type { QdrantExploitResult } from "./qdrant-storage.ts";
export { StylusClient } from "./stylus-client.ts";
export {
  AccessControlTool,
  FlashLoanTool,
  GasAnalyzerTool,
  MemoryTool,
  PatternDetectorTool,
  ReflectionTool,
} from "./tools.ts";
export type { Tool, ToolSignal } from "./tools.ts";
export {
  AgentCore,
  ConfidenceEngine,
  ConsensusEngine,
  FinalDecisionEngine,
  AttackSimulationEngine,
  GraphConstructionEngine,
  MemoryLayer,
  RaxcAnalyzer,
  RaxcAnalyzerRemote,
  ReportEngine,
  RiskScoringEngine,
  SeverityLock,
  SignalNormalizer,
  ToolRegistry,
  ToolTrustWeighting,
  ExploitabilityEstimator,
  AttestationEngine,
  ConsistencyEngineVerifier,
  AttackSuccessProbability,
  AttackerPersona,
} from "./agent.ts";
export type {
  AgentVote,
  AnalysisResult,
  AttackSimulation,
  AttackerCapabilities,
  AttackerModel,
  AttestationProof,
  ConsistencyCheck,
  DecisionResult,
  DeterministicReplay,
  ExecutionStep,
  ExploitGraph,
  ExploitVerdict,
  FinalDecision,
  IntelligenceReport,
  SeverityProof,
  StateProof,
  StateTransition,
  ToolSignalReference,
} from "./agent.ts";

// ─── Constants ────────────────────────────────────────────────────────────────

export const TOP_K = 5;
export const SIM_THRESHOLD = 0.01; // Lowered to always trigger analysis

// ─── Environment setup ────────────────────────────────────────────────────────

/** Load .env from the project root */
export function loadEnv(): void {
  dotenv.config();
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(__dirname, "..");
  dotenv.config({ path: path.join(root, ".env"), override: false });
}

/** Build OpenAI client (LLM reasoning + embeddings). */
export function buildOpenAiClient(): OpenAiClient {
  return OpenAiClient.fromEnv();
}

// ─── Embedding (OpenAI text-embedding-3-small, 1536 dims) ──────────────────────

/** Embed text — always uses OpenAI text-embedding-3-small. */
export async function embed(text: string): Promise<number[]> {
  return embedOpenAI(text);
}

async function embedOpenAI(text: string): Promise<number[]> {
  const apiKey = process.env["OPENAI_API_KEY"];
  if (!apiKey) throw new Error("OPENAI_API_KEY not set");

  const truncated = text.slice(0, 8000);
  const resp = await fetch("https://api.openai.com/v1/embeddings", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      input: truncated,
      model: "text-embedding-3-small",
    }),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`OpenAI API error ${resp.status}: ${body}`);
  }

  const data = (await resp.json()) as { data: Array<{ embedding: number[] }> };
  return data.data[0]?.embedding ?? [];
}

// ─── Analysis workflow ────────────────────────────────────────────────────────

/** Analyze contract using Qdrant vector database. */
export async function analyzeQdrant(
  storage: QdrantStorageClient,
  compute: OpenAiClient,
  contract: string,
): Promise<string> {
  console.log("[RaxcAnalyzer]   Embedding contract code...");
  const queryVec = await embed(contract);

  console.log("[RaxcAnalyzer]   Querying Qdrant (defi_cases + defi_protocols)...");
  const topMatches = await storage.query(queryVec, TOP_K);

  const topScore = topMatches[0]?.score ?? 0;
  console.log(`[RaxcAnalyzer]   Top similarity: ${topScore.toFixed(3)}`);

  if (topScore < SIM_THRESHOLD) {
    console.log(
      `[!] Similarity ${topScore.toFixed(3)} below threshold ${SIM_THRESHOLD} — skipping analysis, contract appears safe.`,
    );
    return `✅ NO EXPLOITABLE VULNERABILITY FOUND\nTop similarity score (${topScore.toFixed(3)}) is below minimum threshold (${SIM_THRESHOLD}).`;
  }

  console.log("[RaxcAnalyzer]   Building RAG context...");
  const context = buildRagContextQdrant(topMatches);

  console.log("[LLM]            Sending for analysis...");
  const prompt = buildAnalysisPrompt(context, contract);
  return compute.infer(prompt);
}

/** Build RAG context string from Qdrant search results */
export function buildRagContextQdrant(top: QdrantExploitResult[]): string {
  let ctx = "";

  for (let i = 0; i < top.length; i++) {
    const e = top[i];
    const scoreRounded = Math.round(e.score * 1000) / 1000;
    const isReal = e.source !== "DeFiVulnLabs";

    const header =
      `--- Reference ${i + 1}: ${e.exploitName} (${e.date}) ` +
      `[similarity: ${scoreRounded}] [source: ${e.source}] [collection: ${e.collection}] ---`;

    let txLine: string;
    let lostLine: string;
    let typeLine: string;

    if (isReal) {
      txLine = `Attack Tx: ${e.attackTx || "unknown"}`;
      lostLine = `Total Lost: ${e.totalLost}`;
      typeLine = "";
    } else {
      txLine = "Attack Tx: N/A (educational pattern)";
      lostLine = "Total Lost: N/A";
      typeLine = `Vulnerability Type: ${e.vulnType}\n`;
    }

    const code = e.codeSnippet.slice(0, 1500);

    ctx += `\n${header}\nChain: ${e.chain}\n${lostLine}\n${txLine}\n${typeLine}Code Snippet:\n${code}\n`;
  }

  return ctx;
}

function buildAnalysisPrompt(context: string, contract: string): string {
  return `You are a smart contract security expert specializing in DeFi vulnerabilities.

Analyze the following Solidity contract for potential vulnerabilities.
Use the reference cases below as context — retrieved from DeFiHackLabs (real protocol attacks) and DeFiVulnLabs (educational vulnerability patterns).

## Similar Reference Cases (DeFiHackLabs real exploits + DeFiVulnLabs educational patterns):
${context}

## Contract to Analyze:
${contract}

## Critical instructions before answering:
1. The exploit cases show HOW past vulnerabilities worked. Your job is to determine if THIS contract has the same UNMITIGATED flaw — not just a similar structure.
2. Actively check for these mitigations. If any are correctly implemented, they PREVENT exploitation:
   - ReentrancyGuard modifier or Checks-Effects-Interactions (state update before external call)
   - TWAP / time-weighted average price oracle (resistant to single-block manipulation)
   - onlyOwner / role-based access control on sensitive functions
   - Solidity 0.8+ built-in overflow protection or SafeMath
3. Structural similarity to an exploit is NOT sufficient. The contract must have the same exploitable flaw WITH NO mitigation present.
4. Include a CONFIDENCE score (0-100) reflecting how certain you are a real exploitable vulnerability exists with no mitigation.
5. For EXPLOIT_TX in your report: only cite the exact Attack Tx URLs present in the reference cases above. If a reference shows "N/A" or no real tx, write N/A. Do NOT fabricate or invent transaction hashes.

## Provide a structured security report with the following sections:

**Vulnerability Found:** Yes / No
**Risk Level:** Critical / High / Medium / Low / None
**Vulnerability Type:** (e.g. Reentrancy, Flash Loan, Price Manipulation, Access Control, etc.)
**Confidence:** (0-100 — certainty that a real exploitable vulnerability exists with no mitigation present)
**Similar Exploit Reference:** (which exploit case above is most relevant and why)
**Explanation:** (describe the exact vulnerability and how an attacker could exploit it step-by-step)
**Recommendation:**
IMPORTANT: Provide AT LEAST 3-4 detailed cases (A, B, C, D, ...). Each case must be a complete, standalone solution.
Separate each distinct issue or improvement into its own labeled case (A, B, C, D, ...). For each case:
- State the problem in one sentence.
- Show ONLY the one affected function rewritten in full — do NOT include contract declaration, constructor, imports, structs, or any other functions.
- Every line of the function must be written out completely — the words "existing code", "existing logic", "..." and any placeholder comments are FORBIDDEN.
- Add an inline comment on every line you changed explaining what was fixed and why.
- If a vulnerability was found: each case must directly correspond to one finding named in the Explanation section.
- If no vulnerability was found: each case must apply a concrete proactive improvement.
- You MUST write ALL cases completely. Do NOT summarize, skip, or abbreviate any case.`;
}
