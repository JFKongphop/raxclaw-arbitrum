/*!
RAXC WebSocket Server — real-time exploit intelligence over WebSocket.

Connect: ws://localhost:3001/ws
Send a JSON message to trigger analysis:
  { "contract": "pragma solidity ^0.8.0; contract Foo { ... }" }

The server streams phase-by-phase progress then sends the final result,
mirroring the terminal output of the CLI example.

Run:
    bun run src/bin/ws-server.ts
*/

import { Hono } from "hono";
import { createBunWebSocket } from "hono/bun";

const { upgradeWebSocket, websocket } = createBunWebSocket();
import {
  loadEnv,
  buildOpenAiClient,
  QdrantStorageClient,
  StylusClient,
  AgentCore,
  RaxcAnalyzer,
  RaxcAnalyzerRemote,
  GasAnalyzerTool,
  PatternDetectorTool,
  FlashLoanTool,
  AccessControlTool,
  ReflectionTool,
  MemoryTool,
} from "../index.ts";
import type { AnalysisResult } from "../agent.ts";

// ─── Load environment ─────────────────────────────────────────────────────────

loadEnv();

// ─── Analysis runner (identical pipeline to agent-example) ────────────────────

async function runAnalysis(
  contractCode: string,
  send: (data: Record<string, unknown>) => void,
): Promise<AnalysisResult> {
  send({ type: "info", text: "[*] Connecting to Qdrant..." });
  const qdrant = QdrantStorageClient.fromEnv();
  const loaded = await qdrant.health();
  send({
    type: "info",
    text: `[✓] Qdrant online — ${loaded} total exploit vectors loaded`,
  });

  const stylus = await StylusClient.fromEnv();
  const compute = buildOpenAiClient();

  const core = new AgentCore(qdrant, stylus, compute);

  // Register tools
  core.tools.register(new RaxcAnalyzer(qdrant, compute));
  send({ type: "info", text: "[✓] Registered tool: RaxcAnalyzer" });
  core.tools.register(new RaxcAnalyzerRemote(qdrant, compute));
  send({ type: "info", text: "[✓] Registered tool: RaxcAnalyzerRemote" });
  core.tools.register(new GasAnalyzerTool());
  send({ type: "info", text: "[✓] Registered tool: GasAnalyzerTool" });
  core.tools.register(new PatternDetectorTool());
  send({ type: "info", text: "[✓] Registered tool: PatternDetectorTool" });
  core.tools.register(new FlashLoanTool());
  send({ type: "info", text: "[✓] Registered tool: FlashLoanTool" });
  core.tools.register(new AccessControlTool());
  send({ type: "info", text: "[✓] Registered tool: AccessControlTool" });
  core.tools.register(new ReflectionTool(compute));
  send({ type: "info", text: "[✓] Registered tool: ReflectionTool" });
  core.tools.register(new MemoryTool(core.memory));
  send({ type: "info", text: "[✓] Registered tool: MemoryTool" });

  // Extract contract name
  const words = contractCode.split(/\s+/);
  const contractIdx = words.findIndex((w) => w === "contract");
  const contractName = contractIdx !== -1
    ? (words[contractIdx + 1] ?? "Contract").replace(/[^a-zA-Z0-9_]/g, "")
    : "Contract";

  send({ type: "info", text: `[*] Analyzing contract: ${contractName}` });
  send({
    type: "info",
    text: "[*] Initiating autonomous exploit analysis — 13-phase verification pipeline...",
  });

  // Set up progress streaming
  core.setProgressSender((msg: string) => {
    send({ type: "progress", text: msg });
  });

  // Run the full pipeline
  const result = await core.analyze(contractCode, contractName);

  // ─── Stream results ─────────────────────────────────────────────────────

  // Header box
  send({
    type: "banner",
    text: "\n╔══════════════════════════════════════════════════════════════════════════╗\n║                  AUTONOMOUS EXPLOIT INTELLIGENCE RESULT                  ║\n╚══════════════════════════════════════════════════════════════════════════╝",
  });

  // Phase: Basic Decision
  let basic = `  Vulnerability Found:  ${result.decision.vulnerabilityFound}\n  Risk Level:          ${result.decision.riskLevel}\n  Confidence:          ${(result.decision.confidence * 100).toFixed(1)}%\n  Tool Signals:        ${result.signals.length}`;
  if (result.decision.primaryVulnerability) {
    basic = `  Vulnerability Type:  ${result.decision.primaryVulnerability}\n${basic}`;
  }
  send({ type: "info", text: `📊 BASIC DECISION:\n${basic}` });
  await sleep(800);

  // Phase: Intelligence Report
  send({
    type: "info",
    text: `📈 INTELLIGENCE REPORT:\n  Risk Score:          ${(result.intelligenceReport.riskScore * 100).toFixed(2)}%\n  Exploitability:      ${(result.intelligenceReport.exploitabilityScore * 100).toFixed(2)}%\n  Attack Likelihood:   ${(result.intelligenceReport.attackLikelihood * 100).toFixed(2)}%\n  Classification:      ${result.intelligenceReport.finalClassification}`,
  });
  await sleep(800);

  // Phase: Attack Simulation
  send({
    type: "info",
    text: `🧪 ATTACK SIMULATION:\n  Execution Path:      ${result.attackSimulation.executionPath.length} steps\n  State Transitions:   ${result.attackSimulation.stateTransitions.length} tracked\n  Attacker Type:       ${result.attackSimulation.attackerModel.attackerType}\n  Exploit Status:      ${result.attackSimulation.exploitVerdict.status}\n  Success Probability: ${(result.attackSimulation.exploitVerdict.successProbability * 100).toFixed(1)}%\n  Replay ID:           ${result.attackSimulation.replayInfo.replayId}`,
  });
  await sleep(800);

  // Phase: Graph Construction
  send({
    type: "info",
    text: `📊 ATTACK MAP ENGINE:\n  Graph Nodes:         ${result.attackGraph.nodes.length}\n  Graph Edges:         ${result.attackGraph.edges.length}\n  Root Node:           ${result.attackGraph.rootNode}`,
  });
  await sleep(800);

  // Phase: Consistency Verification
  send({
    type: "info",
    text: `✅ CONSISTENCY VERIFICATION:\n  Simulation Valid:    ${result.consistencyCheck.simulationValid ? "✅ PASS" : "❌ FAIL"}\n  Graph Consistent:    ${result.consistencyCheck.graphConsistent ? "✅ PASS" : "❌ FAIL"}\n  State Correct:       ${result.consistencyCheck.stateCorrect ? "✅ PASS" : "❌ FAIL"}\n  Tool Conflict:       ${result.consistencyCheck.toolConflict ? "⚠️  YES" : "✅ NO"}\n  Consistency Score:   ${(result.consistencyCheck.consistencyScore * 100).toFixed(2)}%`,
  });
  await sleep(800);

  // Phase: Final Decision
  send({
    type: "info",
    text: `🎯 FINAL DECISION:\n  Final Verdict:       ${result.finalDecision.finalVerdict}\n  Final Confidence:    ${(result.finalDecision.finalConfidence * 100).toFixed(2)}%\n  Final Attack Prob:   ${(result.finalDecision.finalAttackProbability * 100).toFixed(2)}%\n  Final Risk Score:    ${(result.finalDecision.finalRiskScore * 100).toFixed(2)}%`,
  });
  await sleep(800);

  // Phase: Attestation
  send({
    type: "info",
    text: `🔐 ATTESTATION:\n  Replay ID:           ${result.attestation.replayId}\n  Seed:                ${result.attestation.seed}\n  Trace Hash:          ${result.attestation.executionTraceHash}\n  Timestamp:           ${result.attestation.timestamp}\n  Verdict:             ${result.attestation.finalVerdict}`,
  });
  await sleep(800);

  // Phase: LLM Explanation
  send({ type: "explanation", text: result.explanation });
  await sleep(800);

  // On-Chain Proof
  send({
    type: "banner",
    text: "\n╔════════════════════════════════════════════════════════════════════════╗\n║                      ON-CHAIN PROOF — Arbitrum Sepolia                 ║\n╚════════════════════════════════════════════════════════════════════════╝",
  });
  const agentTx = result.storageRootHash || "—";
  const reportTxClean = result.reportTx || "—";
  send({ type: "info", text: `  AgentMemory (JSON): ${result.storageRootHash}` });
  send({ type: "info", text: `  AuditReport Task #: ${result.reportRootHash}` });
  send({
    type: "info",
    text: `  AgentMemory TX:     https://sepolia.arbiscan.io/tx/${agentTx}`,
  });
  send({
    type: "info",
    text: `  AuditReport TX:     https://sepolia.arbiscan.io/tx/${reportTxClean}`,
  });

  // Build summary
  send({
    type: "complete",
    reportPath: result.filename,
    summary: {
      contract: contractName,
      vulnerability_found: result.decision.vulnerabilityFound,
      risk_level: result.decision.riskLevel,
      confidence: result.decision.confidence,
      final_verdict: result.finalDecision.finalVerdict,
      report_path: result.filename,
      storage_tx: result.storageRootHash,
      report_tx: result.reportTx,
      attestation_replay_id: result.attestation.replayId,
      execution_trace_hash: result.attestation.executionTraceHash,
      agent_explorer_url: `https://sepolia.arbiscan.io/tx/${agentTx}`,
      report_explorer_url: `https://sepolia.arbiscan.io/tx/${reportTxClean}`,
    },
  });

  return result;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Server ───────────────────────────────────────────────────────────────────

const port = parseInt(process.env["WS_PORT"] ?? "3001", 10);

console.log("\n╔══════════════════════════════════════════════════════════════╗");
console.log("║   RAXC WebSocket Server (TypeScript)                         ║");
console.log(`║   ws://0.0.0.0:${port}                                       ║`);
console.log('║   Send: {"contract": "pragma solidity ..."}                  ║');
console.log("╚══════════════════════════════════════════════════════════════╝\n");

const app = new Hono();

app.get("/", (c) => c.text("RAXC WebSocket Server — connect to /ws"));

app.get("/health", (c) => c.json({ status: "ok", uptime: process.uptime() }));

app.get(
  "/ws",
  upgradeWebSocket(() => ({
    onOpen: (_event, ws) => {
      // Send welcome banner
      ws.send(
        JSON.stringify({
          type: "banner",
          text: "╔══════════════════════════════════════════════════════════════════════════╗\n║         RAXC Autonomous Exploit Intelligence Core — WebSocket API        ║\n║         Deterministic Exploit Execution + Verification Framework         ║\n╚══════════════════════════════════════════════════════════════════════════╝",
        }),
      );
      ws.send(
        JSON.stringify({
          type: "info",
          text: 'Send a JSON message: {"contract": "pragma solidity ^0.8.0; ..."}',
        }),
      );
    },
    onMessage: async (event, ws) => {
      const text = typeof event.data === "string" ? event.data : "";
      let contractCode: string;

      try {
        const json = JSON.parse(text);
        contractCode =
          typeof json.contract === "string" ? json.contract : text;
      } catch {
        contractCode = text;
      }

      try {
        await runAnalysis(contractCode, (data) => {
          ws.send(JSON.stringify(data));
        });
      } catch (e) {
        ws.send(
          JSON.stringify({
            type: "error",
            message: (e as Error).message ?? String(e),
          }),
        );
      }
    },
    onClose: () => {
      // Client disconnected
    },
  })),
);

const server = Bun.serve({
  port,
  fetch: app.fetch,
  websocket,
});

console.log(`[✓] WebSocket server listening on ws://0.0.0.0:${port}/ws\n`);

// Prevent the process from exiting
process.on("SIGINT", () => {
  server.stop();
  process.exit(0);
});
