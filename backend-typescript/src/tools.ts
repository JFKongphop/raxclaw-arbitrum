/*!
RAXC Analysis Tools — Multi-tool orchestration for smart contract vulnerability detection.

These tools are plugged into the agent framework for comprehensive analysis:
- GasAnalyzerTool: Identifies gas optimization opportunities
- PatternDetectorTool: Detects common vulnerability patterns using regex/static analysis
- FlashLoanTool: Detects flash loan and price oracle attack surfaces
- AccessControlTool: Deep access control and privilege escalation checks
- ReflectionTool: LLM self-critique via OpenAI — removes hallucinated fixes
- MemoryTool: Loads past audit sessions from Stylus AgentMemory for persistent memory
*/

import type { OpenAiClient } from "./openai-client.ts";
import type { MemoryLayer } from "./agent.ts";

// ─── Tool Interface ───────────────────────────────────────────────────────────

export interface ToolSignal {
  id: string;
  toolName: string;
  vulnerability: string | null;
  severity: string | null;
  confidence: number; // 0.0 - 1.0
  evidence: string;
}

export interface Tool {
  name(): string;
  execute(input: string): Promise<ToolSignal>;
}

// ─── Gas Analyzer Tool ────────────────────────────────────────────────────────

export class GasAnalyzerTool implements Tool {
  constructor() {}

  name(): string {
    return "GasAnalyzerTool";
  }

  async execute(contract: string): Promise<ToolSignal> {
    const findings: string[] = [];

    if (contract.includes("for (") && contract.includes(".length")) {
      findings.push("⛽ Gas: Cache array length in loops to save gas");
    }
    if (contract.includes("uint8") || contract.includes("uint16")) {
      findings.push("⛽ Gas: Consider using uint256 for storage (cheaper in EVM)");
    }
    if (contract.includes("public ") && contract.includes("returns")) {
      findings.push(
        "⛽ Gas: Consider using 'external' instead of 'public' for external-only functions",
      );
    }
    if (contract.includes("string memory") || contract.includes("bytes memory")) {
      findings.push(
        "⛽ Gas: Dynamic types in memory can be expensive - consider calldata for read-only params",
      );
    }
    if (contract.includes("storage") && contract.includes("memory")) {
      findings.push(
        "⛽ Gas: Minimize storage reads - cache storage variables in memory when accessed multiple times",
      );
    }

    const evidence =
      findings.length === 0
        ? "**Gas Analysis:** No major gas optimization opportunities detected."
        : `**Gas Analysis:**\n\nFound ${findings.length} potential gas optimizations:\n\n${findings.map((f) => `- ${f}`).join("\n")}`;

    return {
      id: "GasAnalyzerTool#1",
      toolName: "GasAnalyzerTool",
      vulnerability: null,
      severity: null,
      confidence: 0.6,
      evidence,
    };
  }
}

// ─── Pattern Detector Tool ────────────────────────────────────────────────────

export class PatternDetectorTool implements Tool {
  constructor() {}

  name(): string {
    return "PatternDetectorTool";
  }

  async execute(contract: string): Promise<ToolSignal> {
    const patterns: string[] = [];
    let vulnerabilityType: string | null = null;
    let severity: string | null = null;

    // Reentrancy patterns
    if (contract.includes(".call{value:") || contract.includes(".call(")) {
      const idx = contract.indexOf(".call");
      if (idx !== -1) {
        const before = contract.slice(0, idx);
        const after = contract.slice(idx);
        if (after.includes("=") && !before.includes("nonReentrant")) {
          patterns.push(
            "🚨 Pattern: External call detected - check for reentrancy (CEI pattern required)",
          );
          vulnerabilityType = "Reentrancy";
          severity = "High";
        }
      }
    }

    // Unchecked return value
    if (contract.includes(".transfer(") || contract.includes(".send(")) {
      patterns.push(
        "⚠️  Pattern: Using transfer/send - consider using call with return value check",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Unchecked Return Value";
        severity = "Medium";
      }
    }

    // Delegatecall usage
    if (contract.includes("delegatecall")) {
      patterns.push(
        "🚨 Pattern: delegatecall detected - ensure destination is trusted (storage collision risk)",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Delegatecall";
        severity = "Critical";
      }
    }

    // tx.origin usage
    if (contract.includes("tx.origin")) {
      patterns.push(
        "🚨 Pattern: tx.origin detected - vulnerable to phishing attacks (use msg.sender)",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Access Control";
        severity = "High";
      }
    }

    // Timestamp dependence
    if (contract.includes("block.timestamp") || contract.includes("now")) {
      patterns.push(
        "⚠️  Pattern: Timestamp usage detected - can be manipulated by miners (15-second window)",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Timestamp Dependence";
        severity = "Medium";
      }
    }

    // Unprotected selfdestruct
    if (contract.includes("selfdestruct") && !contract.includes("onlyOwner")) {
      patterns.push("🚨 Pattern: selfdestruct without access control - critical vulnerability");
      vulnerabilityType = "Access Control";
      severity = "Critical";
    }

    // Integer overflow (if old Solidity)
    if (contract.includes("pragma solidity")) {
      const versionLine = contract
        .split("\n")
        .find((l) => l.includes("pragma solidity"));
      if (versionLine) {
        if (
          versionLine.includes("^0.7") ||
          versionLine.includes("^0.6") ||
          versionLine.includes("^0.5")
        ) {
          if (
            !contract.includes("SafeMath") &&
            (contract.includes("+=") || contract.includes("-=") || contract.includes("*="))
          ) {
            patterns.push(
              "⚠️  Pattern: Arithmetic operations in Solidity <0.8 without SafeMath - overflow risk",
            );
            if (!vulnerabilityType) {
              vulnerabilityType = "Integer Overflow";
              severity = "High";
            }
          }
        }
      }
    }

    const evidence =
      patterns.length === 0
        ? "**Pattern Analysis:** No common vulnerability patterns detected."
        : `**Pattern Analysis:**\n\nDetected ${patterns.length} vulnerability patterns:\n\n${patterns.map((p) => `- ${p}`).join("\n")}`;

    const confidence = vulnerabilityType ? 0.7 : 0.5;

    return {
      id: "PatternDetectorTool#1",
      toolName: "PatternDetectorTool",
      vulnerability: vulnerabilityType,
      severity,
      confidence,
      evidence,
    };
  }
}

// ─── Flash Loan Tool ──────────────────────────────────────────────────────────

export class FlashLoanTool implements Tool {
  constructor() {}

  name(): string {
    return "FlashLoanTool";
  }

  async execute(contract: string): Promise<ToolSignal> {
    const findings: string[] = [];
    let vulnerabilityType: string | null = null;
    let severity: string | null = null;

    if (
      contract.includes("flashLoan") ||
      contract.includes("flash_loan") ||
      contract.includes("executeOperation")
    ) {
      findings.push(
        "🚨 FlashLoan: Flash loan callback detected — verify state is not manipulable within single tx",
      );
      vulnerabilityType = "Flash Loan";
      severity = "Critical";
    }

    if (
      (contract.includes("balanceOf") || contract.includes("getReserves")) &&
      contract.includes("price")
    ) {
      findings.push(
        "🚨 FlashLoan: Spot price oracle detected — use TWAP to prevent single-block manipulation",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Price Oracle Manipulation";
        severity = "Critical";
      }
    }

    if (contract.includes("getAmountsOut") || contract.includes("getAmountOut")) {
      findings.push(
        "⚠️  FlashLoan: AMM price query detected — vulnerable to sandwich and flash loan price manipulation",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Price Oracle Manipulation";
        severity = "High";
      }
    }

    if (contract.includes("borrow") && (contract.includes("swap") || contract.includes("liquidate"))) {
      findings.push(
        "⚠️  FlashLoan: Borrow + swap/liquidate in same call — verify flash loan atomicity guard",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Flash Loan";
        severity = "High";
      }
    }

    const evidence =
      findings.length === 0
        ? "**Flash Loan Analysis:** No flash loan or price oracle attack surface detected."
        : `**Flash Loan Analysis:**\n\nFound ${findings.length} flash loan / oracle risk(s):\n\n${findings.map((f) => `- ${f}`).join("\n")}`;

    const confidence = vulnerabilityType ? 0.82 : 0.55;

    return {
      id: "FlashLoanTool#1",
      toolName: "FlashLoanTool",
      vulnerability: vulnerabilityType,
      severity,
      confidence,
      evidence,
    };
  }
}

// ─── Access Control Tool ──────────────────────────────────────────────────────

export class AccessControlTool implements Tool {
  constructor() {}

  name(): string {
    return "AccessControlTool";
  }

  async execute(contract: string): Promise<ToolSignal> {
    const findings: string[] = [];
    let vulnerabilityType: string | null = null;
    let severity: string | null = null;

    const criticalFnPatterns = [
      "withdraw",
      "transferOwnership",
      "upgradeTo",
      "mint",
      "burn",
      "setOwner",
      "initialize",
    ];

    for (const fname of criticalFnPatterns) {
      const pattern = `function ${fname}`;
      const fnIdx = contract.indexOf(pattern);
      if (fnIdx !== -1) {
        const fnBody = contract.slice(fnIdx, Math.min(fnIdx + 300, contract.length));
        if (
          !fnBody.includes("onlyOwner") &&
          !fnBody.includes("require(msg.sender") &&
          !fnBody.includes("onlyRole")
        ) {
          findings.push(
            `🚨 AccessControl: \`${fname}()\` has no owner/role guard — callable by anyone`,
          );
          vulnerabilityType = "Access Control";
          severity = "Critical";
        }
      }
    }

    if (
      contract.includes("renounceOwnership") &&
      !contract.includes("timelock") &&
      !contract.includes("TimeLock")
    ) {
      findings.push(
        "⚠️  AccessControl: renounceOwnership without timelock — irreversible ownership loss",
      );
      if (!vulnerabilityType) {
        vulnerabilityType = "Access Control";
        severity = "High";
      }
    }

    if (
      contract.includes("function initialize") &&
      !contract.includes("initializer") &&
      !contract.includes("_initialized")
    ) {
      findings.push(
        "🚨 AccessControl: initialize() without initializer guard — can be called multiple times",
      );
      vulnerabilityType = "Access Control";
      severity = "Critical";
    }

    if (contract.includes("function set")) {
      const hasAnyGuard =
        contract.includes("onlyOwner") ||
        contract.includes("require(msg.sender") ||
        contract.includes("onlyRole");
      if (!hasAnyGuard) {
        findings.push(
          "⚠️  AccessControl: setter functions detected with no access control pattern found in contract",
        );
        if (!vulnerabilityType) {
          vulnerabilityType = "Access Control";
          severity = "Medium";
        }
      }
    }

    const evidence =
      findings.length === 0
        ? "**Access Control Analysis:** No access control vulnerabilities detected."
        : `**Access Control Analysis:**\n\nFound ${findings.length} access control issue(s):\n\n${findings.map((f) => `- ${f}`).join("\n")}`;

    const confidence = vulnerabilityType ? 0.85 : 0.6;

    return {
      id: "AccessControlTool#1",
      toolName: "AccessControlTool",
      vulnerability: vulnerabilityType,
      severity,
      confidence,
      evidence,
    };
  }
}

// ─── Reflection Tool ──────────────────────────────────────────────────────────

export class ReflectionTool implements Tool {
  private compute: OpenAiClient;

  constructor(compute: OpenAiClient) {
    this.compute = compute;
  }

  name(): string {
    return "ReflectionTool";
  }

  async execute(input: string): Promise<ToolSignal> {
    const prompt = `You are a senior smart contract security auditor performing self-critique.
Review this vulnerability analysis and:
1. Remove any hallucinated or unsupported fix recommendations
2. Verify the vulnerability is real based on the evidence
3. Adjust confidence: increase if evidence is strong, decrease if speculative
4. Output ONLY: VERDICT: <CONFIRMED|REDUCED|REJECTED> | CONFIDENCE: <0-100> | NOTE: <one sentence>

Analysis to review:
${input}`;

    const response = await this.compute.inferWithMaxTokens(prompt, 256);

    const verdict = response.includes("CONFIRMED")
      ? "CONFIRMED"
      : response.includes("REJECTED")
        ? "REJECTED"
        : "REDUCED";

    let refinedConfidence = 0.7;
    const confIdx = response.indexOf("CONFIDENCE:");
    if (confIdx !== -1) {
      const after = response.slice(confIdx + 11);
      const numStr = after.match(/^\d+/)?.[0];
      if (numStr) {
        const parsed = parseInt(numStr, 10);
        if (!isNaN(parsed)) refinedConfidence = parsed / 100;
      }
    }

    return {
      id: "ReflectionTool#1",
      toolName: "ReflectionTool",
      vulnerability: null,
      severity: null,
      confidence: refinedConfidence,
      evidence: `**Reflection (OpenAI self-critique):**\n\nVerdict: ${verdict}\n\n${response.trim()}`,
    };
  }
}

// ─── Memory Tool ──────────────────────────────────────────────────────────────

export class MemoryTool implements Tool {
  private memory: MemoryLayer;

  constructor(memory: MemoryLayer) {
    this.memory = memory;
  }

  name(): string {
    return "MemoryTool";
  }

  async execute(contract: string): Promise<ToolSignal> {
    const pastAnalyses = await this.memory.retrieveSimilar(contract);

    const evidence =
      pastAnalyses.length === 0
        ? "**Memory (Stylus AgentMemory):** No past audit sessions — first-time analysis."
        : `**Memory (Stylus AgentMemory):** ${pastAnalyses.length} past audit session(s):\n\n${pastAnalyses.map((s, i) => `- [Session ${i + 1}] ${s}`).join("\n")}`;

    const confidence = pastAnalyses.length === 0 ? 0.5 : 0.75;

    return {
      id: "MemoryTool#1",
      toolName: "MemoryTool",
      vulnerability: null,
      severity: null,
      confidence,
      evidence,
    };
  }
}
