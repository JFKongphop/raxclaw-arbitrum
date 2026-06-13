#!/usr/bin/env tsx
/**
 * raxclaw — RAXC × OpenClaw branded CLI (TypeScript backend)
 *
 * Usage:
 *   npx tsx raxclaw.ts analyze [contract.sol]
 *   npx tsx raxclaw.ts run [contract.sol]
 *   npx tsx raxclaw.ts agent --message "audit DeFiVault.sol"
 *
 * Routes to backend/examples/agent-example.ts via Bun.
 */

import { execFileSync } from "child_process";
import * as path from "path";
import * as fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REPO_ROOT = path.resolve(__dirname);
const AGENT_EXAMPLE = path.join(
  REPO_ROOT,
  "backend",
  "examples",
  "agent-example.ts",
);
const OPENCLAW_BIN = path.join(REPO_ROOT, "node_modules", ".bin", "openclaw");
const BUN_BIN = "bun";

// ── RAXC banner ──────────────────────────────────────────────────────────────
function banner() {
  console.log("");
  console.log("██████╗   █████╗ ██╗  ██╗ ██████╗██╗      █████╗ ██╗    ██╗");
  console.log("██╔══██╗ ██╔══██╗╚██╗██╔╝██╔════╝██║     ██╔══██╗██║    ██║");
  console.log("██████╔╝ ███████║ ╚███╔╝ ██║     ██║     ███████║██║ █╗ ██║");
  console.log("██╔══██╗ ██╔══██║ ██╔██╗ ██║     ██║     ██╔══██║██║███╗██║");
  console.log("██║  ██║ ██║  ██║██╔╝ ██╗╚██████╗███████╗██║  ██║╚███╔███╔╝");
  console.log("╚═╝  ╚═╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ");
  console.log("");
  console.log("RAXC × OpenClaw    —    Autonomous Security Cognition on Arbitrum");
  console.log("════════════════════════════════════════════════════════════");
  console.log("");
}

// ── Validate OpenClaw installed ───────────────────────────────────────────────
function requireOpenclaw() {
  if (!fs.existsSync(OPENCLAW_BIN)) {
    console.error("[raxclaw] OpenClaw not installed. Run: npm install");
    process.exit(1);
  }
}

// ── CLI routing ───────────────────────────────────────────────────────────────
const [, , command, ...args] = process.argv;

banner();

switch (command) {
  case "analyze": {
    const contract = args[0] ?? "";
    console.log(`[raxclaw]        Running RAXC audit via TypeScript backend`);
    console.log(`[raxclaw]        Contract: ${contract || "DeFiVault (built-in demo)"}`);
    console.log("");

    const env = { ...process.env };
    // Only set env var if real code or file provided — otherwise use built-in demo
    if (contract.endsWith(".sol")) {
      env.RAXC_CONTRACT_FILE = contract;
    } else if (contract.includes("pragma") || contract.includes("contract ")) {
      env.RAXC_CONTRACT_CODE = contract;
    }

    execFileSync(BUN_BIN, ["run", AGENT_EXAMPLE], {
      env,
      stdio: "inherit",
      cwd: REPO_ROOT,
    });
    break;
  }

  case "run": {
    // Direct execution — same as analyze but CI-friendly name
    const contract = args.find((a) => !a.startsWith("-")) ?? "";
    console.log(`[raxclaw]        Direct RAXC execution (CI mode)`);
    console.log(`[raxclaw]        Contract: ${contract || "DeFiVault (built-in demo)"}`);
    console.log("");

    const env = { ...process.env };
    if (contract.endsWith(".sol")) {
      env.RAXC_CONTRACT_FILE = contract;
    } else if (contract.includes("pragma") || contract.includes("contract ")) {
      env.RAXC_CONTRACT_CODE = contract;
    }

    execFileSync(BUN_BIN, ["run", AGENT_EXAMPLE], {
      env,
      stdio: "inherit",
      cwd: REPO_ROOT,
    });
    break;
  }

  default: {
    console.log("Usage:");
    console.log(
      "  npx tsx raxclaw.ts analyze [contract.sol]   — TypeScript RAXC audit",
    );
    console.log(
      "  npx tsx raxclaw.ts run [contract.sol]       — direct execution (CI mode)",
    );
    console.log(
      "  npx tsx raxclaw.ts agent --message <msg>    — OpenClaw agent pass-through",
    );
    console.log("");
    console.log("Backend: backend/examples/agent-example.ts (Bun)");
    console.log(
      "Reports: backend/reports/",
    );
    process.exit(0);
  }
}
