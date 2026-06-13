/*!
RAXC WebSocket Client — sends a contract to ws_server and prints results.

Usage:
    bun run src/bin/ws-client.ts                          # uses built-in DeFiVault demo
    bun run src/bin/ws-client.ts -- < contract.sol        # pipe a file
    RAXC_CONTRACT_FILE=path.sol bun run src/bin/ws-client.ts
*/

/// <reference types="bun" />

import * as fs from "fs";

const WS_URL = process.env["WS_URL"] ?? "wss://raxclaw-arbitrum.fly.dev/ws";
const DEFAULT_CONTRACT = `pragma solidity ^0.7.0;

contract DeFiVault {
    mapping(address => uint256) public balances;
    address[] public depositors;
    address public owner;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        depositors.push(msg.sender);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
    }
}`;

async function main(): Promise<void> {
  let contract: string;

  if (process.env["RAXC_CONTRACT_CODE"]) {
    contract = process.env["RAXC_CONTRACT_CODE"];
  } else if (process.env["RAXC_CONTRACT_FILE"]) {
    const filePath = process.env["RAXC_CONTRACT_FILE"];
    try {
      contract = fs.readFileSync(filePath, "utf-8");
    } catch {
      console.error(`Cannot read '${filePath}'`);
      process.exit(1);
    }
  } else {
    contract = DEFAULT_CONTRACT;
  }

  const words = contract.split(/\s+/);
  const contractIdx = words.findIndex((w) => w === "contract");
  const name =
    contractIdx !== -1
      ? (words[contractIdx + 1] ?? "Contract").replace(/[^a-zA-Z0-9_]/g, "")
      : "Contract";

  console.log(
    "\n╔══════════════════════════════════════════════════════╗",
  );
  console.log("║   RAXC WebSocket Client (TypeScript)                 ║");
  console.log(
    "╚══════════════════════════════════════════════════════╝\n",
  );
  console.log(`[*] Connecting to ${WS_URL}...`);

  const ws = new WebSocket(WS_URL);

  const done = new Promise<void>((resolve) => {
    ws.onopen = () => {
      console.log("[✓] Connected\n");
      console.log(`[*] Analyzing: ${name}\n`);
      ws.send(JSON.stringify({ contract }));
    };

    ws.onmessage = (event) => {
      const text = typeof event.data === "string" ? event.data : "";
      let data: Record<string, unknown>;
      try {
        data = JSON.parse(text);
      } catch {
        return;
      }

      const type = typeof data.type === "string" ? data.type : "";

      switch (type) {
        case "banner":
          console.log(data.text ?? "");
          break;
        case "info":
          console.log(data.text ?? "");
          break;
        case "progress":
          for (const line of String(data.text ?? "").split("\n")) {
            console.log(`  \x1b[2m${line}\x1b[0m`);
          }
          break;
        case "explanation":
          console.log("\n\x1b[1;35m[🧠 LLM EXPLANATION]\x1b[0m");
          console.log(data.text ?? "");
          break;
        case "complete": {
          const summary = data.summary as Record<string, unknown> | undefined;
          console.log(
            "\n\x1b[36m╔═══════════════════════════════════════════════════════════════════╗\x1b[0m",
          );
          console.log(
            "\x1b[36m║        AUTONOMOUS ENGINE — SOVEREIGN EXECUTION COMPLETE           ║\x1b[0m",
          );
          console.log(
            "\x1b[36m╚═══════════════════════════════════════════════════════════════════╝\x1b[0m\n",
          );
          if (summary) {
            console.log(
              `  Contract:        ${summary["contract"] ?? "?"}`,
            );
            console.log(
              `  Vulnerability:   ${(summary["vulnerability_found"] as boolean) ? "YES" : "NO"}`,
            );
            console.log(
              `  Risk Level:      ${summary["risk_level"] ?? "?"}`,
            );
            console.log(
              `  Confidence:      ${((Number(summary["confidence"]) || 0) * 100).toFixed(1)}%`,
            );
            console.log(
              `  Final Verdict:   ${summary["final_verdict"] ?? "?"}`,
            );
            console.log(`  Report:          ${summary["report_path"] ?? "?"}`);
            console.log(`  AgentMemory TX:  ${summary["storage_tx"] ?? "—"}`);
            console.log(`  AuditReport TX:  ${summary["report_tx"] ?? "—"}`);
            console.log(
              `  Attestation ID:  ${summary["attestation_replay_id"] ?? "—"}`,
            );
          }
          ws.close();
          resolve();
          break;
        }
        case "error":
          console.error(
            `\n❌ ERROR: ${data.message ?? ""}`,
          );
          ws.close();
          resolve();
          break;
      }
    };

    ws.onerror = (err) => {
      console.error(`\n❌ WebSocket error:`, err);
      resolve();
    };
  });

  await done;
}

main().catch(console.error);
