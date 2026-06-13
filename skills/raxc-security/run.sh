#!/usr/bin/env bash
# RAXC Security Audit — OpenClaw skill invocation script
# Called by OpenClaw when user asks to audit a Solidity contract.
#
# Usage (direct): bash skills/raxc-security/run.sh
# Usage (raxclaw): ./dist/raxclaw run
# Usage (OpenClaw): automatic via SKILL.md
#
# Zero-config: all values are baked in for dev/demo.
# Clone the repo and run — no .env setup required.

set -e

# ── Resolve repo root ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"

# ── Baked-in configuration (override by setting vars before running) ──────

# Arbitrum Sepolia (Stylus contracts)
export ARBITRUM_SEPOLIA="${ARBITRUM_SEPOLIA:-https://arbitrum-sepolia.infura.io/v3/af5f1e33ac0c4cd69daa3f63a587723e}"

# Stylus contract addresses
export AGENT_MEMORY="${AGENT_MEMORY:-0x1f2bdb90f87b0250cf8a56bb24eb4c30c960f2db}"
export AUDIT_REPORT="${AUDIT_REPORT:-0x10a1ec0dff526246ff09d72609bbbde9a0f60e25}"
export AGENT_TOKEN_ID="${AGENT_TOKEN_ID:-0}"

# OpenAI
export OPENAI_API_KEY="${OPENAI_API_KEY:-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}"
export OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}"

# Qdrant vector database
export QDRANT_ENDPOINT="${QDRANT_ENDPOINT:-https://68fe2ddf-6131-4899-8cf8-d213fd9421ae.us-east4-0.gcp.cloud.qdrant.io}"
export QDRANT_API_KEY="${QDRANT_API_KEY:-eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3MiOiJtIiwic3ViamVjdCI6ImFwaS1rZXk6MTY4N2M4NzktOTgzOC00ODgwLTlmYWMtMzhiYjY4NzQyMzg4In0.ru6NjZyc1qUVDCGRgZPb5sU9vb6dlJuS4tXg7vSOLhI}"

# Dev wallet
export PRIVATE_KEY="${PRIVATE_KEY:-0x5368e0ef6bb84d4143b17f35a021eb7fb9c077c611b7fb8a6c58336ee831810e}"

# ── Load .env if present (allows overriding any value above) ──────────────────
ENV_FILE="$REPO_ROOT/.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

# ── OpenClaw orchestration preamble ──────────────────────────────────────────
echo ""
echo "[OpenClaw]       Received request: smart contract security audit"
echo "[OpenClaw]       Matched skill    → raxc-security-audit"
echo "[OpenClaw]       Building execution graph..."
echo "[Planner]        Analyzing contract scope..."
echo "[Planner]        Selecting tools: PatternDetector, MemoryTool, RaxcAnalyzer, ReflectionTool"
echo "[Planner]        Execution order: Memory → RAG → LLM → Consensus → Simulate → Reflect → Persist"
echo "[Planner]        Dispatching to RAXC cognition engine..."
echo ""

# ── Run RAXC cognition engine ─────────────────────────────────────────────────
cd "$BACKEND_DIR"

echo "[RAXC]           Running via Bun (TypeScript backend)"
exec bun run examples/agent-example.ts 2>&1
