# RAXC Stylus Contracts — On-Chain Audit Trail

> **Stylus smart contracts for persistent AI agent memory and immutable audit reports.**
> **Part of the [RAXC Autonomous Exploit Intelligence Core](../README.md).**

[![Stylus](https://img.shields.io/badge/Stylus-Rust%20→%20WASM-orange)](https://arbitrum.io/stylus)
[![Arbitrum](https://img.shields.io/badge/Arbitrum-Sepolia-blue)](https://sepolia.arbiscan.io)

Arbitrum Stylus contracts written in Rust. Three contracts share a single crate,
selected at build/deploy time via feature flags.

---

## Contracts

| Contract | Feature flag | Description |
|---|---|---|
| `RaxcAgentMemory` | `agent-memory` | NFT-based persistent AI agent memory |
| `RaxcAuditReport` | `audit-report` | On-chain smart-contract audit reports |
| `Counter` | *(default)* | Simple on-chain counter (test) |

### Deployed — Arbitrum Sepolia

| Contract | Address |
|---|---|
| AgentMemory | `0xdef586e63cf2f20cbe9f055b738cd4ceda273900` |
| AuditReport | `0x6c46b355a1178e2e9f8c5c2d8dab81e061d67434` |
| Counter | `0xa018a255881e0525831df7bcdf9a03d1b06e1790` |

### `AgentMemory` — Long-Context Memory

Stores JSON audit summaries on-chain with cryptographic hashing per entry.

| Function | Description |
|---|---|
| `mint(to, agent)` → `tokenId` | Mint new agent identity |
| `pushMemory(tokenId, summaryJson, description)` | Store audit summary |
| `getMemoryData(tokenId, index)` → `bytes` | Read entry by index |
| `memoryCount(tokenId)` → `uint256` | Total entries for a token |

**Authorization**: Only token owner or authorized agent can push.
**Storage**: Flat key derivation `keccak256(token_id, index)` for sparse maps.

### `AuditReport` — Immutable Audit Trail

Stores full markdown security reports on-chain. Each report is hashed and
timestamped. Risk levels: `0=None | 1=Low | 2=Medium | 3=High | 4=Critical`.

| Function | Description |
|---|---|
| `createAudit(contractName)` → `taskId` | Create new audit task |
| `finalizeAudit(taskId, riskLevel, confidence, vulnType, reportMarkdown)` | Store full report |
| `getReport(taskId)` → `bytes` | Read report by task ID |
| `recordCount()` → `uint256` | Total audits on record |

---

## Project Structure

```
src/
├── lib.rs            # Feature router — one entrypoint per build
├── counter.rs        # Counter contract
├── agent_memory.rs   # RaxcAgentMemory contract
└── audit_report.rs   # RaxcAuditReport contract

caller/src/bin/
├── counter.rs        # Call Counter on-chain
├── agent_memory.rs   # Call AgentMemory on-chain
└── audit_report.rs   # Call AuditReport on-chain

data/
├── memory.json       # Sample agent memory payload
└── report.md         # Sample audit report (used in tests + callers)

Makefile              # All commands
```

---

## Prerequisites

```sh
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install cargo-stylus
cargo install cargo-stylus

# Add WASM target
rustup target add wasm32-unknown-unknown
```

### `.env` file (workspace root)

```env
ARBITRUM_SEPOLIA=https://arbitrum-sepolia.infura.io/v3/<YOUR_KEY>
PRIVATE_KEY=0x<YOUR_PRIVATE_KEY>
```

---

## Running Tests

Run all tests across all three contracts at once:

```sh
make test
```

Or directly with cargo:

```sh
cargo test --target aarch64-apple-darwin \
  --features "stylus-test,agent-memory,audit-report" -- --nocapture
```

Expected output: **15 tests, 0 failures**.

---

## Checking Contracts (no deploy)

Validates that the WASM compiles and fits within Stylus limits:

```sh
make check-counter
make check-agent-memory
make check-audit-report

# or all at once
make check-all
```

---

## Deploying

Each contract is deployed separately using its feature flag.

### Counter (default)

```sh
make deploy-counter
```

### AgentMemory

```sh
make deploy-agent-memory
```

### AuditReport

```sh
make deploy-audit-report
```

All deploy commands read `ARBITRUM_SEPOLIA` and `PRIVATE_KEY` from `.env` automatically.

> If you see `max fee per gas less than block base fee`, the gas price setting in the
> Makefile (`--max-fee-per-gas-gwei 0.1`) is already above Arbitrum Sepolia's typical
> base fee. Increase it if needed.

---

## Verifying Deployments

After deploying, verify that the on-chain bytecode matches your local build:

```sh
# Replace TX with the deployment tx hash printed during deploy
make verify-counter  TX=0x<deployment-tx>
make verify-agent    TX=0x<deployment-tx>
make verify-audit    TX=0x<deployment-tx>
```

---

## Calling Contracts

Reads `.env` for RPC and private key, then calls the deployed contract:

```sh
make call-counter        # increment, addNumber, mulNumber, reset
make call-agent-memory   # mint token, push data/memory.json, verify
make call-audit-report   # create audit, finalize with data/report.md, verify
```

Or via cargo directly (run from workspace root):

```sh
cd caller
cargo run --bin counter
cargo run --bin agent_memory
cargo run --bin audit_report
```

---

## Exporting ABIs

```sh
make abi-counter
make abi-agent-memory
make abi-audit-report
```

---

## Make targets reference

```
make help
```
