include .env
export

RPC        := $(ARBITRUM_SEPOLIA)
PK         := $(PRIVATE_KEY)
FLAGS      := --no-verify --max-fee-per-gas-gwei 0.1 --endpoint "$(RPC)" --private-key "$(PK)"

# ── Test ──────────────────────────────────────────────────────────────────────

.PHONY: test
test:
	cargo test --target aarch64-apple-darwin \
	  --features "stylus-test,agent-memory,audit-report" -- --nocapture

# ── Check (no deploy) ─────────────────────────────────────────────────────────

.PHONY: check-counter check-agent-memory check-audit-report check-all
check-counter:
	cargo stylus check --endpoint "$(RPC)"

check-agent-memory:
	cargo stylus check --endpoint "$(RPC)" --features agent-memory

check-audit-report:
	cargo stylus check --endpoint "$(RPC)" --features audit-report

check-all: check-counter check-agent-memory check-audit-report

# ── Deploy ────────────────────────────────────────────────────────────────────

.PHONY: deploy-counter deploy-agent-memory deploy-audit-report

deploy-counter:
	cargo stylus deploy $(FLAGS)

deploy-agent-memory:
	cargo stylus deploy $(FLAGS) --features agent-memory

deploy-audit-report:
	cargo stylus deploy $(FLAGS) --features audit-report

# ── Verify ────────────────────────────────────────────────────────────────────
# Usage: make verify-counter   TX=0xabc...
#        make verify-agent     TX=0xabc...
#        make verify-audit     TX=0xabc...

.PHONY: verify-counter verify-agent verify-audit

verify-counter:
	cargo stylus verify --no-verify --endpoint "$(RPC)" --deployment-tx "$(TX)"

verify-agent:
	cargo stylus verify --no-verify --endpoint "$(RPC)" --deployment-tx "$(TX)" \
	  --features agent-memory

verify-audit:
	cargo stylus verify --no-verify --endpoint "$(RPC)" --deployment-tx "$(TX)" \
	  --features audit-report

# ── Call contracts ────────────────────────────────────────────────────────────

.PHONY: call-counter call-agent-memory call-audit-report

call-counter:
	cd caller && cargo run --bin counter

call-agent-memory:
	cd caller && cargo run --bin agent_memory

call-audit-report:
	cd caller && cargo run --bin audit_report

# ── Export ABI ────────────────────────────────────────────────────────────────

.PHONY: abi-counter abi-agent-memory abi-audit-report

abi-counter:
	cargo stylus export-abi

abi-agent-memory:
	cargo stylus export-abi --features agent-memory

abi-audit-report:
	cargo stylus export-abi --features audit-report

# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@echo ""
	@echo "Usage: make <target> [TX=0x...]"
	@echo ""
	@echo "  Test"
	@echo "    test                   run all contract tests"
	@echo ""
	@echo "  Check"
	@echo "    check-counter          check Counter wasm"
	@echo "    check-agent-memory     check AgentMemory wasm"
	@echo "    check-audit-report     check AuditReport wasm"
	@echo "    check-all              check all three"
	@echo ""
	@echo "  Deploy"
	@echo "    deploy-counter         deploy Counter"
	@echo "    deploy-agent-memory    deploy AgentMemory"
	@echo "    deploy-audit-report    deploy AuditReport"
	@echo ""
	@echo "  Verify  (requires TX=<deployment-tx-hash>)"
	@echo "    verify-counter  TX=0x  verify Counter deployment"
	@echo "    verify-agent    TX=0x  verify AgentMemory deployment"
	@echo "    verify-audit    TX=0x  verify AuditReport deployment"
	@echo ""
	@echo "  Call"
	@echo "    call-counter           run counter caller"
	@echo "    call-agent-memory      run agent_memory caller"
	@echo "    call-audit-report      run audit_report caller"
	@echo ""
	@echo "  ABI"
	@echo "    abi-counter            print Counter ABI"
	@echo "    abi-agent-memory       print AgentMemory ABI"
	@echo "    abi-audit-report       print AuditReport ABI"
	@echo ""
