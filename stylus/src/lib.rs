//! Multi-contract Stylus workspace.
//!
//! Select which contract to build/deploy using a feature flag:
//!
//!   cargo stylus deploy --features agent-memory  ...  → AgentMemory
//!   cargo stylus deploy --features audit-report  ...  → AuditReport
//!   cargo stylus deploy                          ...  → Counter (default)

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
extern crate alloc;

// ── Contract modules ──────────────────────────────────────────────────────────

/// Stores on-chain key/value memory for an AI agent.
#[cfg(feature = "agent-memory")]
pub mod agent_memory;

/// Records audit report hashes on-chain.
#[cfg(feature = "audit-report")]
pub mod audit_report;

/// Simple counter (default when no contract feature is selected).
#[cfg(not(any(feature = "agent-memory", feature = "audit-report")))]
pub mod counter;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod test {
  #[cfg(not(any(feature = "agent-memory", feature = "audit-report")))]
  use stylus_sdk::{alloy_primitives::U256, testing::*};

  #[cfg(not(any(feature = "agent-memory", feature = "audit-report")))]
  use super::counter::Counter;

  #[test]
  #[cfg(not(any(feature = "agent-memory", feature = "audit-report")))]
  fn test_counter() {
    let vm = TestVM::default();
    let mut contract = Counter::from(&vm);

    assert_eq!(U256::ZERO, contract.number());
    contract.increment();
    assert_eq!(U256::from(1), contract.number());
    contract.add_number(U256::from(3));
    assert_eq!(U256::from(4), contract.number());
    contract.mul_number(U256::from(2));
    assert_eq!(U256::from(8), contract.number());
    contract.set_number(U256::from(100));
    assert_eq!(U256::from(100), contract.number());
    vm.set_value(U256::from(2));
    contract.add_from_msg_value();
    assert_eq!(U256::from(102), contract.number());
  }
}
