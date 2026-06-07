#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]

#[cfg(not(any(test, feature = "export-abi")))]
#[unsafe(no_mangle)]
pub extern "C" fn main() {}

#[cfg(feature = "export-abi")]
fn main() {
  #[cfg(feature = "agent-memory")]
  stylus_sdk::abi::export::print_from_args::<stylus_new::agent_memory::RaxcAgentMemory>();

  #[cfg(feature = "audit-report")]
  stylus_sdk::abi::export::print_from_args::<stylus_new::audit_report::RaxcAuditReport>();

  #[cfg(not(any(feature = "agent-memory", feature = "audit-report")))]
  stylus_sdk::abi::export::print_from_args::<stylus_new::counter::Counter>();
}
