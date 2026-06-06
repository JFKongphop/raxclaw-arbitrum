// RaxcAuditReport — Stylus (Rust) contract for Arbitrum
// ERC-8183 style: stores full markdown audit reports as bytes on-chain.
// Each audit task has: requester, contract name, risk level, confidence,
// vulnerability type, keccak256 report hash, and the raw report bytes.
//
// Deploy:  cargo stylus deploy --endpoint <RPC_URL> --private-key <KEY>
// Check:   cargo stylus check
// ABI:     cargo run --bin export-abi --features export-abi

#![cfg_attr(all(not(feature = "export-abi"), not(test)), no_main)]
extern crate alloc;

use alloc::{string::String, vec::Vec};
use alloy_primitives::{keccak256, Address, FixedBytes, Uint, U256};
use alloy_sol_types::sol;
use stylus_sdk::{prelude::*, storage::*};

// Type aliases for StorageU8 / StorageU64 value types
type U8Val = Uint<8, 1>;
type U64Val = Uint<64, 1>;

// ── Events ─────────────────────────────────────────────────────────────────

sol! {
    event AuditCreated(
        uint256 indexed task_id,
        address indexed requester,
        string  contract_name,
        uint256 timestamp
    );

    event AuditFinalized(
        uint256 indexed task_id,
        uint8   risk_level,
        uint64  confidence,
        bytes32 report_hash,
        uint256 timestamp
    );
}

// ── Storage ────────────────────────────────────────────────────────────────

/// RiskLevel enum mirrors the Solidity contract:
/// 0=None 1=Low 2=Medium 3=High 4=Critical
#[storage]
#[entrypoint]
pub struct RaxcAuditReport {
  /// Monotonically increasing counter — also serves as next task ID
  record_count: StorageU256,

  // Per-task fields — keyed by task_id (U256)
  requester: StorageMap<U256, StorageAddress>,
  contract_name: StorageMap<U256, StorageString>,
  risk_level: StorageMap<U256, StorageU8>,
  confidence: StorageMap<U256, StorageU64>,
  vuln_type: StorageMap<U256, StorageString>,

  /// keccak256 of reportData — for integrity verification without reading the full report
  report_hash: StorageMap<U256, StorageFixedBytes<32>>,

  /// Full markdown report as UTF-8 bytes stored on-chain
  report_data: StorageMap<U256, StorageBytes>,

  created_at: StorageMap<U256, StorageU256>,
  completed_at: StorageMap<U256, StorageU256>,
}

// ── Public interface ───────────────────────────────────────────────────────

#[public]
impl RaxcAuditReport {
  /// Create a new audit task — call this before running the RAXC agent.
  /// Returns the task_id to pass to finalize_audit() after the agent finishes.
  pub fn create_audit(&mut self, contract_name: String) -> Result<U256, Vec<u8>> {
    let task_id = self.record_count.get();
    self.record_count.set(task_id + U256::from(1u8));

    let caller = self.vm().msg_sender();
    let now = U256::from(self.vm().block_timestamp());

    self.requester.setter(task_id).set(caller);
    self.contract_name.setter(task_id).set_str(&contract_name);
    self.created_at.setter(task_id).set(now);

    self.vm().log(AuditCreated {
      task_id,
      requester: caller,
      contract_name,
      timestamp: now,
    });

    Ok(task_id)
  }

  /// Finalize an audit — stores the full markdown report as bytes on-chain.
  /// Called by the RAXC agent after analysis completes.
  ///
  /// risk_level: 0=None 1=Low 2=Medium 3=High 4=Critical
  /// confidence: 0–100
  /// report_markdown: UTF-8 encoded markdown report
  pub fn finalize_audit(
    &mut self,
    task_id: U256,
    risk_level: u8,
    confidence: u64,
    vuln_type: String,
    report_markdown: Vec<u8>,
  ) -> Result<(), Vec<u8>> {
    if self.created_at.get(task_id) == U256::ZERO {
      return Err(b"task not found".to_vec());
    }
    if self.completed_at.get(task_id) != U256::ZERO {
      return Err(b"already finalized".to_vec());
    }
    if confidence > 100 {
      return Err(b"confidence must be 0-100".to_vec());
    }

    let hash: FixedBytes<32> = keccak256(&report_markdown);
    let now = U256::from(self.vm().block_timestamp());

    self.risk_level.setter(task_id).set(U8Val::from(risk_level));
    self
      .confidence
      .setter(task_id)
      .set(U64Val::from(confidence));
    self.vuln_type.setter(task_id).set_str(&vuln_type);
    self.report_hash.setter(task_id).set(hash);
    self.report_data.setter(task_id).set_bytes(&report_markdown);
    self.completed_at.setter(task_id).set(now);

    self.vm().log(AuditFinalized {
      task_id,
      risk_level,
      confidence,
      report_hash: hash,
      timestamp: now,
    });

    Ok(())
  }

  /// Read the full markdown report bytes for a task.
  pub fn get_report(&self, task_id: U256) -> Result<Vec<u8>, Vec<u8>> {
    if self.created_at.get(task_id) == U256::ZERO {
      return Err(b"task not found".to_vec());
    }
    Ok(self.report_data.get(task_id).get_bytes())
  }

  /// Verify report integrity — returns true if the provided bytes match the stored keccak256 hash.
  pub fn verify_report(&self, task_id: U256, report_markdown: Vec<u8>) -> bool {
    let stored: FixedBytes<32> = self.report_hash.get(task_id);
    let computed: FixedBytes<32> = keccak256(&report_markdown);
    stored == computed
  }

  // ── Read-only getters ──────────────────────────────────────────────────

  pub fn record_count(&self) -> U256 {
    self.record_count.get()
  }

  pub fn get_requester(&self, task_id: U256) -> Address {
    self.requester.get(task_id)
  }

  pub fn get_risk_level(&self, task_id: U256) -> u8 {
    self.risk_level.get(task_id).as_limbs()[0] as u8
  }

  pub fn get_confidence(&self, task_id: U256) -> u64 {
    self.confidence.get(task_id).as_limbs()[0]
  }

  pub fn get_report_hash(&self, task_id: U256) -> FixedBytes<32> {
    self.report_hash.get(task_id)
  }

  pub fn is_finalized(&self, task_id: U256) -> bool {
    self.completed_at.get(task_id) != U256::ZERO
  }

  pub fn created_at(&self, task_id: U256) -> U256 {
    self.created_at.get(task_id)
  }

  pub fn completed_at(&self, task_id: U256) -> U256 {
    self.completed_at.get(task_id)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use stylus_sdk::testing::*;

  fn setup() -> (TestVM, RaxcAuditReport) {
    let vm = TestVM::new();
    vm.set_block_timestamp(1_000_000);
    vm.set_sender(Address::from([0xAAu8; 20]));
    let contract = RaxcAuditReport::from(&vm);
    (vm, contract)
  }

  #[test]
  fn test_create_audit() {
    let (_vm, mut contract) = setup();
    let task_id = contract
      .create_audit("DeFiVault".to_string())
      .expect("create_audit failed");
    assert_eq!(task_id, U256::ZERO);
    assert_eq!(contract.record_count(), U256::from(1u8));
    assert!(!contract.is_finalized(task_id));
  }

  #[test]
  fn test_finalize_audit() {
    let (_vm, mut contract) = setup();
    let task_id = contract
      .create_audit("DeFiVault".to_string())
      .expect("create_audit failed");

    let report = b"# Audit Report\n**Vulnerability:** Reentrancy".to_vec();
    contract
      .finalize_audit(task_id, 4, 87, "Reentrancy".to_string(), report.clone())
      .expect("finalize_audit failed");

    assert!(contract.is_finalized(task_id));
    assert_eq!(contract.get_risk_level(task_id), 4);
    assert_eq!(contract.get_confidence(task_id), 87);
    assert_eq!(contract.get_report(task_id).unwrap(), report);
  }

  #[test]
  fn test_verify_report() {
    let (_vm, mut contract) = setup();
    let task_id = contract
      .create_audit("TokenPool".to_string())
      .expect("create_audit failed");
    let report = b"# Report".to_vec();
    contract
      .finalize_audit(task_id, 3, 75, "Flash Loan".to_string(), report.clone())
      .expect("finalize failed");

    assert!(contract.verify_report(task_id, report.clone()));
    assert!(!contract.verify_report(task_id, b"tampered".to_vec()));
  }

  #[test]
  fn test_double_finalize_fails() {
    let (_vm, mut contract) = setup();
    let task_id = contract
      .create_audit("Vault".to_string())
      .expect("create failed");
    let report = b"report".to_vec();
    contract
      .finalize_audit(task_id, 1, 50, "None".to_string(), report.clone())
      .expect("first finalize failed");
    let result = contract.finalize_audit(task_id, 1, 50, "None".to_string(), report);
    assert!(result.is_err());
  }

  #[test]
  fn test_invalid_confidence() {
    let (_vm, mut contract) = setup();
    let task_id = contract
      .create_audit("Vault".to_string())
      .expect("create failed");
    let result = contract.finalize_audit(task_id, 1, 101, "None".to_string(), b"r".to_vec());
    assert!(result.is_err());
  }

  // ── data-file upload/download tests ─────────────────────────────────────

  /// Compress bytes with zlib (deflate + header/checksum).
  fn compress(data: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
  }

  /// Decompress zlib bytes back to the original.
  fn decompress(data: &[u8]) -> Vec<u8> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).unwrap();
    out
  }

  /// Upload data/report.md compressed, download it, decompress, verify integrity.
  #[test]
  fn test_upload_download_report_file() {
    let (_vm, mut contract) = setup();

    // Load the real report file at compile time
    let original: &[u8] = include_bytes!("../../data/report.md");

    let compressed = compress(original);
    let original_len = original.len();
    let compressed_len = compressed.len();
    println!(
      "[audit-report] report.md: {} bytes → compressed {} bytes ({:.1}% saving)",
      original_len,
      compressed_len,
      100.0 * (1.0 - compressed_len as f64 / original_len as f64)
    );

    // Upload compressed bytes as the on-chain report
    let task_id = contract
      .create_audit("DeFiVault".to_string())
      .expect("create failed");
    contract
      .finalize_audit(
        task_id,
        4,
        87,
        "Reentrancy".to_string(),
        compressed.clone(),
      )
      .expect("finalize failed");

    // Download and verify hash before decompressing
    assert!(contract.verify_report(task_id, compressed.clone()));

    // Download and decompress
    let downloaded = contract.get_report(task_id).expect("get_report failed");
    assert_eq!(downloaded, compressed, "stored bytes must match uploaded bytes");

    let restored = decompress(&downloaded);
    assert_eq!(restored, original, "decompressed bytes must match original file");

    println!(
      "[audit-report] round-trip OK: restored {} bytes match original",
      restored.len()
    );
  }

  /// Estimate EVM gas cost for uploading `data` bytes as calldata + storage.
  ///
  /// Calldata: 4 gas per zero byte, 16 gas per non-zero byte (EIP-2028).
  /// Storage:  each new 32-byte slot costs ~20,000 gas (SSTORE cold write).
  ///           StorageBytes uses 1 slot for the length + ceil(len/32) slots for data.
  fn estimate_upload_gas(data: &[u8]) -> u64 {
    // Calldata cost
    let calldata: u64 = data
      .iter()
      .map(|&b| if b == 0 { 4u64 } else { 16u64 })
      .sum();

    // Storage cost: length slot + data slots
    let data_slots = data.len().div_ceil(32) as u64;
    let total_slots = 1 + data_slots; // 1 for the length word
    let storage: u64 = total_slots * 20_000;

    calldata + storage
  }

  #[test]
  fn test_gas_estimate_compressed_vs_raw() {
    let original: &[u8] = include_bytes!("../../data/report.md");
    let compressed = compress(original);

    let gas_raw = estimate_upload_gas(original);
    let gas_compressed = estimate_upload_gas(&compressed);
    let saving = gas_raw - gas_compressed;
    let saving_pct = 100.0 * saving as f64 / gas_raw as f64;

    println!("[gas estimate] report.md upload (raw):        {:>10} gas", gas_raw);
    println!("[gas estimate] report.md upload (compressed): {:>10} gas", gas_compressed);
    println!("[gas estimate] gas saved by compression:      {:>10} gas ({:.1}%)", saving, saving_pct);

    // Compressed must always be cheaper
    assert!(
      gas_compressed < gas_raw,
      "compressed upload should cost less gas than raw"
    );
  }

  /// Print ETH and USD cost for each gas price scenario.
  /// formula: cost_eth = gas * gas_price_gwei * 1e-9
  #[test]
  fn test_eth_cost_breakdown() {
    let original: &[u8] = include_bytes!("../../data/report.md");
    let compressed = compress(original);

    let gas_raw        = estimate_upload_gas(original);
    let gas_compressed = estimate_upload_gas(&compressed);
    let gas_saved      = gas_raw - gas_compressed;

    // (label, gwei, usd_per_eth)
    let scenarios: &[(&str, f64, f64)] = &[
      ("Arbitrum One  (typical ~0.01 gwei)", 0.01,  3_000.0),
      ("Arbitrum One  (busy    ~0.1  gwei)", 0.1,   3_000.0),
      ("Ethereum mainnet (low  ~5    gwei)", 5.0,   3_000.0),
      ("Ethereum mainnet (norm ~20   gwei)", 20.0,  3_000.0),
    ];

    println!();
    println!("=== report.md gas cost breakdown ===");
    for (label, gwei, usd_per_eth) in scenarios {
      let eth_raw        = gas_raw        as f64 * gwei * 1e-9;
      let eth_compressed = gas_compressed as f64 * gwei * 1e-9;
      let eth_saved      = gas_saved      as f64 * gwei * 1e-9;
      println!(
        "  {}\n    raw: {:.8} ETH (${:.4})  compressed: {:.8} ETH (${:.4})  saved: {:.8} ETH (${:.4})",
        label,
        eth_raw,        eth_raw        * usd_per_eth,
        eth_compressed, eth_compressed * usd_per_eth,
        eth_saved,      eth_saved      * usd_per_eth,
      );
    }
    println!();

    // Sanity: compressed is always cheaper
    assert!(gas_compressed < gas_raw);
  }
}
