use alloc::{string::String, vec::Vec};
use alloy_primitives::{Address, FixedBytes, U256, Uint, keccak256};
use alloy_sol_types::sol;
use stylus_sdk::{prelude::*, storage::*};

type U8Val = Uint<8, 1>;
type U64Val = Uint<64, 1>;

// ── Events ────────────────────────────────────────────────────────────────────

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

// ── Storage ───────────────────────────────────────────────────────────────────

/// RiskLevel: 0=None 1=Low 2=Medium 3=High 4=Critical
#[storage]
#[entrypoint]
pub struct RaxcAuditReport {
  record_count: StorageU256,
  requester: StorageMap<U256, StorageAddress>,
  contract_name: StorageMap<U256, StorageString>,
  risk_level: StorageMap<U256, StorageU8>,
  confidence: StorageMap<U256, StorageU64>,
  vuln_type: StorageMap<U256, StorageString>,
  report_hash: StorageMap<U256, StorageFixedBytes<32>>,
  report_data: StorageMap<U256, StorageBytes>,
  created_at: StorageMap<U256, StorageU256>,
  completed_at: StorageMap<U256, StorageU256>,
}

// ── Public interface ──────────────────────────────────────────────────────────

#[public]
impl RaxcAuditReport {
  /// Create a new audit task. Returns the task_id.
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
  /// risk_level: 0=None 1=Low 2=Medium 3=High 4=Critical
  /// confidence: 0–100
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

  /// Returns true if the provided bytes match the stored keccak256 hash.
  pub fn verify_report(&self, task_id: U256, report_markdown: Vec<u8>) -> bool {
    let stored: FixedBytes<32> = self.report_hash.get(task_id);
    let computed: FixedBytes<32> = keccak256(&report_markdown);
    stored == computed
  }

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

// ── Tests ─────────────────────────────────────────────────────────────────────

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
    let task_id = contract.create_audit("DeFiVault".to_string()).unwrap();
    assert_eq!(task_id, U256::ZERO);
    assert_eq!(contract.record_count(), U256::from(1u8));
    assert!(!contract.is_finalized(task_id));
  }

  #[test]
  fn test_finalize_audit() {
    let (_vm, mut contract) = setup();
    let task_id = contract.create_audit("DeFiVault".to_string()).unwrap();
    let report = b"# Audit Report\n**Vulnerability:** Reentrancy".to_vec();
    contract
      .finalize_audit(task_id, 4, 87, "Reentrancy".to_string(), report.clone())
      .unwrap();
    assert!(contract.is_finalized(task_id));
    assert_eq!(contract.get_risk_level(task_id), 4);
    assert_eq!(contract.get_confidence(task_id), 87);
    assert_eq!(contract.get_report(task_id).unwrap(), report);
  }

  #[test]
  fn test_verify_report() {
    let (_vm, mut contract) = setup();
    let task_id = contract.create_audit("TokenPool".to_string()).unwrap();
    let report = b"# Report".to_vec();
    contract
      .finalize_audit(task_id, 3, 75, "Flash Loan".to_string(), report.clone())
      .unwrap();
    assert!(contract.verify_report(task_id, report.clone()));
    assert!(!contract.verify_report(task_id, b"tampered".to_vec()));
  }

  #[test]
  fn test_double_finalize_fails() {
    let (_vm, mut contract) = setup();
    let task_id = contract.create_audit("Vault".to_string()).unwrap();
    let report = b"report".to_vec();
    contract
      .finalize_audit(task_id, 1, 50, "None".to_string(), report.clone())
      .unwrap();
    assert!(
      contract
        .finalize_audit(task_id, 1, 50, "None".to_string(), report)
        .is_err()
    );
  }

  #[test]
  fn test_invalid_confidence() {
    let (_vm, mut contract) = setup();
    let task_id = contract.create_audit("Vault".to_string()).unwrap();
    assert!(
      contract
        .finalize_audit(task_id, 1, 101, "None".to_string(), b"r".to_vec())
        .is_err()
    );
  }

  fn compress(data: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
  }

  fn decompress(data: &[u8]) -> Vec<u8> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).unwrap();
    out
  }

  #[test]
  fn test_upload_download_report_file() {
    let (_vm, mut contract) = setup();
    // Path is relative to this source file: src/audit_report.rs → ../report.md
    let original: &[u8] = include_bytes!("../data/report.md");
    let compressed = compress(original);
    println!(
      "[audit-report] report.md: {} bytes → compressed {} bytes",
      original.len(),
      compressed.len()
    );

    let task_id = contract.create_audit("DeFiVault".to_string()).unwrap();
    contract
      .finalize_audit(task_id, 4, 87, "Reentrancy".to_string(), compressed.clone())
      .unwrap();

    assert!(contract.verify_report(task_id, compressed.clone()));
    let downloaded = contract.get_report(task_id).unwrap();
    assert_eq!(downloaded, compressed);
    let restored = decompress(&downloaded);
    assert_eq!(restored, original);
    println!("[audit-report] round-trip OK: {} bytes", restored.len());
  }

  fn estimate_upload_gas(data: &[u8]) -> u64 {
    let calldata: u64 = data
      .iter()
      .map(|&b| if b == 0 { 4u64 } else { 16u64 })
      .sum();
    let storage: u64 = (1 + data.len().div_ceil(32) as u64) * 20_000;
    calldata + storage
  }

  #[test]
  fn test_gas_estimate_compressed_vs_raw() {
    let original: &[u8] = include_bytes!("../data/report.md");
    let compressed = compress(original);
    let gas_raw = estimate_upload_gas(original);
    let gas_compressed = estimate_upload_gas(&compressed);
    let saving_pct = 100.0 * (gas_raw - gas_compressed) as f64 / gas_raw as f64;
    println!(
      "[gas] raw: {} | compressed: {} | saved: {:.1}%",
      gas_raw, gas_compressed, saving_pct
    );
    assert!(gas_compressed < gas_raw);
  }
}
