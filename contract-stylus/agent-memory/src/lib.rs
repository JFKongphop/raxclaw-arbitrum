// RaxcAgentMemory — Stylus (Rust) contract for Arbitrum
// ERC-7857-inspired intelligent agent NFT: stores compact JSON memory summaries as bytes on-chain.
// Each token = one persistent agent identity.
// After every audit the RAXC agent pushes a JSON summary — the agent reads this back
// at the start of the next audit to build long-context memory.
//
// Memory entries use a composite key: keccak256(token_id ++ entry_index)
// This avoids nested maps and works cleanly with Stylus flat storage.
//
// Deploy:  cargo stylus deploy --endpoint <RPC_URL> --private-key <KEY>
// Check:   cargo stylus check
// ABI:     cargo run --bin export-abi --features export-abi

#![cfg_attr(all(not(feature = "export-abi"), not(test)), no_main)]
extern crate alloc;

use alloc::{string::String, vec::Vec};
use alloy_primitives::{keccak256, Address, FixedBytes, U256};
use alloy_sol_types::sol;
use stylus_sdk::{prelude::*, storage::*};

// ── Events ─────────────────────────────────────────────────────────────────

sol! {
    event AgentMinted(
        uint256 indexed token_id,
        address indexed owner,
        address indexed agent
    );

    event MemoryPushed(
        uint256 indexed token_id,
        uint256 indexed entry_index,
        bytes32 content_hash,
        uint256 timestamp
    );
}

// ── Storage ────────────────────────────────────────────────────────────────

#[storage]
#[entrypoint]
pub struct RaxcAgentMemory {
  /// Next token ID to mint
  next_token_id: StorageU256,

  /// token_id → owner address
  token_owner: StorageMap<U256, StorageAddress>,

  /// token_id → authorized agent wallet (Rust process that pushes memory)
  agent_address: StorageMap<U256, StorageAddress>,

  /// token_id → number of memory entries
  mem_count: StorageMap<U256, StorageU256>,

  // Per-entry fields — keyed by composite_key(token_id, entry_index)
  /// Compact JSON summary bytes
  mem_data: StorageMap<U256, StorageBytes>,
  /// keccak256(mem_data) for integrity verification
  mem_hash: StorageMap<U256, StorageFixedBytes<32>>,
  /// Block timestamp of when the entry was pushed
  mem_timestamp: StorageMap<U256, StorageU256>,
  /// Human-readable label e.g. "RAXC Audit: DeFiVault 2026-06-05"
  mem_desc: StorageMap<U256, StorageString>,
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Derive a unique flat storage key from (token_id, entry_index).
/// Equivalent to keccak256(abi.encode(token_id, entry_index)).
fn entry_key(token_id: U256, index: U256) -> U256 {
  let mut buf = [0u8; 64];
  buf[..32].copy_from_slice(&token_id.to_be_bytes::<32>());
  buf[32..].copy_from_slice(&index.to_be_bytes::<32>());
  U256::from_be_bytes(*keccak256(buf))
}

// ── Public interface ───────────────────────────────────────────────────────

#[public]
impl RaxcAgentMemory {
  /// Mint a new agent identity.
  /// `to`    — token owner (user wallet)
  /// `agent` — authorized agent wallet (Rust process that calls push_memory)
  /// Returns the new token_id.
  pub fn mint(&mut self, to: Address, agent: Address) -> Result<U256, Vec<u8>> {
    if to == Address::ZERO {
      return Err(b"invalid owner".to_vec());
    }

    let token_id = self.next_token_id.get();
    self.next_token_id.set(token_id + U256::from(1u8));

    self.token_owner.setter(token_id).set(to);
    self.agent_address.setter(token_id).set(agent);

    self.vm().log(AgentMinted {
      token_id,
      owner: to,
      agent,
    });

    Ok(token_id)
  }

  /// Push a new memory entry after an audit completes.
  /// Only callable by the token owner or authorized agent wallet.
  ///
  /// `summary_json` — compact JSON: contract_name, vuln_type, risk, confidence, explanation, etc.
  /// `description`  — human label e.g. "RAXC Audit: DeFiVault 2026-06-05"
  pub fn push_memory(
    &mut self,
    token_id: U256,
    summary_json: Vec<u8>,
    description: String,
  ) -> Result<(), Vec<u8>> {
    let owner = self.token_owner.get(token_id);
    if owner == Address::ZERO {
      return Err(b"token not found".to_vec());
    }

    let caller = self.vm().msg_sender();
    let agent = self.agent_address.get(token_id);
    if caller != owner && caller != agent {
      return Err(b"not authorized".to_vec());
    }
    if summary_json.is_empty() {
      return Err(b"empty memory".to_vec());
    }

    let index = self.mem_count.get(token_id);
    let key = entry_key(token_id, index);
    let hash: FixedBytes<32> = keccak256(&summary_json);
    let now = U256::from(self.vm().block_timestamp());

    self.mem_data.setter(key).set_bytes(&summary_json);
    self.mem_hash.setter(key).set(hash);
    self.mem_timestamp.setter(key).set(now);
    self.mem_desc.setter(key).set_str(&description);
    self.mem_count.setter(token_id).set(index + U256::from(1u8));

    self.vm().log(MemoryPushed {
      token_id,
      entry_index: index,
      content_hash: hash,
      timestamp: now,
    });

    Ok(())
  }

  /// Read a single memory entry's JSON bytes by index.
  pub fn get_memory_data(&self, token_id: U256, index: U256) -> Result<Vec<u8>, Vec<u8>> {
    self.check_bounds(token_id, index)?;
    Ok(self.mem_data.get(entry_key(token_id, index)).get_bytes())
  }

  /// Read a single memory entry's keccak256 hash by index.
  pub fn get_memory_hash(&self, token_id: U256, index: U256) -> Result<FixedBytes<32>, Vec<u8>> {
    self.check_bounds(token_id, index)?;
    Ok(self.mem_hash.get(entry_key(token_id, index)))
  }

  /// Read a single memory entry's timestamp by index.
  pub fn get_memory_timestamp(&self, token_id: U256, index: U256) -> Result<U256, Vec<u8>> {
    self.check_bounds(token_id, index)?;
    Ok(self.mem_timestamp.get(entry_key(token_id, index)))
  }

  /// Verify a memory entry's integrity.
  /// Returns true if keccak256(data) matches the stored hash.
  pub fn verify_memory(&self, token_id: U256, index: U256, data: Vec<u8>) -> bool {
    if self.check_bounds(token_id, index).is_err() {
      return false;
    }
    let stored: FixedBytes<32> = self.mem_hash.get(entry_key(token_id, index));
    let computed: FixedBytes<32> = keccak256(&data);
    stored == computed
  }

  /// Total number of memory entries for a token.
  pub fn memory_count(&self, token_id: U256) -> U256 {
    self.mem_count.get(token_id)
  }

  /// Owner of a token.
  pub fn owner_of(&self, token_id: U256) -> Address {
    self.token_owner.get(token_id)
  }

  /// Authorized agent wallet for a token.
  pub fn get_agent_address(&self, token_id: U256) -> Address {
    self.agent_address.get(token_id)
  }

  /// Update the authorized agent wallet — only callable by token owner.
  pub fn set_agent_address(&mut self, token_id: U256, agent: Address) -> Result<(), Vec<u8>> {
    let owner = self.token_owner.get(token_id);
    if owner == Address::ZERO {
      return Err(b"token not found".to_vec());
    }
    if self.vm().msg_sender() != owner {
      return Err(b"not token owner".to_vec());
    }
    self.agent_address.setter(token_id).set(agent);
    Ok(())
  }

  /// Total tokens minted.
  pub fn total_supply(&self) -> U256 {
    self.next_token_id.get()
  }
}

impl RaxcAgentMemory {
  /// Internal bounds check for memory entry access.
  fn check_bounds(&self, token_id: U256, index: U256) -> Result<(), Vec<u8>> {
    let owner = self.token_owner.get(token_id);
    if owner == Address::ZERO {
      return Err(b"token not found".to_vec());
    }
    if index >= self.mem_count.get(token_id) {
      return Err(b"index out of bounds".to_vec());
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use stylus_sdk::testing::*;

  fn alice() -> Address {
    Address::from([0x11u8; 20])
  }
  fn agent() -> Address {
    Address::from([0x22u8; 20])
  }

  fn setup() -> (TestVM, RaxcAgentMemory) {
    let vm = TestVM::new();
    vm.set_block_timestamp(1_000_000);
    vm.set_sender(alice());
    let contract = RaxcAgentMemory::from(&vm);
    (vm, contract)
  }

  #[test]
  fn test_mint() {
    let (_vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).expect("mint failed");
    assert_eq!(token_id, U256::ZERO);
    assert_eq!(contract.owner_of(U256::ZERO), alice());
    assert_eq!(contract.get_agent_address(U256::ZERO), agent());
    assert_eq!(contract.memory_count(U256::ZERO), U256::ZERO);
  }

  #[test]
  fn test_push_memory_by_agent() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).expect("mint failed");

    vm.set_sender(agent());
    let json = b"{\"vuln\":\"Reentrancy\"}".to_vec();
    contract
      .push_memory(token_id, json.clone(), "Audit: DeFiVault".to_string())
      .expect("push_memory failed");

    assert_eq!(contract.memory_count(token_id), U256::from(1u8));
    let data = contract.get_memory_data(token_id, U256::ZERO).unwrap();
    assert_eq!(data, json);
  }

  #[test]
  fn test_verify_memory() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).expect("mint failed");

    vm.set_sender(agent());
    let json = b"{\"risk\":\"Critical\"}".to_vec();
    contract
      .push_memory(token_id, json.clone(), "desc".to_string())
      .expect("push failed");

    assert!(contract.verify_memory(token_id, U256::ZERO, json.clone()));
    assert!(!contract.verify_memory(token_id, U256::ZERO, b"tampered".to_vec()));
  }

  #[test]
  fn test_unauthorized_push_fails() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).expect("mint failed");

    vm.set_sender(Address::from([0x99u8; 20]));
    let result = contract.push_memory(token_id, b"data".to_vec(), "d".to_string());
    assert!(result.is_err());
  }

  #[test]
  fn test_multiple_entries() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).expect("mint failed");
    vm.set_sender(agent());

    for i in 0..3u8 {
      let json = alloc::format!("{{\"entry\":{}}}", i).into_bytes();
      contract
        .push_memory(token_id, json, alloc::format!("entry {}", i))
        .expect("push failed");
    }
    assert_eq!(contract.memory_count(token_id), U256::from(3u8));
  }

  // ── data-file upload/download tests ─────────────────────────────────────

  /// Compress bytes with zlib.
  fn compress(data: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
  }

  /// Decompress zlib bytes.
  fn decompress(data: &[u8]) -> Vec<u8> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).unwrap();
    out
  }

  /// Upload data/memory.json compressed, download it, decompress, verify integrity.
  #[test]
  fn test_upload_download_memory_file() {
    let (vm, mut contract) = setup();

    // Load the real memory JSON file at compile time
    let original: &[u8] = include_bytes!("../../data/memory.json");

    let compressed = compress(original);
    let original_len = original.len();
    let compressed_len = compressed.len();
    println!(
      "[agent-memory] memory.json: {} bytes → compressed {} bytes ({:.1}% saving)",
      original_len,
      compressed_len,
      100.0 * (1.0 - compressed_len as f64 / original_len as f64)
    );

    // Mint token and push compressed memory entry
    let token_id = contract.mint(alice(), agent()).expect("mint failed");
    vm.set_sender(agent());
    contract
      .push_memory(
        token_id,
        compressed.clone(),
        "RAXC Audit: DeFiVault 2026-06-01".to_string(),
      )
      .expect("push_memory failed");

    // Verify the stored hash matches the compressed bytes
    assert!(contract.verify_memory(token_id, U256::ZERO, compressed.clone()));

    // Download and decompress
    let downloaded = contract
      .get_memory_data(token_id, U256::ZERO)
      .expect("get_memory_data failed");
    assert_eq!(
      downloaded, compressed,
      "stored bytes must match uploaded bytes"
    );

    let restored = decompress(&downloaded);
    assert_eq!(restored, original, "decompressed bytes must match original file");

    println!(
      "[agent-memory] round-trip OK: restored {} bytes match original",
      restored.len()
    );
  }

  /// Estimate EVM gas cost for uploading `data` bytes as calldata + storage.
  ///
  /// Calldata: 4 gas per zero byte, 16 gas per non-zero byte (EIP-2028).
  /// Storage:  each new 32-byte slot costs ~20,000 gas (SSTORE cold write).
  ///           StorageBytes uses 1 slot for the length + ceil(len/32) slots for data.
  fn estimate_upload_gas(data: &[u8]) -> u64 {
    let calldata: u64 = data
      .iter()
      .map(|&b| if b == 0 { 4u64 } else { 16u64 })
      .sum();
    let data_slots = data.len().div_ceil(32) as u64;
    let total_slots = 1 + data_slots;
    let storage: u64 = total_slots * 20_000;
    calldata + storage
  }

  #[test]
  fn test_gas_estimate_compressed_vs_raw() {
    let original: &[u8] = include_bytes!("../../data/memory.json");
    let compressed = compress(original);

    let gas_raw = estimate_upload_gas(original);
    let gas_compressed = estimate_upload_gas(&compressed);
    let saving = gas_raw - gas_compressed;
    let saving_pct = 100.0 * saving as f64 / gas_raw as f64;

    println!("[gas estimate] memory.json upload (raw):        {:>10} gas", gas_raw);
    println!("[gas estimate] memory.json upload (compressed): {:>10} gas", gas_compressed);
    println!("[gas estimate] gas saved by compression:        {:>10} gas ({:.1}%)", saving, saving_pct);

    assert!(
      gas_compressed < gas_raw,
      "compressed upload should cost less gas than raw"
    );
  }

  /// Print ETH and USD cost for each gas price scenario.
  #[test]
  fn test_eth_cost_breakdown() {
    let original: &[u8] = include_bytes!("../../data/memory.json");
    let compressed = compress(original);

    let gas_raw        = estimate_upload_gas(original);
    let gas_compressed = estimate_upload_gas(&compressed);
    let gas_saved      = gas_raw - gas_compressed;

    let scenarios: &[(&str, f64, f64)] = &[
      ("Arbitrum One  (typical ~0.01 gwei)", 0.01,  3_000.0),
      ("Arbitrum One  (busy    ~0.1  gwei)", 0.1,   3_000.0),
      ("Ethereum mainnet (low  ~5    gwei)", 5.0,   3_000.0),
      ("Ethereum mainnet (norm ~20   gwei)", 20.0,  3_000.0),
    ];

    println!();
    println!("=== memory.json gas cost breakdown ===");
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

    assert!(gas_compressed < gas_raw);
  }
}
