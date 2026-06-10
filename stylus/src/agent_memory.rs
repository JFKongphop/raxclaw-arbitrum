use alloc::{string::String, vec::Vec};
use alloy_primitives::{Address, Bytes, FixedBytes, U256, keccak256};
use alloy_sol_types::sol;
use stylus_sdk::{prelude::*, storage::*};

// ── Events ────────────────────────────────────────────────────────────────────

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

// ── Storage ───────────────────────────────────────────────────────────────────

#[storage]
#[entrypoint]
pub struct RaxcAgentMemory {
  next_token_id: StorageU256,
  token_owner: StorageMap<U256, StorageAddress>,
  agent_address: StorageMap<U256, StorageAddress>,
  mem_count: StorageMap<U256, StorageU256>,
  mem_data: StorageMap<U256, StorageBytes>,
  mem_hash: StorageMap<U256, StorageFixedBytes<32>>,
  mem_timestamp: StorageMap<U256, StorageU256>,
  mem_desc: StorageMap<U256, StorageString>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derive a unique flat storage key from (token_id, entry_index).
fn entry_key(token_id: U256, index: U256) -> U256 {
  let mut buf = [0u8; 64];
  buf[..32].copy_from_slice(&token_id.to_be_bytes::<32>());
  buf[32..].copy_from_slice(&index.to_be_bytes::<32>());
  U256::from_be_bytes(*keccak256(buf))
}

// ── Public interface ──────────────────────────────────────────────────────────

#[public]
impl RaxcAgentMemory {
  /// Mint a new agent identity. Returns the new token_id.
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
  pub fn push_memory(
    &mut self,
    token_id: U256,
    summary_json: Bytes,
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
  pub fn get_memory_data(&self, token_id: U256, index: U256) -> Result<Bytes, Vec<u8>> {
    self.check_bounds(token_id, index)?;
    Ok(Bytes::from(self.mem_data.get(entry_key(token_id, index)).get_bytes()))
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
  pub fn verify_memory(&self, token_id: U256, index: U256, data: Bytes) -> bool {
    if self.check_bounds(token_id, index).is_err() {
      return false;
    }
    let stored: FixedBytes<32> = self.mem_hash.get(entry_key(token_id, index));
    keccak256(&data) == stored
  }

  pub fn memory_count(&self, token_id: U256) -> U256 {
    self.mem_count.get(token_id)
  }
  pub fn owner_of(&self, token_id: U256) -> Address {
    self.token_owner.get(token_id)
  }
  pub fn get_agent_address(&self, token_id: U256) -> Address {
    self.agent_address.get(token_id)
  }
  pub fn total_supply(&self) -> U256 {
    self.next_token_id.get()
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
}

impl RaxcAgentMemory {
  fn check_bounds(&self, token_id: U256, index: U256) -> Result<(), Vec<u8>> {
    if self.token_owner.get(token_id) == Address::ZERO {
      return Err(b"token not found".to_vec());
    }
    if index >= self.mem_count.get(token_id) {
      return Err(b"index out of bounds".to_vec());
    }
    Ok(())
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
    let token_id = contract.mint(alice(), agent()).unwrap();
    assert_eq!(token_id, U256::ZERO);
    assert_eq!(contract.owner_of(U256::ZERO), alice());
    assert_eq!(contract.get_agent_address(U256::ZERO), agent());
    assert_eq!(contract.memory_count(U256::ZERO), U256::ZERO);
  }

  #[test]
  fn test_push_memory_by_agent() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).unwrap();
    vm.set_sender(agent());
    let json = b"{\"vuln\":\"Reentrancy\"}".to_vec();
    contract
      .push_memory(token_id, json.clone().into(), "Audit: DeFiVault".to_string())
      .unwrap();
    assert_eq!(contract.memory_count(token_id), U256::from(1u8));
    assert_eq!(
      contract.get_memory_data(token_id, U256::ZERO).unwrap(),
      json
    );
  }

  #[test]
  fn test_verify_memory() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).unwrap();
    vm.set_sender(agent());
    let json = b"{\"risk\":\"Critical\"}".to_vec();
    contract
      .push_memory(token_id, json.clone().into(), "desc".to_string())
      .unwrap();
    assert!(contract.verify_memory(token_id, U256::ZERO, json.clone().into()));
    assert!(!contract.verify_memory(token_id, U256::ZERO, b"tampered".to_vec().into()));
  }

  #[test]
  fn test_unauthorized_push_fails() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).unwrap();
    vm.set_sender(Address::from([0x99u8; 20]));
    assert!(
      contract
        .push_memory(token_id, b"data".to_vec().into(), "d".to_string())
        .is_err()
    );
  }

  #[test]
  fn test_multiple_entries() {
    let (vm, mut contract) = setup();
    let token_id = contract.mint(alice(), agent()).unwrap();
    vm.set_sender(agent());
    for i in 0..3u8 {
      let json = alloc::format!("{{\"entry\":{}}}", i).into_bytes();
      contract
        .push_memory(token_id, json.into(), alloc::format!("entry {}", i))
        .unwrap();
    }
    assert_eq!(contract.memory_count(token_id), U256::from(3u8));
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
  fn test_upload_download_memory_file() {
    let (vm, mut contract) = setup();
    // Path is relative to this source file: src/agent_memory.rs → ../memory.json
    let original: &[u8] = include_bytes!("../data/memory.json");
    let compressed = compress(original);
    println!(
      "[agent-memory] memory.json: {} bytes → compressed {} bytes",
      original.len(),
      compressed.len()
    );

    let token_id = contract.mint(alice(), agent()).unwrap();
    vm.set_sender(agent());
    contract
      .push_memory(
        token_id,
        compressed.clone().into(),
        "RAXC Audit: DeFiVault 2026-06-01".to_string(),
      )
      .unwrap();

    assert!(contract.verify_memory(token_id, U256::ZERO, compressed.clone().into()));
    let downloaded = contract.get_memory_data(token_id, U256::ZERO).unwrap();
    assert_eq!(downloaded, compressed);
    let restored = decompress(&downloaded);
    assert_eq!(restored, original);
    println!("[agent-memory] round-trip OK: {} bytes", restored.len());
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
    let original: &[u8] = include_bytes!("../data/memory.json");
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

  #[test]
  fn test_eth_cost_breakdown() {
    let original: &[u8] = include_bytes!("../data/memory.json");
    let compressed = compress(original);
    let gas_raw = estimate_upload_gas(original);
    let gas_compressed = estimate_upload_gas(&compressed);
    let gas_saved = gas_raw - gas_compressed;
    let scenarios: &[(&str, f64, f64)] = &[
      ("Arbitrum One  (typical ~0.01 gwei)", 0.01, 3_000.0),
      ("Arbitrum One  (busy    ~0.1  gwei)", 0.1, 3_000.0),
      ("Ethereum mainnet (low  ~5    gwei)", 5.0, 3_000.0),
      ("Ethereum mainnet (norm ~20   gwei)", 20.0, 3_000.0),
    ];
    println!("\n=== memory.json gas cost breakdown ===");
    for (label, gwei, usd_per_eth) in scenarios {
      let eth_raw = gas_raw as f64 * gwei * 1e-9;
      let eth_compressed = gas_compressed as f64 * gwei * 1e-9;
      let eth_saved = gas_saved as f64 * gwei * 1e-9;
      println!(
        "  {}\n    raw: {:.8} ETH (${:.4})  compressed: {:.8} ETH (${:.4})  saved: {:.8} ETH (${:.4})",
        label,
        eth_raw,
        eth_raw * usd_per_eth,
        eth_compressed,
        eth_compressed * usd_per_eth,
        eth_saved,
        eth_saved * usd_per_eth
      );
    }
    assert!(gas_compressed < gas_raw);
  }
}
