use alloy::{
  network::EthereumWallet,
  primitives::{U256, address},
  providers::ProviderBuilder,
  signers::local::PrivateKeySigner,
  sol,
};
use std::str::FromStr;

sol! {
  #[sol(rpc)]
  interface IAgentMemory {
    function mint(address to, address agent) external returns (uint256 tokenId);
    function pushMemory(uint256 tokenId, bytes calldata summaryJson, string calldata description) external;
    function getMemoryData(uint256 tokenId, uint256 index) external view returns (bytes memory);
    function getMemoryHash(uint256 tokenId, uint256 index) external view returns (bytes32);
    function verifyMemory(uint256 tokenId, uint256 index, bytes calldata data) external view returns (bool);
    function memoryCount(uint256 tokenId) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
    function totalSupply() external view returns (uint256);
  }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenvy::from_path("../.env").ok();

  let rpc_url = std::env::var("ARBITRUM_SEPOLIA").expect("ARBITRUM_SEPOLIA must be set in .env");
  let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set in .env");

  let signer = PrivateKeySigner::from_str(&private_key)?;
  let wallet_addr = signer.address();
  let wallet = EthereumWallet::from(signer);
  let provider = ProviderBuilder::new()
    .wallet(wallet)
    .connect(&rpc_url)
    .await?;

  let addr = address!("4dd833d6e078b053beff3874ff6e4a93549a25e7");
  let contract = IAgentMemory::new(addr, &provider);

  println!("=== AgentMemory ({addr}) ===");
  println!(
    "total supply before: {}",
    contract.totalSupply().call().await?
  );

  // Mint a new agent token (owner = caller, agent = caller for demo).
  println!("minting agent token...");
  let receipt = contract
    .mint(wallet_addr, wallet_addr)
    .send()
    .await?
    .get_receipt()
    .await?;
  println!("mint tx: {:?}", receipt.transaction_hash);

  let token_id = contract.totalSupply().call().await? - U256::from(1);
  println!("token_id: {token_id}");
  println!("owner:    {}", contract.ownerOf(token_id).call().await?);

  // Push a memory entry — read the real memory.json from data/.
  let summary = std::fs::read("../data/memory.json")
    .expect("data/memory.json not found — run from the workspace root");
  println!("pushing memory entry ({} bytes from data/memory.json)...", summary.len());
  let receipt = contract
    .pushMemory(
      token_id,
      summary.clone().into(),
      "RAXC Audit: DeFiVault 2026-06-07".to_string(),
    )
    .send()
    .await?
    .get_receipt()
    .await?;
  println!("pushMemory tx: {:?}", receipt.transaction_hash);

  println!(
    "memory count: {}",
    contract.memoryCount(token_id).call().await?
  );

  // Read it back and verify integrity.
  let data = contract.getMemoryData(token_id, U256::ZERO).call().await?;
  println!("memory[0] ({} bytes): {}", data.len(), String::from_utf8_lossy(&data));

  let valid = contract
    .verifyMemory(token_id, U256::ZERO, summary.into())
    .call()
    .await?;
  println!("integrity check: {valid}");

  Ok(())
}
