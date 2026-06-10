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
  interface IAuditReport {
    function createAudit(string calldata contractName) external returns (uint256 taskId);
    function finalizeAudit(
      uint256 taskId,
      uint8 riskLevel,
      uint64 confidence,
      string calldata vulnType,
      bytes calldata reportMarkdown
    ) external;
    function getReport(uint256 taskId) external view returns (bytes memory);
    function verifyReport(uint256 taskId, bytes calldata reportMarkdown) external view returns (bool);
    function isFinalized(uint256 taskId) external view returns (bool);
    function getRiskLevel(uint256 taskId) external view returns (uint8);
    function getConfidence(uint256 taskId) external view returns (uint64);
    function recordCount() external view returns (uint256);
  }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenvy::from_path("../.env").ok();

  let rpc_url = std::env::var("ARBITRUM_SEPOLIA").expect("ARBITRUM_SEPOLIA must be set in .env");
  let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set in .env");

  let signer = PrivateKeySigner::from_str(&private_key)?;
  let wallet = EthereumWallet::from(signer);
  let provider = ProviderBuilder::new()
    .wallet(wallet)
    .connect(&rpc_url)
    .await?;

  let addr = address!("1074fb96d4e092f8d2bd88474052898e96ee06f4");
  let contract = IAuditReport::new(addr, &provider);

  println!("=== AuditReport ({addr}) ===");
  println!(
    "record count before: {}",
    contract.recordCount().call().await?
  );

  // Create a new audit task.
  println!("creating audit task for 'DeFiVault'...");
  let receipt = contract
    .createAudit("DeFiVault".to_string())
    .send()
    .await?
    .get_receipt()
    .await?;
  println!("createAudit tx: {:?}", receipt.transaction_hash);

  let task_id = contract.recordCount().call().await? - U256::from(1);
  println!("task_id: {task_id}");

  // Finalize with the real report — read data/report.md from disk.
  let report = std::fs::read("../data/report.md")
    .expect("data/report.md not found — run from the workspace root");
  println!("finalizing audit ({} bytes from data/report.md)...", report.len());
  let receipt = contract
    .finalizeAudit(
      task_id,
      4,  // Critical
      87, // 87% confidence
      "Reentrancy".to_string(),
      report.clone().into(),
    )
    .send()
    .await?
    .get_receipt()
    .await?;
  println!("finalizeAudit tx: {:?}", receipt.transaction_hash);

  println!("finalized:   {}", contract.isFinalized(task_id).call().await?);
  println!("risk level:  {}", contract.getRiskLevel(task_id).call().await?);
  println!("confidence:  {}", contract.getConfidence(task_id).call().await?);

  // Read report back and show first 120 chars.
  let stored = contract.getReport(task_id).call().await?;
  let preview = String::from_utf8_lossy(&stored);
  println!("report ({} bytes): {}...", stored.len(), &preview[..preview.len().min(120)]);

  // Verify integrity.
  let valid = contract.verifyReport(task_id, report.into()).call().await?;
  println!("integrity check: {valid}");

  Ok(())
}
