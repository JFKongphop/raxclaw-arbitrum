use alloy::{
  primitives::{U256, address},
  providers::ProviderBuilder,
  sol,
};

sol! {
  #[sol(rpc)]
  interface IAuditReport {
    function getReport(uint256 taskId) external view returns (bytes memory);
    function recordCount() external view returns (uint256);
    function isFinalized(uint256 taskId) external view returns (bool);
    function getRiskLevel(uint256 taskId) external view returns (uint8);
    function getConfidence(uint256 taskId) external view returns (uint64);
  }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenvy::from_path("../.env").ok();

  let rpc_url = std::env::var("ARBITRUM_SEPOLIA").expect("ARBITRUM_SEPOLIA must be set in .env");

  let provider = ProviderBuilder::new().connect(&rpc_url).await?;

  let addr = address!("1074fb96d4e092f8d2bd88474052898e96ee06f4");
  let contract = IAuditReport::new(addr, &provider);

  let count = contract.recordCount().call().await?;
  println!("total records on chain: {count}");

  for i in 0..count.to::<u64>() {
    let task_id = U256::from(i);

    if !contract.isFinalized(task_id).call().await? {
      println!("task {i}: not finalized, skipping");
      continue;
    }

    let data = contract.getReport(task_id).call().await?;
    let risk = contract.getRiskLevel(task_id).call().await?;
    let confidence = contract.getConfidence(task_id).call().await?;

    let out_path = format!("../downloaded_report_{i}.md");
    std::fs::write(&out_path, &data)?;

    println!(
      "task {i}: downloaded {} bytes → {out_path}  (risk={risk}, confidence={confidence}%)",
      data.len()
    );
  }

  Ok(())
}
