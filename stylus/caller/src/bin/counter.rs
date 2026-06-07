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
  interface ICounter {
    function number() external view returns (uint256);
    function setNumber(uint256 newNumber) external;
    function increment() external;
    function addNumber(uint256 newNumber) external;
    function mulNumber(uint256 newNumber) external;
  }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenvy::from_path("../../.env").ok();

  let rpc_url = std::env::var("ARBITRUM_SEPOLIA").expect("ARBITRUM_SEPOLIA must be set in .env");
  let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set in .env");

  let signer = PrivateKeySigner::from_str(&private_key)?;
  let wallet = EthereumWallet::from(signer);
  let provider = ProviderBuilder::new()
    .wallet(wallet)
    .connect(&rpc_url)
    .await?;

  // Replace with your deployed Counter address.
  let addr = address!("a018a255881e0525831df7bcdf9a03d1b06e1790");
  let counter = ICounter::new(addr, &provider);

  println!("=== Counter ({addr}) ===");
  println!("number: {}", counter.number().call().await?);

  counter.increment().send().await?.get_receipt().await?;
  println!("number after increment: {}", counter.number().call().await?);

  counter
    .addNumber(U256::from(10))
    .send()
    .await?
    .get_receipt()
    .await?;
  println!(
    "number after addNumber(10): {}",
    counter.number().call().await?
  );

  counter
    .mulNumber(U256::from(2))
    .send()
    .await?
    .get_receipt()
    .await?;
  println!(
    "number after mulNumber(2): {}",
    counter.number().call().await?
  );

  // Reset for next run.
  counter
    .setNumber(U256::ZERO)
    .send()
    .await?
    .get_receipt()
    .await?;
  println!("reset to 0");

  Ok(())
}
