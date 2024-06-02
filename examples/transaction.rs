extern crate crypto_wallet;
use alloy::{
    node_bindings::Anvil,
    providers::{Provider, ProviderBuilder},
};
use anyhow::Result;
use crypto_wallet::{transaction::Transaction, wallet::Wallet};
use ethnum::AsU256;
use hex_literal::hex;

#[tokio::main]
async fn main() -> Result<()> {
    let anvil = Anvil::new()
        .block_time(1)
        .try_spawn()
        .expect("Failed to spawn Anvil");

    println!("Creating provider with endpoint: {}", anvil.endpoint_url());
    let provider = ProviderBuilder::new().on_http(anvil.endpoint_url());

    // Create two wallets
    let wallet_a = Wallet::from_secret(hex!(
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
    ))
    .unwrap();
    let wallet_b = Wallet::from_secret(anvil.keys()[0].to_bytes()).unwrap();

    println!("\nCreated two wallets successfully!");
    println!("Wallet A address: {}", wallet_a.anvil_address());
    println!("Wallet B address: {}", wallet_b.anvil_address());

    // check both balance
    let balance_a = provider.get_balance(wallet_a.anvil_address()).await?;
    let balance_b = provider.get_balance(wallet_b.anvil_address()).await?;
    println!("Checking balance...");
    println!("Balance A: {}\nBalance B: {}", balance_a, balance_b);

    let mut transaction = Transaction {
        chain_id: anvil.chain_id().as_u256(),
        value: 999999.as_u256(),
        to: Some(wallet_a.address().clone()),
        nonce: 0.as_u256(),
        max_priority_fee_per_gas: 28e9.as_u256(),
        max_fee_per_gas: 42e9.as_u256(),
        gas: 100_000.as_u256(),
        ..Default::default()
    };

    println!("\nCreating transaction...");
    println!("Transaction: {:?}", transaction);

    let payload = transaction.sign_with_wallet(&wallet_b).unwrap();
    println!("\nSigning transaction...");
    println!("Signed Transaction Payload: {:?}", hex::encode(&payload));

    let receipt = provider
        .send_raw_transaction(&payload)
        .await?
        .get_receipt()
        .await?;
    println!("\nTransaction sent successfully!");
    println!("Transaction hash: {:?}", receipt.transaction_hash);

    // check both balance
    let balance_a = provider.get_balance(wallet_a.anvil_address()).await?;
    let balance_b = provider.get_balance(wallet_b.anvil_address()).await?;
    println!("\nChecking balance...");
    println!("Balance A: {}\nBalance B: {}", balance_a, balance_b);

    Ok(())
}
