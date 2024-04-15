use alloy::{
    node_bindings::Anvil,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use anyhow::{Ok, Result};
use crypto_wallet::{transaction::Transaction, wallet::Wallet};
use ethnum::AsU256;
use hex_literal::hex;

extern crate crypto_wallet;

#[tokio::main]
async fn main() -> Result<()> {
    // anvil node
    let anvil = Anvil::new()
        .block_time(1)
        .try_spawn()
        .expect("Failed to spawn Anvil");

    // provider
    let provider = ProviderBuilder::new()
        .on_http(anvil.endpoint_url())
        .expect("Failed to build provider");

    // Wallet
    let wallet_a = Wallet::from_secret(hex!(
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
    ))
    .unwrap();
    let wallet_b = Wallet::from_secret(anvil.keys()[0].to_bytes()).unwrap();

    // check wallet a & b balance
    let balance = provider
        .get_balance(Address::from_slice(wallet_a.address().as_slice()), None)
        .await
        .expect("Failed to get balance");
    println!("Balance A: {}", balance);

    let balance = provider
        .get_balance(Address::from_slice(wallet_b.address().as_slice()), None)
        .await
        .expect("Failed to get balance");
    println!("Balance B: {}", balance);

    // create transaction
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

    // sign transaction
    let payload = transaction.sign_with_wallet(&wallet_b).unwrap();

    // send transaction
    let receipt = provider
        .send_raw_transaction(&payload)
        .await?
        .get_receipt()
        .await?;
    println!("Send transaction: {:?}", receipt.transaction_hash);

    // check wallet a & b balance
    let balance = provider
        .get_balance(Address::from_slice(wallet_a.address().as_slice()), None)
        .await?;
    println!("Balance A: {}", balance);

    let balance = provider
        .get_balance(Address::from_slice(wallet_b.address().as_slice()), None)
        .await?;
    println!("Balance B: {}", balance);

    Ok(())
}
