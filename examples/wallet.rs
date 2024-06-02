extern crate crypto_wallet;
use crypto_wallet::wallet;
use hex_literal::hex;

fn main() {
    let secret: [u8; 32] = hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");
    println!("Creating wallet from secret: {:?}", hex::encode(secret));

    let wallet = wallet::Wallet::from_secret(secret).unwrap();

    println!("\nWallet created successfully! The following are the wallet details:");
    println!("Public key: {:?}", wallet.public_key_hex());
    println!("Ethereum address: {:?}", wallet.address());

    println!("\nSigning a message...");
    let message = "Hello, world!";
    let signature = wallet.sign_message(message.as_bytes()).unwrap();
    println!("Message: {:?}", message);
    println!("Signature: {:?}", signature);
}
