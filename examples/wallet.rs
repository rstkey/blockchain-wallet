extern crate crypto_wallet;
use crypto_wallet::wallet;
use hex_literal::hex;

fn main() {
    let secret: [u8; 32] = hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");
    let wallet = wallet::Wallet::from_secret(secret).unwrap();

    println!("Public key: {:?}", wallet.public_key_hex());
    println!("Ethereum address: {:?}", wallet.address());

    let message = "Hello, world!";
    let signature = wallet.sign_message(message.as_bytes()).unwrap();
    println!("Signature: {:?}", signature);
}
