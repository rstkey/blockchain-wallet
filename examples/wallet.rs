extern crate crypto_wallet;
use crypto_wallet::wallet;
use hex_literal::hex;
use std::fs::read_to_string;
use tempfile::tempdir;

fn main() {
    let secret: [u8; 32] = hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");
    let wallet = wallet::Wallet::from_secret(secret).unwrap();

    // debug
    println!("Wallet = {:?}\n", wallet);

    // Public key
    println!("Public key = {:?}\n", wallet.public_key_hex());

    // Ethereum address
    println!("Ethereum address = {:?}\n", wallet.address());

    // Sign message
    let message = "Hello, world!";
    let signature = wallet.sign_message(message.as_bytes()).unwrap();
    println!("{:?}\n", signature);

    // Export to keystore
    let dir = tempdir().expect("failed to create tempdir");
    let password = "password";
    let file_path = wallet
        .encrypt_keystore(&dir, password.as_bytes())
        .expect("failed to encrypt keystore");

    let keystore_file_path = dir.path().join(file_path);

    println!(
        "Wrote keystore for {:?} to {:?}\n",
        wallet.address(),
        keystore_file_path
    );

    // read the keystore file back
    let recovered = wallet::Wallet::decrypt_keystore(keystore_file_path.clone(), password)
        .expect("failed to decrypt keystore");
    assert_eq!(wallet.address(), recovered.address());

    let keystore_contents =
        read_to_string(keystore_file_path).expect("Error reading keystore file");

    println!("Keystore file contents: {keystore_contents:?}\n");
}
