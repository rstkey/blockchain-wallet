extern crate crypto_wallet;
use crypto_wallet::wallet;
use hex_literal::hex;
use serde_json::Value;
use tempfile::tempdir;

fn main() {
    let secret: [u8; 32] = hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");

    println!("Creating wallet from secret: {:?}", hex::encode(secret));
    let wallet = wallet::Wallet::from_secret(secret).unwrap();

    let dir = tempdir().expect("failed to create tempdir");
    let password = "password";

    println!("\nCreating keystore file...");
    let file_name = wallet
        .encrypt_keystore(&dir, password.as_bytes())
        .expect("failed to export keystore");
    let keystore_file_path = dir.path().join(file_name);
    println!("Keystore file path: {:?}", keystore_file_path);

    println!("\nContent of the keystore file:");
    let keystore_content =
        std::fs::read_to_string(&keystore_file_path).expect("failed to read file");
    let v: Value = serde_json::from_str(&keystore_content).expect("failed to parse JSON");
    let pretty = serde_json::to_string_pretty(&v).expect("failed to serialize JSON");
    println!("{}", pretty);

    println!("\nImporting keystore file...");
    let recovered = wallet::Wallet::decrypt_keystore(keystore_file_path, password)
        .expect("failed to decrypt keystore");
    assert_eq!(wallet.address(), recovered.address());
    println!("Keystore file imported successfully!");
}
