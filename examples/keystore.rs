extern crate crypto_wallet;
use crypto_wallet::wallet;
use hex_literal::hex;
use tempfile::tempdir;

fn main() {
    let secret: [u8; 32] = hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");
    let wallet = wallet::Wallet::from_secret(secret).unwrap();

    let dir = tempdir().expect("failed to create tempdir");
    let password = "password";
    let file_path = wallet
        .encrypt_keystore(&dir, password.as_bytes())
        .expect("failed to encrypt keystore");

    let keystore_file_path = dir.path().join(file_path);
    println!("Keystore file path: {:?}", keystore_file_path);

    let recovered = wallet::Wallet::decrypt_keystore(keystore_file_path, password)
        .expect("failed to decrypt keystore");
    assert_eq!(wallet.address(), recovered.address());
}
