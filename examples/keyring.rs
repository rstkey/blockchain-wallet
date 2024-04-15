extern crate crypto_wallet;
use std::fs::read_to_string;

use crypto_wallet::keyring;
use tempfile::tempdir;

pub fn main() {
    let mnemonic = "lend pole exclude donkey range tank gather space dress topic fantasy siege";
    let password = "";
    let mut keyring =
        keyring::Keyring::new_from_mnemonic_phrase(&mnemonic, Some(password.to_string()))
            .expect("failed to create keyring");

    let expected = [
        "0x854c3009720121F5f8BFD6Ff5d9b72a6bB21736C",
        "0x5a4d18d63Ab8e20B96D18aa2bbB56D06fC30798F",
    ];

    // create 5 accounts
    let addresses = keyring.add_accounts(5).expect("failed to add accounts");
    println!("Created accounts: {:?}", addresses);

    // make sure the first two accounts are the same as expected
    for i in 0..2 {
        assert_eq!(addresses[i].to_string(), expected[i]);
    }

    // get wallet
    let wallet = keyring
        .get_wallet(&addresses[0])
        .expect("failed to get wallet");

    // test sign message
    let message = "Hello, world!";
    let signature = wallet.sign_message(message.as_bytes()).unwrap();
    println!("Signature: {:?}", signature);

    // Test encrypt to vault
    let dir = tempdir().expect("failed to create tempdir");
    let filename = keyring
        .export_to_file(&dir)
        .expect("failed to export to file");
    let file_path = dir.path().join(filename);

    let recovered = keyring::Keyring::import_from_file(file_path.clone(), password.to_string())
        .expect("failed to import from file");

    // make sure the addresses are the same
    let addresses = keyring.get_addresses();
    let recovered_addresses = recovered.get_addresses();
    assert_eq!(addresses, recovered_addresses);
    println!("Recovered addresses: {:?}", recovered_addresses);

    let vault_content = read_to_string(file_path).expect("Error reading vault file");
    println!("Vault file contents: {vault_content:?}\n")
}
