extern crate crypto_wallet;
use crypto_wallet::{hdwallet, vault};
use tempfile::tempdir;

fn main() {
    run_example(vault::EncryptionOptions::Aes256Gcm);
    run_example(vault::EncryptionOptions::SpeckCBC);
}

fn run_example(algorithm: vault::EncryptionOptions) {
    println!("Starting example with {:?}", algorithm);

    let mut hdwallet = hdwallet::HDWallet::new_random(None).unwrap();
    hdwallet.add_accounts(5).expect("failed to add accounts");
    println!("Created HDWallet and added accounts");

    let dir = tempdir().expect("failed to create tempdir");
    println!("Created temporary directory: {:?}", dir.path());

    let filename = hdwallet
        .export(&dir, algorithm)
        .expect("failed to export to file");
    let file_path = dir.path().join(filename);
    println!("Exported HDWallet to file: {:?}", file_path);

    let recovered =
        hdwallet::HDWallet::import(file_path, "".to_string()).expect("failed to import from file");
    println!("Imported HDWallet from file");

    let addresses = hdwallet.get_addresses();
    let recovered_addresses = recovered.get_addresses();
    println!("Original addresses: {:?}", addresses);
    println!("Recovered addresses: {:?}", recovered_addresses);

    assert_eq!(addresses, recovered_addresses);
    println!("Addresses match");
}
