extern crate crypto_wallet;
use crypto_wallet::{hdwallet, vault};
use tempfile::tempdir;

pub fn main() {
    let mut hdwallet = hdwallet::HDWallet::new_random(None).unwrap();
    hdwallet.add_accounts(5).expect("failed to add accounts");

    // Test encrypt to vault
    let dir = tempdir().expect("failed to create tempdir");
    let filename = hdwallet
        .export(&dir, vault::EncryptionOptions::SpeckCBC)
        .expect("failed to export to file");
    let file_path = dir.path().join(filename);

    let recovered = hdwallet::HDWallet::import(file_path.clone(), "".to_string())
        .expect("failed to import from file");

    // make sure the addresses are the same
    let addresses = hdwallet.get_addresses();
    let recovered_addresses = recovered.get_addresses();
    assert_eq!(addresses, recovered_addresses);
}
