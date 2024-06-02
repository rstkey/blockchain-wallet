extern crate crypto_wallet;
use crypto_wallet::hdwallet;

fn main() {
    let mnemonic = "lend pole exclude donkey range tank gather space dress topic fantasy siege";
    let mut hdwallet = hdwallet::HDWallet::new_from_mnemonic_phrase(&mnemonic, None)
        .expect("failed to create HDWallet");
    println!("Created HDWallet from mnemonic phrase: {:?}", mnemonic);

    println!("\nAdding 5 accounts...");
    let addresses = hdwallet.add_accounts(5).expect("failed to add accounts");
    for (index, address) in addresses.iter().enumerate() {
        println!("Address {}: {}", index + 1, address);
    }

    println!("\nGetting wallet for the first address...");
    let wallet = hdwallet
        .get_wallet(&addresses[0])
        .expect("failed to get wallet");

    println!("\nWallet created successfully! The following are the wallet details:");
    println!("Public key: {:?}", wallet.public_key_hex());
    println!("Ethereum address: {:?}", wallet.address());

    println!("\nSigning a message...");
    let message = "Hello, world!";
    println!("Message: {}", message);
    let signature = wallet.sign_message(message.as_bytes()).unwrap();
    println!("Signature: {:?}", signature);
}
