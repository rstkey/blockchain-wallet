extern crate crypto_wallet;
use crypto_wallet::hdwallet;

fn main() {
    let mnemonic = "lend pole exclude donkey range tank gather space dress topic fantasy siege";
    let password = "";
    let mut hdwallet =
        hdwallet::HDWallet::new_from_mnemonic_phrase(&mnemonic, Some(password.to_string()))
            .expect("failed to create HDWallet");

    let addresses = hdwallet.add_accounts(5).expect("failed to add accounts");
    println!("Addresses: {:?}\n", addresses);

    let wallet = hdwallet
        .get_wallet(&addresses[0])
        .expect("failed to get wallet");

    let message = "Hello, world!";
    let signature = wallet.sign_message(message.as_bytes()).unwrap();
    println!("Signature: {:?}", signature);
}
