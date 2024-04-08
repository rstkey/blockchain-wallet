use std::error::Error;
use std::fmt;

use crate::bip32::{hdk, path::Path};
use crate::bip39::mnemonic::{Mnemonic, Seed};
use crate::wallet::Wallet;

pub struct HDKeyring {
    wallets: Vec<Wallet>,
    mnemonic: Option<Mnemonic>,
    root: Option<Wallet>,
}

impl HDKeyring {
    pub fn new() -> Self {
        HDKeyring {
            wallets: Vec::new(),
            mnemonic: None,
            root: None,
        }
    }

    pub fn generate_random_mnemonic(&mut self) {
        let mnemonic = Mnemonic::random(12).expect("Failed to generate mnemonic");
        self.init_from_mnemonic(&mnemonic).unwrap();
    }

    // Todo: create a new wallet (need a derivation function)
    pub fn init_from_mnemonic(&mut self, mnemonic: &Mnemonic) -> Result<(), Box<dyn Error>> {
        if self.root.is_some() {
            return Err(Box::new(HdKeyringError::MnemonicAlreadyProvided));
        }

        let seed = mnemonic.to_seed("");
        let root = hdk::derive(seed.as_ref(), &Path::for_index(0))?;

        self.mnemonic = Some(mnemonic.clone());
        self.root = Some(root);

        Ok(())
    }
}

#[derive(Debug)]
enum HdKeyringError {
    MnemonicAlreadyProvided,
    NoMnemonicProvided,
    EmptyOrigin,
    AccountNotFound(String),
}

impl fmt::Display for HdKeyringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HdKeyringError::MnemonicAlreadyProvided => {
                write!(f, "Secret recovery phrase already provided")
            }
            HdKeyringError::NoMnemonicProvided => write!(f, "No secret recovery phrase provided"),
            HdKeyringError::EmptyOrigin => write!(f, "'origin' must be a non-empty string"),
            HdKeyringError::AccountNotFound(address) => {
                write!(f, "Address {} not found in this keyring", address)
            }
        }
    }
}

impl Error for HdKeyringError {}
