use std::error::Error;
use std::fmt;

use crate::account::PrivateKey;
use crate::bip39::mnemonic::{Mnemonic, Seed};
use crate::hdk::{self, Path};
use ethers::signers::{LocalWallet, Signer};

const DEFAULT_HD_PATH: &str = "m/44'/60'/0'/0";

pub struct HDKeyring {
    wallets: Vec<PrivateKey>,
    mnemonic: Option<Mnemonic>,
    root: Option<PrivateKey>,
    hd_path: &'static str,
}

impl HDKeyring {
    pub fn new() -> Self {
        HDKeyring {
            wallets: Vec::new(),
            mnemonic: None,
            root: None,
            hd_path: DEFAULT_HD_PATH,
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
