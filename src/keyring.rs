use ethaddr::Address;
use rand::{CryptoRng, Rng};
use std::error::Error;
use std::fmt;
use std::{fs::File, path::Path};

use crate::bip32::{hdk, path::Path as Bip32path};
use crate::bip39::mnemonic::{self, Mnemonic, Seed};
use crate::wallet::Wallet;
use anyhow::{Ok, Result};
use serde::ser::{Serialize, SerializeStruct, Serializer};

mod keyring_store;
mod vault_data;

pub struct Keyring {
    wallets: Vec<Wallet>,
    mnemonic: Mnemonic,
    seed: Seed,
    password: Option<String>,
}

impl Keyring {
    pub fn new_random(password: Option<String>) -> Result<Self> {
        let mnemonic = Mnemonic::random(12).expect("Failed to generate mnemonic");
        Self::new_from_mnemonic(&mnemonic, password)
    }

    // Todo: create a new wallet (need a derivation function)
    pub fn new_from_mnemonic(mnemonic: &Mnemonic, password: Option<String>) -> Result<Self> {
        let password = password.unwrap_or_else(|| "".to_string());
        let seed = mnemonic.to_seed(&password);
        // let root = hdk::derive(seed.as_ref(), &Path::for_index(0))?;

        Ok(Keyring {
            wallets: Vec::new(),
            mnemonic: mnemonic.clone(),
            seed: seed,
            password: Some(password),
        })
    }

    pub fn add_accounts(&mut self, num_accounts: usize) -> Result<Vec<Address>> {
        let old_len = self.wallets.len();
        let mut addresses = Vec::with_capacity(num_accounts - old_len);

        if old_len > num_accounts {
            return Ok(addresses);
        }

        for i in old_len..num_accounts {
            let path = Bip32path::for_index(i);
            let wallet = hdk::derive(self.seed.as_ref(), &path)?;
            addresses.push(wallet.address());
            self.wallets.push(wallet);
        }

        Ok(addresses)
    }

    pub fn get_addresses(&self) -> Vec<Address> {
        self.wallets.iter().map(|w| w.address()).collect()
    }

    pub fn get_wallet(&self, address: &Address) -> Result<&Wallet> {
        self.wallets
            .iter()
            .find(|w| w.address() == *address)
            .ok_or_else(|| HdKeyringError::AccountNotFound(address.to_string()).into())
    }

    pub fn export_to_file<P, R>(&self, path: P, rng: &mut R) -> Result<String>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng,
    {
        let vault = vault_data::VaultData::new(self.mnemonic.to_phrase(), self.wallets.len());
        todo!() // using keyring_store
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
