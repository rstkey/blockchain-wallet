use ethaddr::Address;
use std::path::Path;

use crate::bip32::{hdk, path::Path as Bip32path};
use crate::bip39::mnemonic::{Mnemonic, Seed};
use crate::wallet::Wallet;
use anyhow::{anyhow, Ok, Result};

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

    pub fn new_from_mnemonic_phrase(phrase: &str, password: Option<String>) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(phrase)?;
        Self::new_from_mnemonic(&mnemonic, password)
    }

    fn new_from_mnemonic(mnemonic: &Mnemonic, password: Option<String>) -> Result<Self> {
        let password = password.unwrap_or_else(|| "".to_string());
        let seed = mnemonic.to_seed(&password);

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
            .ok_or_else(|| anyhow!("Wallet not found"))
    }

    pub fn export_to_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let vault = vault_data::VaultData::new(self.mnemonic.to_phrase(), self.wallets.len());
        let filename =
            keyring_store::encrypt(path, vault, self.password.clone().unwrap_or("".to_string()))?;
        return Ok(filename);
    }

    pub fn import_from_file<P>(path: P, password: String) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let decrypted_data = keyring_store::decrypt(path, password.clone())?;
        let vault: vault_data::VaultData = serde_json::from_slice(&decrypted_data)?;

        let mnemonic = Mnemonic::from_phrase(&vault.mnemonic)?;
        let seed = mnemonic.to_seed(password.clone());
        let mut keyring = Keyring {
            wallets: Vec::new(),
            mnemonic,
            seed,
            password: Some(password.clone()),
        };
        keyring.add_accounts(vault.num_accounts)?;
        Ok(keyring)
    }
}
