use ethaddr::Address;
use std::path::Path;

use crate::bip32::{hdk, path::Path as Bip32path};
use crate::bip39::mnemonic::{Mnemonic, Seed};
use crate::vault;
use crate::wallet::Wallet;
use anyhow::{anyhow, Ok, Result};

pub struct HDWallet {
    wallets: Vec<Wallet>,
    mnemonic: Mnemonic,
    seed: Seed,
    password: Option<String>,
}

impl HDWallet {
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

        Ok(HDWallet {
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

    pub fn export<P: AsRef<Path>>(
        &self,
        path: P,
        algorithm: vault::EncryptionOptions,
    ) -> Result<String> {
        let vault = vault::VaultData::new(self.mnemonic.to_phrase(), self.wallets.len());
        let filename = vault::encrypt_to_file(
            path,
            vault,
            self.password.clone().unwrap_or("".to_string()),
            algorithm,
        )?;
        return Ok(filename);
    }

    pub fn import<P>(path: P, password: String) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let decrypted_data =
            vault::decrypt_file(path, password.clone()).expect("Failed to decrypt");

        let vault: vault::VaultData =
            serde_json::from_slice(&decrypted_data).expect("Failed to parse");

        let mnemonic = Mnemonic::from_phrase(&vault.mnemonic)?;
        let seed = mnemonic.to_seed(password.clone());
        let mut keyring = HDWallet {
            wallets: Vec::new(),
            mnemonic,
            seed,
            password: Some(password.clone()),
        };
        keyring.add_accounts(vault.num_accounts)?;
        Ok(keyring)
    }
}
