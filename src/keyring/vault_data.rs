use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    pub mnemonic: String,
    pub num_accounts: usize,
}

impl VaultData {
    pub fn new(mnemonic: String, num_accounts: usize) -> Self {
        Self {
            mnemonic,
            num_accounts,
        }
    }
}
