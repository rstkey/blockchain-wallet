use crate::utils;
use anyhow::Result;
use base64::{prelude::BASE64_STANDARD as base64, Engine};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Write, path::Path};
use uuid::Uuid;

const DEFAULT_KEY_SIZE: usize = 32; // 256 bits
const DEFAULT_SALT_SIZE: usize = 32;
const DEFAULT_ITERATIONS: u32 = 10_000;
mod algorithm;

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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptionResult {
    data: String,
    encryption_options: EncryptionMetadata,
    key_metadata: KeyDerivationMetadata,
}

#[derive(Serialize, Deserialize)]
struct KeyDerivationMetadata {
    salt: String,
    algorithm: String,
    iterations: u32,
}

#[derive(Serialize, Deserialize)]
struct EncryptionMetadata {
    iv_or_nonce: Vec<u8>,
    algorithm: EncryptionOptions,
}

#[derive(Serialize, Deserialize)]
pub enum EncryptionOptions {
    Aes256Gcm,
    SpeckCBC,
}

// Encrypts the given data and writes it to a file.
pub fn encrypt_to_file<P, S, T>(
    dir: P,
    data: T,
    password: S,
    algorithm: EncryptionOptions,
) -> Result<String>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
    T: Serialize,
{
    let salt = utils::generate_salt(DEFAULT_SALT_SIZE);
    let key = utils::pbkdf2_hash(
        password.as_ref(),
        &salt,
        DEFAULT_ITERATIONS,
        DEFAULT_KEY_SIZE,
    )?;

    let plaintext = serde_json::to_vec(&data)?;
    let (ciphertext, nonce) = match algorithm {
        EncryptionOptions::Aes256Gcm => self::algorithm::encrypt_aes_gcm(&key, &plaintext)?,
        EncryptionOptions::SpeckCBC => self::algorithm::encrypt_speck_cbc(&key, &plaintext)?,
    };

    let result = EncryptionResult {
        data: base64.encode(&ciphertext),
        encryption_options: EncryptionMetadata {
            iv_or_nonce: nonce,
            algorithm: algorithm,
        },
        key_metadata: KeyDerivationMetadata {
            salt: base64.encode(&salt),
            algorithm: "PBKDF2".to_string(),
            iterations: DEFAULT_ITERATIONS,
        },
    };

    let filename = format!("{}.json", Uuid::new_v4());
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(dir.as_ref().join(filename.clone()))?;
    file.write_all(serde_json::to_vec(&result)?.as_slice())?;

    Ok(filename)
}

// Decrypts the data from the given file.
pub fn decrypt_file<P, S>(path: P, password: S) -> Result<Vec<u8>>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    // Open the file and read its contents into a string
    let contents = std::fs::read_to_string(&path)?;

    // Deserialize the contents into an EncryptionResult
    let result: EncryptionResult = serde_json::from_str(&contents)?;

    // Decode the salt and derive the key
    let salt = base64.decode(&result.key_metadata.salt)?;
    let key = utils::pbkdf2_hash(
        password.as_ref(),
        &salt,
        result.key_metadata.iterations,
        DEFAULT_KEY_SIZE,
    )?;

    // Decode the ciphertext and nonce
    let ciphertext = base64.decode(&result.data)?;
    let nonce = result.encryption_options.iv_or_nonce;

    // Decrypt the data
    match result.encryption_options.algorithm {
        EncryptionOptions::Aes256Gcm => self::algorithm::decrypt_aes_gcm(&key, &ciphertext, &nonce),
        EncryptionOptions::SpeckCBC => {
            self::algorithm::decrypt_speck_cbc(&key, &ciphertext, &nonce)
        }
    }
}
