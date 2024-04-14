use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm};
use anyhow::{anyhow, Result};
use base64::{prelude::BASE64_STANDARD as base64, Engine};
use digest::{Key, KeyInit};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fs::OpenOptions, io::Write, path::Path};
use uuid::Uuid;

const DEFAULT_CIPHER: &str = "aes-128-gcm";
const DEFAULT_KEY_SIZE: usize = 32;
const DEFAULT_IV_SIZE: usize = 12;
const DEFAULT_SALT_SIZE: usize = 32;
const DEFAULT_ITERATIONS: u32 = 900_000;

#[derive(Serialize, Deserialize)]
struct EncryptionResult {
    data: String,
    iv: String,
    salt: String,
    key_metadata: KeyDerivationOptions,
}

#[derive(Serialize, Deserialize)]
struct KeyDerivationOptions {
    algorithm: String,
    iterations: u32,
}

pub fn encrypt<P, R, S, T>(dir: P, rng: &mut R, data: T, password: S) -> Result<String>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
    T: Serialize,
{
    let salt = generate_salt(rng, DEFAULT_SALT_SIZE);
    let key = derive_key(password.as_ref(), &salt, DEFAULT_ITERATIONS)?;

    let plaintext = serde_json::to_vec(&data)?;
    let (ciphertext, nonce) = encrypt_data(&key, &plaintext, rng)?;

    let result = EncryptionResult {
        data: base64.encode(&ciphertext),
        iv: base64.encode(&nonce),
        salt: base64.encode(&salt),
        key_metadata: KeyDerivationOptions {
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

fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
    let mut key = vec![0u8; DEFAULT_KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password, salt, iterations, key.as_mut_slice())?;
    Ok(key)
}

fn encrypt_data<R: Rng + CryptoRng>(
    key: &[u8],
    plaintext: &[u8],
    rng: R,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(rng);

    let encrypted_data = cipher.encrypt(&nonce, plaintext).unwrap();

    Ok((encrypted_data, nonce.to_vec()))
}

pub fn decrypt_data(key: &[u8], encrypted_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| anyhow!("Decryption failed"))?;

    Ok(decrypted_data)
}

fn generate_salt<R>(rng: &mut R, size: usize) -> Vec<u8>
where
    R: Rng + CryptoRng,
{
    let mut salt = vec![0u8; size];
    rng.fill_bytes(&mut salt);
    salt
}
