use crate::utils;
use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm};
use anyhow::{anyhow, Result};
use digest::{Key, KeyInit};

// Encrypts the given plaintext using the provided key.
pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(utils::get_rng());

    let encrypted_data = cipher.encrypt(&nonce, plaintext).unwrap();

    Ok((encrypted_data, nonce.to_vec()))
}

// Decrypts the given encrypted data using the provided key and nonce.
pub fn decrypt_aes_gcm(key: &[u8], encrypted_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| anyhow!("Decryption failed"))
        .expect("Decryption failed");

    Ok(decrypted_data)
}

pub fn encrypt_speck_cbc(_key: &[u8], _plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    unimplemented!()
}

pub fn decrypt_speck_cbc(_key: &[u8], _encrypted_data: &[u8], _iv: &[u8]) -> Result<Vec<u8>> {
    unimplemented!()
}
