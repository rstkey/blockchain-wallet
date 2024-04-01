use crate::utils;

mod myaes;

pub enum Cipher {
    Aes128Ctr(Aes128CipherParams),
}

impl Cipher {
    pub fn new_aes128_ctr() -> Self {
        let mut iv = [0u8; 16];
        utils::get_random_bytes(&mut iv).unwrap();

        Cipher::Aes128Ctr(Aes128CipherParams { iv })
    }
}

pub struct Aes128CipherParams {
    iv: [u8; 16],
}

/// encrypt/decrypt the plaintext using the key and the cipher's parameters
/// the key should be 16 bytes long derived by kdf
impl Cipher {
    pub fn encrypt(&self, key: Vec<u8>, plaintext: &[u8]) -> Vec<u8> {
        match self {
            Cipher::Aes128Ctr(params) => {
                let byte_key = key.as_slice()[..16].try_into().unwrap();
                myaes::encrypt(byte_key, plaintext, params.iv.clone())
            }
        }
    }

    pub fn decrypt(&self, key: Vec<u8>, plaintext: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            Cipher::Aes128Ctr(params) => {
                let byte_key = key.as_slice()[..16].try_into().unwrap();
                myaes::decrypt(byte_key, plaintext, params.iv.clone())
            }
        }
    }
}
