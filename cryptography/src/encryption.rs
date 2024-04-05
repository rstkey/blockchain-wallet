use aes::cipher::{KeyIvInit, StreamCipher};
type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

pub trait SymmetricCipher {
    fn new() -> Self;
    fn encrypt(&self, key: [u8; 16], plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: [u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
}

pub struct AesCtr {
    iv: [u8; 16],
}

impl SymmetricCipher for AesCtr {
    fn new() -> Self {
        let mut iv = [0u8; 16];
        utils::get_random_bytes(&mut iv).unwrap();

        Self { iv }
    }

    fn encrypt(&self, key: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
        apply_aes_ctr(key, plaintext, self.iv)
    }

    fn decrypt(&self, key: [u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        Ok(apply_aes_ctr(key, plaintext, self.iv))
    }
}

// aes-ctr encryption
fn apply_aes_ctr(key: [u8; 16], plaintext: &[u8], iv: [u8; 16]) -> Vec<u8> {
    let mut buf = plaintext.to_vec();
    let mut cipher = Aes128Ctr64LE::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42; 16];
        let iv = [0x24; 16];
        let plaintext: &[u8] = b"Hello, world!";

        let encryptor = AesCtr { iv };

        // Encrypt the plaintext
        let ciphertext = encryptor.encrypt(key, plaintext);

        // Decrypt the ciphertext
        let decrypted = encryptor.decrypt(key, &ciphertext).unwrap();

        // The decrypted text should be the same as the original plaintext
        assert_eq!(plaintext, &decrypted[..]);
    }
}
