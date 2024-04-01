pub mod encryption;
pub mod kdf;
pub mod mac;
use kdf::{Kdf, ScryptKdf};
use utils;

use encryption::Cipher;

pub struct EncryptedAccount {
    cipher: Cipher,
    ciphertext: Vec<u8>,
    kdf: kdf::Kdf<ScryptKdf>,
    mac: [u8; 32],
}

impl<'a> EncryptedAccount {
    pub fn encrypt(private_key: &str, password: &str) -> Self {
        let kdf = Kdf::new();
        let cipher = Cipher::new_aes128_ctr(); // 16 bytes key

        let derived_key = kdf.derive(password).unwrap(); // 32 bytes
        let ciphertext = cipher.encrypt(
            derived_key[0..16].as_bytes().to_vec(),
            private_key.as_bytes(),
        ); // encrypt only use the first 16 bytes

        let mac = mac::compute_hmac(derived_key[16..33].as_bytes(), &ciphertext);

        Self {
            cipher,
            ciphertext,
            kdf,
            mac,
        }
    }

    pub fn decrypt(&self, password: &str) -> Result<String, anyhow::Error> {
        let derived_key = self.kdf.derive(password).unwrap();

        // Compute the MAC over the ciphertext and the second half of the derived key
        let mac_check = mac::compute_hmac(&derived_key[16..33].as_bytes(), &self.ciphertext);

        // Verify the MAC
        if mac_check != self.mac {
            return Err(anyhow::anyhow!("MAC verification failed"));
        }

        let decrypted = self
            .cipher
            .decrypt(derived_key[0..16].as_bytes().to_vec(), &self.ciphertext)
            .expect("Decryption error");

        Ok(String::from_utf8(decrypted)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: &str = "69ab2ad71fbea9dd3a492760f4312f9235933205b82bcb1a73fdc3a71c110c97";
    const PASSWORD: &str = "dimas_tri_mustakim";

    #[test]
    fn test_encrypt_decrypt_account() {
        // Create a new encrypted account
        let account = EncryptedAccount::encrypt(PRIVATE_KEY, PASSWORD);
        println!("Done encrypting account");

        // Decrypt the account
        let decrypted = account.decrypt(PASSWORD);
        println!("{:?}", decrypted);
        assert!(decrypted.is_ok());

        // The decrypted private key should be the same as the original private key
        assert_eq!(PRIVATE_KEY, decrypted.unwrap());
    }
}
