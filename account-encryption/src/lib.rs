pub mod encryption;
pub mod kdf;
pub mod mac;
mod utils;

use encryption::Cipher;
use kdf::Kdf;

pub struct EncryptedAccount {
    cipher: Cipher,
    ciphertext: Vec<u8>,
    kdf: Kdf,
    mac: String,
}

impl EncryptedAccount {
    pub fn new(private_key: &str, password: &str) -> Self {
        let kdf = Kdf::new_scrypt();
        let cipher = Cipher::new_aes128_ctr();

        let derived_key = kdf.derive_key(password).unwrap();
        let derived_key_clone = derived_key.clone(); // Clone the derived_key
        let ciphertext = cipher.encrypt(derived_key.into_bytes(), private_key.as_bytes());

        let mac = String::from_utf8_lossy(
            mac::compute_hmac(derived_key_clone.into_bytes().as_ref(), &ciphertext).as_ref(),
        )
        .to_string();

        Self {
            cipher,
            ciphertext,
            kdf,
            mac,
        }
    }

    pub fn decrypt(&self, password: &str) -> Result<String, anyhow::Error> {
        self.kdf
            .verify_password(password, &self.mac)
            .expect("Invalid password");

        let derived_key = self.kdf.derive_key(password).unwrap();
        let decrypted = self
            .cipher
            .decrypt(derived_key.into_bytes(), &self.ciphertext)
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
        let account = EncryptedAccount::new(PRIVATE_KEY, PASSWORD);

        // Decrypt the account
        let decrypted = account.decrypt(PASSWORD);
        println!("{:?}", decrypted);
        assert!(decrypted.is_ok());

        // The decrypted private key should be the same as the original private key
        assert_eq!(PRIVATE_KEY, decrypted.unwrap());
    }
}
