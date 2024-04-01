// aes-ctr encryption
use aes::cipher::{KeyIvInit, StreamCipher};
type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

pub fn encrypt(key: [u8; 16], plaintext: &[u8], iv: [u8; 16]) -> Vec<u8> {
    apply_aes_ctr(key, plaintext, iv)
}

pub fn decrypt(key: [u8; 16], plaintext: &[u8], iv: [u8; 16]) -> Result<Vec<u8>, anyhow::Error> {
    Ok(apply_aes_ctr(key, plaintext, iv))
}

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

        // Encrypt the plaintext
        let ciphertext = encrypt(key, plaintext, iv);

        // Decrypt the ciphertext
        let decrypted = decrypt(key, &ciphertext, iv).unwrap();

        // The decrypted text should be the same as the original plaintext
        assert_eq!(plaintext, &decrypted[..]);
    }
}
