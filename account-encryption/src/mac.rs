use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn compute_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);

    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    code_bytes.into()
}

pub fn verify_mac(key: &[u8], message: &[u8], mac: &[u8]) -> bool {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(message);
    match hasher.verify(mac.into()) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const KEY: &[u8; 24] = b"my secret and secure key";
    const MESSAGE: &[u8; 13] = b"input message";
    const EXPECTED: [u8; 32] =
        hex!("97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9");

    #[test]
    fn test_compute_hmac() {
        let computed_hmac = compute_hmac(KEY, MESSAGE);
        assert_eq!(computed_hmac, EXPECTED);
    }

    #[test]
    fn test_verify_mac_valid() {
        let is_valid = verify_mac(KEY, MESSAGE, &EXPECTED);
        assert!(is_valid);
    }

    #[test]
    fn test_verify_mac_invalid() {
        let invalid_mac = hex!("97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd8");

        let is_valid = verify_mac(KEY, MESSAGE, &invalid_mac);
        assert!(!is_valid);
    }
}
