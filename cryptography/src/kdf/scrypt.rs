use super::DerivationFunction;
use scrypt::{
    password_hash::{PasswordHash, PasswordVerifier},
    Params, Scrypt,
};

#[allow(dead_code)]
pub struct ScryptKdfParams {
    dklen: usize,
    n: u8,
    p: u32,
    r: u32,
    salt: [u8; 0],
}

impl<'a> Default for ScryptKdfParams {
    // The default setting following the backup implementation of trust wallet.
    fn default() -> Self {
        Self {
            dklen: 32,
            n: 14,
            p: 4,
            r: 8,
            salt: [0u8; 0],
        }
    }
}

pub struct ScryptKdf(ScryptKdfParams);

impl DerivationFunction for ScryptKdf {
    fn new() -> Self {
        Self(ScryptKdfParams::default())
    }

    fn derive(&self, password: &str) -> Result<String, anyhow::Error> {
        let scrypt_params = Params::new(self.0.n, self.0.r, self.0.p, self.0.dklen)
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;

        let mut dk = vec![0u8; self.0.dklen];
        scrypt::scrypt(password.as_bytes(), &self.0.salt, &scrypt_params, &mut dk)
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;

        Ok(String::from_utf8_lossy(&dk).to_string())
    }

    fn verify(&self, password: &str, password_hash: &str) -> Result<(), anyhow::Error> {
        let parsed_hash = PasswordHash::new(password_hash)?;
        Scrypt.verify_password(password.as_bytes(), &parsed_hash)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_and_verify_password() {
        let password = "my_password";
        let hasher = ScryptKdf::new();

        // Derive password hash
        let password_hash = hasher.derive(password).unwrap();

        // Verify password
        assert!(hasher.verify(password, &password_hash).is_ok());
    }

    #[test]
    fn test_derive_with_incorrect_password() {
        let password = "wrong_password";
        let hasher = ScryptKdf::new();

        // Derive password hash
        let password_hash = hasher.derive("my_password").unwrap();

        // Verify incorrect password
        assert!(hasher.verify(password, &password_hash).is_err());
    }
}
