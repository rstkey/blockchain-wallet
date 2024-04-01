mod scrypt;
pub use scrypt::{derive, verify, ScryptKdfParams};

pub enum Kdf {
    Scrypt(ScryptKdfParams),
}

impl Kdf {
    pub fn new_scrypt() -> Self {
        Kdf::Scrypt(ScryptKdfParams::default())
    }
}

impl Kdf {
    pub fn derive_key(&self, password: &str) -> Result<String, anyhow::Error> {
        match self {
            Kdf::Scrypt(params) => derive(password, params),
        }
    }

    pub fn verify_password(
        &self,
        password: &str,
        password_hash: &str,
    ) -> Result<(), anyhow::Error> {
        match self {
            Kdf::Scrypt(_) => verify(password, password_hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "randompassword";

    #[test]
    fn test_derive_verify_password() {
        // Create a new Kdf::Scrypt
        let kdf = Kdf::new_scrypt();

        // Derive a key from the password
        let derived_key = kdf.derive_key(PASSWORD);

        // Verify the password against the derived key
        let result = kdf.verify_password(PASSWORD, derived_key.unwrap().as_str());

        // The password should be verified successfully
        assert!(result.is_ok());
    }
}
