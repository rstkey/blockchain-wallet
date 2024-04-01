use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Params, Scrypt,
};

#[allow(dead_code)]
pub struct ScryptKdfParams {
    dklen: usize,
    n: u8,
    p: u32,
    r: u32,
    salt: SaltString,
}

impl Default for ScryptKdfParams {
    fn default() -> Self {
        Self {
            dklen: Params::RECOMMENDED_LEN, // TODO: check this. i use recommended because it's 32. the trust wallet use that. but need to check because aes128 use 16.
            n: Params::RECOMMENDED_LOG_N,
            p: Params::RECOMMENDED_P,
            r: Params::RECOMMENDED_R,
            salt: SaltString::generate(&mut OsRng),
        }
    }
}

pub fn derive(password: &str, params: &ScryptKdfParams) -> Result<String, anyhow::Error> {
    // TODO: use the full params to hash the password

    let password_hash = Scrypt.hash_password(password.as_bytes(), &params.salt)?;
    Ok(password_hash.to_string())
}

pub fn verify(password: &str, password_hash: &str) -> Result<(), anyhow::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;
    Scrypt.verify_password(password.as_bytes(), &parsed_hash)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_and_verify_password() {
        let password = "my_password";
        let params = ScryptKdfParams::default();

        // Derive password hash
        let password_hash = derive(password, &params).unwrap();

        // Verify password
        verify(password, &password_hash).unwrap();
    }

    #[test]
    fn test_derive_with_incorrect_password() {
        let password = "wrong_password";
        let params = ScryptKdfParams::default();

        // Derive password hash
        let password_hash = derive("my_password", &params).unwrap();

        // Verify incorrect password
        assert!(verify(password, &password_hash).is_err());
    }
}
