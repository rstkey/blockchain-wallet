mod scrypt;
pub use scrypt::*;

pub trait DerivationFunction {
    fn new() -> Self;
    fn derive(&self, password: &str) -> Result<String, anyhow::Error>;
    fn verify(&self, password: &str, password_hash: &str) -> Result<(), anyhow::Error>;
}

pub struct Kdf<T: DerivationFunction> {
    kdf: T,
}

impl<T: DerivationFunction> Kdf<T> {
    pub fn new() -> Self {
        Self { kdf: T::new() }
    }

    pub fn derive(&self, password: &str) -> Result<String, anyhow::Error> {
        self.kdf.derive(password)
    }

    pub fn verify(&self, password: &str, password_hash: &str) -> Result<(), anyhow::Error> {
        self.kdf.verify(password, password_hash)
    }
}
