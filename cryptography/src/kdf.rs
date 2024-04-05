pub mod scrypt;

pub trait DerivationFunction {
    fn new() -> Self;
    fn derive(&self, password: &str) -> Result<String, anyhow::Error>;
    fn verify(&self, password: &str, password_hash: &str) -> Result<(), anyhow::Error>;
}
