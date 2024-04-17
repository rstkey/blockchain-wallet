//! hierachical deterministic key derivation scheme.

pub use super::path::{Component, Path};
use crate::wallet::Wallet;
use anyhow::{Context as _, Result};
use hmac::{Hmac, Mac as _};
use k256::{elliptic_curve::sec1::ToEncodedPoint as _, SecretKey};
use sha2::Sha512;

/// A value indicating a path component is hardened.
const HARDENED: u32 = 0x8000_0000;

/// Creates a new extended private key from a seed.
pub fn derive(seed: impl AsRef<[u8]>, path: &Path) -> Result<Wallet> {
    derive_slice(seed.as_ref(), path)
}

fn derive_slice(seed: &[u8], path: &Path) -> Result<Wallet> {
    // creating an HMAC-SHA512 hash of the seed.
    let mut extended_key = {
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")?;
        hmac.update(seed.as_ref());
        hmac.finalize().into_bytes()
    };

    // Iterate over each component of the derivation path
    // ie. m/44'/60'/0'/0/0
    for (i, component) in path.components().enumerate() {
        // split the extended key into secret and chain code
        let (secret, chain_code) = extended_key.split_at(32);
        let secret = SecretKey::from_slice(secret)?;

        // Create a new HMAC-SHA512 hash using the chain code
        let mut hmac: Hmac<Sha512> = Hmac::<Sha512>::new_from_slice(chain_code)?;
        let value = match component {
            // If the component is hardened, update the HMAC with the secret key
            Component::Hardened(value) => {
                hmac.update(&[0]);
                hmac.update(&secret.to_bytes());
                value | HARDENED
            }
            // If the component is normal, update the HMAC with the public key derived from the secret key
            Component::Normal(value) => {
                hmac.update(secret.public_key().to_encoded_point(true).as_bytes());
                value
            }
        };
        hmac.update(&value.to_be_bytes());

        // Finalize the HMAC to get the child key
        let mut child_key = hmac.finalize().into_bytes();

        // Create a new secret key from the first 32 bytes of the child key
        let child_secret = SecretKey::from_slice(&child_key[..32])
            .with_context(|| format!("path '{path}' component #{i} yields invalid child key"))?;

        // Create a new secret key by adding the current secret key to the child secret key
        let next_secret =
            SecretKey::new(*child_secret.as_scalar_primitive() + *secret.as_scalar_primitive());

        // Replace the first 32 bytes of the child key with the bytes of the new secret key
        child_key[..32].copy_from_slice(&next_secret.to_bytes());

        // Set the extended key to the child key
        extended_key = child_key
    }

    // create a new wallet from the first 32 bytes of the extended key
    Wallet::from_secret(&extended_key[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::mnemonic::Mnemonic;
    use ethaddr::address;

    const MNEMONIC: &str =
        "myth like bonus scare over problem client lizard pioneer submit female collect";

    #[test]
    fn ganache_deterministic_mnemonic() {
        let mnemonic = MNEMONIC.parse::<Mnemonic>().unwrap();
        let path = "m/44'/60'/0'/0/0".parse::<Path>().unwrap();

        let account = derive(mnemonic.to_seed(""), &path).unwrap();
        assert_eq!(
            account.address(),
            address!("0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"),
        );
    }
}
