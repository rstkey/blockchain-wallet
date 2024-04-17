use anyhow::Result;
use ethaddr::Address;
use sha2::Sha256;
use std::fmt::{self, Debug, Formatter};

// secp256k1 elliptic curve library with support for ECDSA signing/verification/public-key recovery
use k256::{
    ecdsa::{hazmat::SignPrimitive, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint as _,
    PublicKey, SecretKey,
};

use std::path::Path;

use crate::utils;
mod signature;
pub use signature::Signature;

/// Represents an Ethereum private key.
pub struct Wallet(SecretKey);

impl Wallet {
    /// Creates a new private key from a secret.
    pub fn from_secret(secret: impl AsRef<[u8]>) -> Result<Self> {
        let key = SecretKey::from_slice(secret.as_ref())?;
        Ok(Wallet(key))
    }

    /// Returns the public key for the private key.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// Returns an uncompressed encoded bytes for the public key.
    pub fn public_key_encoded_uncompressed(&self) -> [u8; 65] {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("unexpected uncompressed private key length")
    }

    /// String representation of the public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_encoded_uncompressed())
    }

    /// Returns the public address for the private key.
    pub fn address(&self) -> Address {
        let encoded: [u8; 65] = self.public_key_encoded_uncompressed();

        // Ethereum address is the last 20 bytes of the keccak hash of
        // the concatenated elliptic curve coordinates of the public key. Note
        // that an encoded uncompressed public key is serialized into 65 bytes
        // where the first byte is a SEC1 tag that is always 0x04 (representing
        // an uncompressed point) and the subsequent bytes are the coordinates
        // we want. So discard the first byte for the address calculation.
        debug_assert_eq!(encoded[0], 0x04);
        let hash = utils::hash::keccak256(&encoded[1..]);

        Address::from_slice(&hash[12..])
    }

    /// Returns the private key's 32 byte secret.
    pub fn secret(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    /// Generate a signature for the specified message. Message is a 32-byte hash.
    pub fn sign(&self, message: [u8; 32]) -> Result<Signature> {
        let (signature, recovery_id) = SigningKey::from(&self.0)
            .as_nonzero_scalar()
            .try_sign_prehashed_rfc6979::<Sha256>(&message.into(), b"")?;
        Ok(Signature(signature, recovery_id.unwrap()))
    }

    /// Sign a message and return the signature.
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let message = utils::hash::keccak256(message);
        self.sign(message)
    }

    /// Write the json keystore file to the specified directory.
    pub fn encrypt_keystore<P, S>(&self, keypath: P, password: S) -> Result<String>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
    {
        let private_key = self.secret();
        let uuid = crate::keystore::encrypt_key(keypath, private_key, password)?;
        Ok(uuid)
    }

    pub fn decrypt_keystore<P, S>(keypath: P, password: S) -> Result<Self>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
    {
        let pk = crate::keystore::decrypt_key(keypath, password)?;
        Ok(Wallet::from_secret(pk)?)
    }
}

impl Debug for Wallet {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("PrivateKey").field(&self.address()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    pub const PRIVATE_KEY: [u8; 32] =
        hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");

    #[test]
    fn deterministic_address() {
        let key = Wallet::from_secret(PRIVATE_KEY).unwrap();
        println!("{:?}", key);
        assert_eq!(
            *key.address(),
            hex!("90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"),
        );
    }

    #[test]
    fn deterministic_signature() {
        let key = Wallet::from_secret(PRIVATE_KEY).unwrap();
        let message = utils::hash::keccak256(b"\x19Ethereum Signed Message:\n12Hello World!");
        let expected_result = Signature::from_parts(
            hex!("408790f153cbfa2722fc708a57d97a43b24429724cf060df7c915d468c43bd84"),
            hex!("61c96aac95ce37d7a31087b6634f4a3ea439a9f704b5c818584fa2a32fa83859"),
            1,
        );

        assert_eq!(key.sign(message).unwrap(), expected_result);
    }
}
