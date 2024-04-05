use anyhow::Result;
use ethaddr::Address;
use sha2::Sha256;
use std::fmt::{self, Debug, Formatter};
use utils;

// secp256k1 elliptic curve library with support for ECDSA signing/verification/public-key recovery
use k256::{
    ecdsa::{hazmat::SignPrimitive, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint as _,
    PublicKey, SecretKey,
};

mod signature;
use signature::Signature;

/// Represents an Ethereum private key.
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Creates a private key from a secret.
    pub fn from_secret(secret: impl AsRef<[u8]>) -> Result<Self> {
        let key = SecretKey::from_slice(secret.as_ref())?;
        Ok(PrivateKey(key))
    }

    /// Returns the public key for the private key.
    pub fn public(&self) -> PublicKey {
        self.0.public_key()
    }

    /// Returns an uncompressed encoded bytes for the public key.
    pub fn public_encode_uncompressed(&self) -> [u8; 65] {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("unexpected uncompressed private key length")
    }

    /// Returns the public address for the private key.
    pub fn address(&self) -> Address {
        let encoded = self.public_encode_uncompressed();

        // Ethereum address is the last 20 bytes of the keccak hash of
        // the concatenated elliptic curve coordinates of the public key. Note
        // that an encoded uncompressed public key is serialized into 65 bytes
        // where the first byte is a SEC1 tag that is always 0x04 (representing
        // an uncompressed point) and the subsequent bytes are the coordinates
        // we want. So discard the first byte for the address calculation.
        debug_assert_eq!(encoded[0], 0x04);
        let hash = utils::keccak256(&encoded[1..]);

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
}

impl Debug for PrivateKey {
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
        let key = PrivateKey::from_secret(PRIVATE_KEY).unwrap();
        println!("{:?}", key);
        assert_eq!(
            *key.address(),
            hex!("90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"),
        );
    }

    #[test]
    fn deterministic_signature() {
        let key = PrivateKey::from_secret(PRIVATE_KEY).unwrap();
        let message = utils::keccak256(b"\x19Ethereum Signed Message:\n12Hello World!");
        let expected_result = Signature::from_parts(
            hex!("408790f153cbfa2722fc708a57d97a43b24429724cf060df7c915d468c43bd84"),
            hex!("61c96aac95ce37d7a31087b6634f4a3ea439a9f704b5c818584fa2a32fa83859"),
            1,
        );

        assert_eq!(key.sign(message).unwrap(), expected_result);
    }
}
