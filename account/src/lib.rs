use anyhow::Result;
use ethaddr::Address;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::{
    ecdsa::{hazmat::SignPrimitive, SigningKey},
    SecretKey,
};
use sha2::Sha256;
use std::fmt::{self, Debug, Formatter};

mod signature;
mod utils;

//////////////////////////////////
/// Public Key
//////////////////////////////////

/// A public key.
pub struct PublicKey(pub k256::PublicKey);

impl PublicKey {
    /// Returns an uncompressed encoded bytes for the public key.
    pub fn encode_uncompressed(&self) -> [u8; 65] {
        self.0
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("unexpected uncompressed private key length")
    }
}

//////////////////////////////////
/// Private Key
//////////////////////////////////

/// A struct representing an Ethereum private key.
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Creates a private key from a secret.
    pub fn from_secret(secret: impl AsRef<[u8]>) -> Result<Self> {
        let key = SecretKey::from_slice(secret.as_ref())?;
        Ok(PrivateKey(key))
    }

    /// Returns the public key for the private key.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// Returns the public address for the private key.
    pub fn address(&self) -> Address {
        let encoded = self.public().encode_uncompressed();

        // NOTE: An ethereum address is the last 20 bytes of the keccak hash of
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

    /// Generate a signature for the specified message.
    pub fn sign(&self, message: [u8; 32]) -> signature::Signature {
        self.try_sign(message).expect("signature operation failed")
    }

    /// Generate a signature for the specified message.
    pub fn try_sign(&self, message: [u8; 32]) -> Result<signature::Signature> {
        let (signature, recovery_id) = SigningKey::from(&self.0)
            .as_nonzero_scalar()
            .try_sign_prehashed_rfc6979::<Sha256>(&message.into(), b"")?;
        Ok(signature::Signature(signature, recovery_id.unwrap()))
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

    pub const DETERMINISTIC_PRIVATE_KEY: [u8; 32] =
        hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");

    #[test]
    fn ganache_determinitic_address() {
        let key = PrivateKey::from_secret(DETERMINISTIC_PRIVATE_KEY).unwrap();
        assert_eq!(
            *key.address(),
            hex!("90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"),
        );
    }

    #[test]
    fn ganache_deterministic_signature() {
        let key = PrivateKey::from_secret(DETERMINISTIC_PRIVATE_KEY).unwrap();
        let message = utils::keccak256(b"\x19Ethereum Signed Message:\n12Hello World!");
        assert_eq!(
            key.sign(message),
            signature::Signature::from_parts(
                hex!("408790f153cbfa2722fc708a57d97a43b24429724cf060df7c915d468c43bd84"),
                hex!("61c96aac95ce37d7a31087b6634f4a3ea439a9f704b5c818584fa2a32fa83859"),
                1,
            ),
        );
    }
}
