use anyhow::Result;
use ethereum_types::H160 as Address;
use k256::SecretKey;
use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use sha3::{Digest, Keccak256};
use std::io; // For the fill_bytes method

pub mod hash;
pub mod serialization;

/// Populates the provided slice with cryptographically strong random bytes.
pub fn get_random_bytes(mut buf: impl AsMut<[u8]>) -> io::Result<()> {
    let mut rng = StdRng::from_entropy(); // Get an RNG seeded with OS entropy
    rng.fill_bytes(buf.as_mut());

    // assert that buf is not > 256 bytes
    assert!(buf.as_mut().len() <= 256);

    Ok(())
}

/// Converts a K256 SigningKey to an Ethereum Address
pub fn address_from_pk<S>(pk: S) -> Result<Address>
where
    S: AsRef<[u8]>,
{
    let secret_key = SecretKey::from_slice(pk.as_ref())?;
    let public_key: [u8; 65] = secret_key
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()?;
    debug_assert_eq!(public_key[0], 0x04);
    let hash = hash::keccak256(&public_key[1..]);
    Ok(Address::from_slice(&hash[12..]))
}
