use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::io; // For the fill_bytes method

/// Populates the provided slice with cryptographically strong random bytes.
pub fn get_random_bytes(mut buf: impl AsMut<[u8]>) -> io::Result<()> {
    let mut rng = StdRng::from_entropy(); // Get an RNG seeded with OS entropy
    rng.fill_bytes(buf.as_mut());

    // assert that buf is not > 256 bytes
    assert!(buf.as_mut().len() <= 256);

    Ok(())
}

/// Returns the Keccak-256 hash of the specified input.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data.as_ref());
    hasher.finalize().into()
}

/// Returns the SHA256 hash of the specified input.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hasher.finalize().into()
}
