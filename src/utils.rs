use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use std::io; // For the fill_bytes method

/// Populates the provided slice with cryptographically strong random bytes.
pub fn get_random_bytes(mut buf: impl AsMut<[u8]>) -> io::Result<()> {
    let mut rng = StdRng::from_entropy(); // Get an RNG seeded with OS entropy
    rng.fill_bytes(buf.as_mut());

    // assert that buf is not > 256 bytes
    assert!(buf.as_mut().len() <= 256);

    Ok(())
}

pub mod hash {
    use sha2::{Digest as _, Sha256};
    use sha3::Keccak256;

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
}

pub mod serialization {
    //! Module with JSON serialization helpers.

    use serde_json::{Map, Value};

    /// A JSON object.
    pub type JsonObject = Map<String, Value>;

    /// Permisive deserialization for optional 256-bit integer types.
    pub mod numopt {
        use ethnum::serde::permissive::Permissive;
        use serde::{Deserialize, Deserializer};

        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Helper<T>(#[serde(with = "ethnum::serde::permissive")] T)
        where
            T: Permissive;

        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            T: Permissive,
            D: Deserializer<'de>,
        {
            let option = Option::deserialize(deserializer)?;
            Ok(option.map(|Helper(v)| v))
        }
    }

    /// Dynamic byte array serialization methods.
    pub mod bytes {
        use serde::{
            de::{self, Deserializer},
            Deserialize as _,
        };
        use std::borrow::Cow;

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = Cow::<str>::deserialize(deserializer)?;
            let s = s
                .strip_prefix("0x")
                .ok_or_else(|| de::Error::custom("storage slot missing '0x' prefix"))?;
            hex::decode(s).map_err(de::Error::custom)
        }
    }

    /// Fixed byte array serialization methods.
    pub mod bytearray {
        use serde::{
            de::{self, Deserializer},
            Deserialize as _,
        };
        use std::borrow::Cow;

        pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
        where
            D: Deserializer<'de>,
        {
            let mut value = [0_u8; N];
            let s = Cow::<str>::deserialize(deserializer)?;
            let s = s
                .strip_prefix("0x")
                .ok_or_else(|| de::Error::custom("storage slot missing '0x' prefix"))?;
            hex::decode_to_slice(s, &mut value).map_err(de::Error::custom)?;
            Ok(value)
        }
    }
}
