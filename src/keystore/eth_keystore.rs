use ethereum_types::H160 as Address;
use hex::{FromHex, ToHex};
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
/// This struct represents the deserialized form of an encrypted JSON keystore based on the
/// [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
pub struct EthKeystore {
    pub address: Address,
    pub crypto: CryptoJson,
    pub id: Uuid,
    pub version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted JSON keystore.
pub struct CryptoJson {
    pub cipher: String,
    pub cipherparams: CipherparamsJson,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub ciphertext: Vec<u8>,
    pub kdf: KdfType,
    pub kdfparams: KdfparamsType,
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "cipherparams" part of an encrypted JSON keystore.
pub struct CipherparamsJson {
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Types of key derivition functions supported by the Web3 Secret Storage.
pub enum KdfType {
    Pbkdf2,
    Scrypt,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
/// Defines the various parameters used in the supported KDFs.
pub enum KdfparamsType {
    Pbkdf2 {
        c: u32,
        dklen: u8,
        prf: String,
        #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
        salt: Vec<u8>,
    },
    Scrypt {
        dklen: u8,
        n: u32,
        p: u32,
        r: u32,
        #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
        salt: Vec<u8>,
    },
}

// Serialization helpers for converting byte buffers to and from hex strings.

/// Serializes a byte buffer into a hex string.
fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&buffer.encode_hex::<String>())
}

/// Deserializes a hex string into a byte buffer.
fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(string).map_err(|err| Error::custom(err.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_geth_compat_keystore() {
        let data = r#"
        {
            "address": "00000398232e2064f896018496b4b44b3d62751f",
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "4f784cd629a7caf34b488e36fb96aad8a8f943a6ce31c7deab950c5e3a5b1c43",
                "cipherparams": {
                    "iv": "76f07196b3c94f25b8f34d869493f640"
                },
                "kdf": "scrypt",
                "kdfparams": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "1e7be4ce8351dd1710b0885438414b1748a81f1af510eda11e4d1f99c8d43975"
                },
                "mac": "5b5433575a2418c1c813337a88b4099baa2f534e5dabeba86979d538c1f594d8"
            },
            "id": "6c4485f3-3cc0-4081-848e-8bf489f2c262",
            "version": 3
        }"#;
        let keystore: EthKeystore = serde_json::from_str(data).unwrap();
        assert_eq!(
            keystore.address.as_bytes().to_vec(),
            hex::decode("00000398232e2064f896018496b4b44b3d62751f").unwrap()
        );
    }
}
