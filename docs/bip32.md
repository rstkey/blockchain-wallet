# BIP32

Modul bip32 - skema hierarkis deterministik untuk key derivation (BIP-32) menggunakan beberapa algoritme kriptografi, antara lain:

1. **HMAC (Hash-based Message Authentication Code)**: HMAC menggunakan fungsi hash **SHA-512** untuk melakukan komputasi kunci anak (child key) dari kunci induk (master key) dan kode rantai (chain code). Ini dilakukan pada fungsi derive_slice(), saat melakukan iterasi untuk setiap komponen pada path derivasi.
2. **Kurva Eliptik K256**: Modul ini menggunakan library k256 untuk operasi pada kunci rahasia (secret key) dan kunci publik (public key) yang direpresentasikan dalam bentuk kurva eliptik. Ini digunakan saat melakukan komputasi kunci anak.

Dari analisis kode, dapat disimpulkan bahwa modul hdk.rs menggunakan HMAC dengan fungsi hash SHA-512 untuk komputasi kunci anak, serta operasi pada kurva eliptik K256 untuk manipulasi kunci rahasia dan publik selama proses derivasi.

### HMAC

HMAC (Hash-based Message Authentication Code) adalah jenis kode otentikasi pesan (MAC) tertentu yang melibatkan fungsi hash kriptografi dan kunci kriptografi rahasia. Kode ini digunakan untuk memverifikasi integritas data dan keaslian pesan secara bersamaan.

HMAC-SHA512 digunakan untuk derivasi kunci dalam fungsi derive_slice:

```rust
let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")?;
hmac.update(seed.as_ref());
hmac.finalize().into_bytes()
```

### Kurva Eliptik secp256k1

kode ini juga menggunakan kurva elips secp256k1 untuk menghasilkan kunci publik dari kunci privat. Hal ini dilakukan dengan panggilan SecretKey::from_slice(secret)? yang membuat kunci privat dari sebuah potongan, dan panggilan secret.public_key().to_encoded_point(true).as_bytes(), yang menghasilkan kunci publik yang sesuai. Kurva elips secp256k1 banyak digunakan dalam mata uang digital, termasuk Bitcoin dan Ethereum.
