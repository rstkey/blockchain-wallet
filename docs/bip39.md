# Bip39

Algoritma kriptografi yang digunakan dalam implementasi BIP-0039 (mnemonic) adalah sebagai berikut:

1. **Generasi Entropy**: Entri acak yang digunakan sebagai benih untuk mnemonic phrase dibangkitkan menggunakan fungsi utils::get_random_bytes(). Fungsi ini dapat menggunakan StdRNG untuk menghasilkan random value menggunakan ChaCha block cipher dengan 12 rounds.
2. **Hash Entri**: Setelah entri acak dihasilkan, dilakukan komputasi hash SHA-256 terhadap entri tersebut. Hash ini disimpan bersama dengan entri acak dalam struktur Mnemonic.
3. **Konversi Mnemonic ke Seed**: Saat mnemonic phrase dimasukkan, fungsi `Mnemonic::from_phrase()` mengambil mnemonic phrase sebagai input, menghasilkan entri acak dan kode checksum dari phrase tersebut, dan kemudian memverifikasi kode checksum. Proses verifikasi kode checksum menggunakan perhitungan hash SHA-256.
4. **Seed PBKDF2**: Untuk menghasilkan benih (seed) 64 byte dari mnemonic phrase, fungsi `Mnemonic::to_seed()` menggunakan algoritma **PBKDF2-HMAC-SHA512**. PBKDF2 adalah algoritma Key Derivation Function (KDF) yang digunakan untuk meningkatkan keamanan benih dari mnemonic phrase.

Dengan demikian, algoritma kriptografi yang digunakan dalam implementasi BIP-0039 (mnemonic) adalah:

- Generasi Entropy: Algoritma Kriptografi Acak (ChaCha block cipher)
- Hash Entri: SHA-256
- Verifikasi Checksum: SHA-256
- Seed Generation: PBKDF2-HMAC-SHA512
