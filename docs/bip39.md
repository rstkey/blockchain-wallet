# Bip39

Modul ini berfungsi untuk menyediakan mekanisme backup "seed"/"entropy" yang digunakan untuk generasi public/private key menggunakan mnemonic phrase. Algoritma kriptografi yang digunakan dalam implementasi BIP-0039 (mnemonic) adalah sebagai berikut:

1. **Generasi Entropy**: Entri acak yang digunakan sebagai seed untuk membuat mnemonic dan membuat turunan secret key. Fungsi ini menggunakan StdRNG untuk menghasilkan random value menggunakan ChaCha block cipher dengan 12 rounds.
2. **Hash Entri**: Setelah entri acak dihasilkan, dilakukan komputasi hash SHA-256 terhadap entri tersebut.
3. **Konversi Mnemonic ke Seed**: Saat mnemonic phrase dimasukkan, fungsi `Mnemonic::from_phrase()` mengambil mnemonic phrase sebagai input, menghasilkan entri acak dan kode checksum dari phrase tersebut, dan kemudian memverifikasi kode checksum. Proses verifikasi kode checksum menggunakan perhitungan hash SHA-256.
4. **Seed PBKDF2**: Untuk menghasilkan 64 byte seed dari mnemonic phrase, fungsi `Mnemonic::to_seed()` menggunakan algoritma **PBKDF2-HMAC-SHA512**. PBKDF2 adalah algoritma Key Derivation Function (KDF) yang digunakan untuk meningkatkan keamanan seed dengan menurunkan entropy rahasia sebelumnya.

Dengan demikian, algoritma kriptografi yang digunakan dalam implementasi BIP-0039 (mnemonic) adalah:

- Generasi Entropy: Algoritma Kriptografi Acak (ChaCha block cipher)
- Hash Entri: SHA-256
- Verifikasi Checksum: SHA-256
- Seed Generation: PBKDF2-HMAC-SHA512
