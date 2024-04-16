# Algoritma Kriptografi di Wallet Cryptocurrency

### Modul Wallet

- Pembuatan Kunci Privat: Menggunakan kelas SecretKey dari pustaka k256, yang didasarkan pada skema kurva eliptik secp256k1 yang digunakan dalam Ethereum.
- Perhitungan Kunci Publik: Menurunkan kunci publik dari kunci privat menggunakan operasi matematis pada kurva eliptik secp256k1.
- Perhitungan Alamat Ethereum: Menerapkan fungsi hash Keccak-256 pada kunci publik yang terenkode untuk mendapatkan alamat Ethereum.
- Tanda Tangan Digital: Mengimplementasikan algoritma tanda tangan digital ECDSA menggunakan pustaka k256 untuk menghasilkan tanda tangan menggunakan kunci privat dan pesan/hash yang akan ditandatangani.

### Modul Transaksi

- Penandatanganan dengan Dompet: Menggunakan kunci privat dompet dan algoritma tanda tangan digital kurva eliptik (misalnya ECDSA) untuk menandatangani transaksi.
- Hashing Pesan Tanda Tangan: Menghitung hash Keccak-256 dari data transaksi yang akan ditandatangani.
- Enkoding RLP: Memanfaatkan skema pengkodean Recursive Length Prefix (RLP) yang dirancang khusus untuk Ethereum, untuk mengenkode data transaksi secara efisien.

### Modul Keystore

- Enkripsi Kunci Privat: Menggunakan AES-128-CTR untuk mengenkripsi kunci privat sebelum disimpan dalam file keystore. Kunci enkripsi diperoleh menggunakan algoritma Scrypt atau PBKDF2, berdasarkan parameter keystore. Juga dibuat Vektor Inisialisasi (IV) acak, dan dihitung Kode Otentikasi Pesan (MAC) Keccak-256 untuk memastikan integritas data.
- Dekripsi Kunci Privat: Melakukan dekripsi kunci privat dari file keystore menggunakan AES-128-CTR. Kunci dekripsi diperoleh menggunakan Scrypt atau PBKDF2, dan MAC diverifikasi untuk memastikan integritas data.

### Modul BIP-39 (Mnemonic)

- Generasi Entropy: Menggunakan generator bilangan acak yang aman secara kriptografis (blok cipher ChaCha) untuk menghasilkan entropy awal untuk frasa mnemonic.
- Hashing Entropy: Menerapkan fungsi hash SHA-256 pada entropy yang dihasilkan.
- Verifikasi Checksum Mnemonic: Menggunakan SHA-256 untuk memverifikasi checksum dari frasa mnemonic.
- Generasi Seed: Menerapkan algoritma PBKDF2-HMAC-SHA512 untuk menurunkan seed dari frasa mnemonic, meningkatkan keamanan seed.

### Modul BIP-32 (Dompet Deterministik Hierarkis)

- Derivasi Kunci Anak: Menggunakan HMAC dengan fungsi hash SHA-512 untuk menghitung kunci anak dari kunci induk dan kode rantai.
- Operasi Kurva Eliptik: Memanfaatkan kurva eliptik secp256k1, diimplementasikan dalam pustaka k256, untuk komputasi kunci privat dan publik selama proses derivasi kunci.

### Secara ringkas, algoritma kriptografi utama yang digunakan dalam implementasi dompet cryptocurrency ini meliputi:

- Kriptografi Kurva Eliptik (secp256k1)
- Fungsi hash Keccak-256 (SHA-3)
- Enkripsi AES-128-CTR
- Fungsi Derivasi Kunci Scrypt dan PBKDF2
- HMAC-SHA512 untuk derivasi kunci
- Pembangkit Bilangan Acak ChaCha
- Tanda Tangan Digital ECDSA

Algoritma-algoritma ini digunakan secara strategis di berbagai modul dalam implementasi dompet untuk menjamin keamanan dan integritas fungsionalitas dompet.
