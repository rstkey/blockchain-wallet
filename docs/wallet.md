# Wallet

Untuk bagian wallet, beberapa bagian yang menggunakan algoritma kriptografi:

### Pembuatan Kunci Privat

elas Wallet menyediakan fungsionalitas untuk membuat kunci privat dari secret/rahasia tertentu menggunakan kelas SecretKey dari library k256. Kunci privat ini merupakan representasi matematis dari kunci privat dalam skema kurva eliptik secp256k1 yang digunakan dalam Ethereum.

### Perhitungan Kunci Publik

Metode public_key() pada kelas Wallet menggunakan kunci privat untuk menghitung kunci publik yang sesuai. Kunci publik ini diperoleh dengan operasi matematis pada kurva eliptik secp256k1.

### Perhitungan Alamat Ethereum

Metode address() pada kelas Wallet menghitung alamat Ethereum yang sesuai dengan kunci publik. Hal ini dilakukan dengan menerapkan fungsi hash Keccak-256 pada representasi terenkode dari kunci publik.

### Pembuatan Tanda Tangan Digital

Metode sign() dan sign_message() pada kelas Wallet mengimplementasikan skema tanda tangan digital ECDSA (Elliptic Curve Digital Signature Algorithm) menggunakan library k256. Tanda tangan digital ini dihasilkan dengan menggunakan kunci privat dan pesan/hash yang akan ditandatangani.

Dari analisis di atas, komponen utama kriptografi yang digunakan adalah skema **kurva eliptik secp256k1** dan fungsi hash **Keccak-256**. Skema kurva eliptik digunakan untuk pembuatan dan manipulasi kunci privat dan publik, sedangkan fungsi hash **Keccak-256** digunakan untuk menghitung alamat Ethereum dari kunci publik.
