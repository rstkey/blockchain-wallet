# Keystore (Web3 Secret Storage Definition)

Algoritma kriptografi digunakan pada beberapa bagian dalam proses export/import keystore file.

### Enkripsi Kunci Privat:

1. Algoritma AES-128-CTR digunakan untuk mengenkripsi kunci privat sebelum disimpan dalam keystore.
2. Kunci enkripsi diperoleh melalui algoritma Scrypt dengan parameter default yang ditentukan (log_n=13, r=8, p=1).
3. Sebuah vektor inisialisasi (IV) acak juga dibuat menggunakan fungsi acak (StdRNG).
4. Setelah proses enkripsi, MAC (Message Authentication Code) dihitung menggunakan algoritma Keccak-256.

### Dekripsi Kunci Privat:

1. Ketika kunci privat akan diambil dari keystore, proses dekripsi dilakukan dengan menggunakan algoritma AES-128-CTR.
2. Kunci dekripsi diperoleh melalui algoritma Scrypt atau PBKDF2 (tergantung pada parameter KdfparamsType yang disimpan dalam keystore).
3. Setelah dekripsi, MAC dihitung dan diverifikasi terhadap MAC yang disimpan dalam keystore untuk memastikan integritas data.

Dengan demikian, dapat disimpulkan bahwa algoritma kriptografi digunakan dalam dua proses utama pada modul keystore, yaitu enkripsi dan dekripsi kunci privat. Algoritma **AES-128-CTR** digunakan untuk melakukan enkripsi dan dekripsi, sedangkan algoritma **Scrypt dan PBKDF2** digunakan untuk menurunkan kunci enkripsi/dekripsi dari kata sandi pengguna. Selain itu, algoritma **Keccak-256** dimanfaatkan untuk menghitung MAC guna memastikan integritas data.
