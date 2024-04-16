# Transaction

Berikut adalah penjelasan rinci mengenai penggunaan algoritma kriptografi dalam modul "transaction.rs":

### Signing dengan Wallet

Pada fungsi sign_with_wallet(), transaksi ditandatangani menggunakan kunci rahasia dari dompet Ethereum. Algoritma kriptografi yang digunakan untuk proses penandatanganan ini adalah algoritma tanda tangan digital, seperti ECDSA (Elliptic Curve Digital Signature Algorithm), yang memanfaatkan kurva eliptik sesuai dengan standar Ethereum.

### Hashing Pesan Tanda Tangan

Fungsi signing_message() menghitung hash Keccak-256 dari transaksi yang akan ditandatangani. Algoritma hash kriptografik Keccak-256 digunakan untuk menghasilkan representasi kompak dari data transaksi, yang kemudian digunakan dalam proses penandatanganan.

### Enkoding RLP

Digunakan skema pengkodean RLP (Recursive Length Prefix) untuk menyandikan data transaksi dalam format yang dapat dikirim melalui jaringan Ethereum. RLP adalah skema pengkodean yang dirancang khusus untuk Ethereum, yang memungkinkan pengkodean data secara efisien.
