# Rust Library For Cryptocurrency Wallet

## Folder Structure

- `src` : contains the source code of the library
- `examples` : contains some examples of the library
- `docs` : contains some documentation of the library

## Requirements

The following are the requirements to run this library:

- Rust
- Cargo

To install the required tools, I recommend using [rustup](https://rustup.rs/).
There, you will find this instruction:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## How to Run

1. Clone this repository
2. Go to the repository directory
3. Run the following command:

```bash
cargo run --example <example_name>
```

## Run the Tests

To run the tests, you can use the following command:

```bash
cargo test
```

## Documentation

- [Wallet](docs/wallet.md)
- [Keystore](docs/keystore.md)
- [BIP32](docs/bip32.md)
- [BIP39](docs/bip39.md)
- [Transaction](docs/transaction.md)
