# Folder Structure

- `src` : contains the source code of the library
- `examples` : contains the examples of the library
- `docs` : contains the documentation of the library

# Todo

- [x] Vault (storing seed, creating)
- [x] Way to interact with the test network/ rpc calling (integrate with alloy provider)
- [x] Change the implementation of keystore (implement it in Wallet struct)

## Transaction

- [x] Transaction (creating, and sending) (see alloy)
- [x] How to send the transaction from my implementation of the transaction.

#### one way to do it

- Parse the signer to the provider signer - Parse the transaction to Alloy TransactionRequest

#### another way to do it

- Other way : reimplement the transaction
- Or search another provider (rust web3, ethers, etc : need to check)

## Simple todo

- [x] Verify that using password is working in mnemonics, and accept Option as the password parameter
- [x] examples: mnemonic signer (create mnemonic, derive path, random and from phrase)
- [x] examples: signing using Wallet object
- [x] examples: signing message
- [ ] differentiate password for seed generation and password for keystore

## refactor todo

- [ ] refactor the cryptography module.
- [ ] refactor the mnemonics to be more readable. use entropy struct

# MY choice regarding transaction

- Reimplement so that it's compatible with alloy

# NOTES

Clef handles account creation, key management and signing transactions/data.

- metamask tidak menggunakan password untuk melakukan derivasi path
