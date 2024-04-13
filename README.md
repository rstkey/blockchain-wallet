# Todo

[ ] Vault (storing seed, creating)
[ ] Way to interact with the test network/ rpc calling (integrate with alloy provider)
[ ] Change the implementation of keystore (implement it in Wallet struct)

## Transaction

[ ] Transaction (creating, and sending) (see alloy)
[ ] How to send the transaction from my implementation of the transaction.

#### one way to do it

- Parse the signer to the provider signer - Parse the transaction to Alloy TransactionRequest

#### another way to do it

- Other way : reimplement the transaction
- Or search another provider (rust web3, ethers, etc : need to check)

## Simple todo

[ ] Verify that using password is working in mnemonics, and accept Option as the password parameter
[ ] examples: mnemonic signer (create mnemonic, derive path, random and from phrase)
[ ] examples: signing using Wallet object
[ ] examples: signing message

## refactor todo

[ ] refactor the cryptography module.
[ ] refactor the mnemonics to be more readable. use entropy struct

# MY choice regarding transaction
- Reimplement so that it's compatible with alloy

# The purpose of this project (blockchain wallet)
Clef handles account creation, key management and signing transactions/data.
