# Blockchain Implementation

This is a simple implementation of a blockchain in Java. It demonstrates the basic concepts of a blockchain, including blocks, transactions, mining, and wallet functionality.

## Features

- Block: Represents a block in the blockchain. Each block contains a list of transactions and a reference to the previous block.
- Transaction: Represents a transaction between two wallets. It includes the sender, recipient, value, and signature.
- Wallet: Represents a wallet in the blockchain. It generates key pairs for signing transactions and maintains a list of unspent transaction outputs (UTXOs).
- StringUtil: Contains utility methods for hashing and digital signatures.
- Chain: The main class that orchestrates the blockchain. It creates the genesis block, manages the list of blocks, and provides methods for mining new blocks and validating the chain.

## Prerequisites

- Java Development Kit (JDK) 8 or above

