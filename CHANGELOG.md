# Zixt Changelog

All notable changes to the Zixt application are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-04-01

### Added
- Initial release of Zixt secure messaging application.
- **Post-Quantum Cryptography**:
  - Kyber1024 (ML-KEM) for key encapsulation.
  - SPHINCS+ (SLH-DSA) for authentication signatures.
  - AES-256-GCM for message encryption.
  - SHA3-512 for password hashing.
- **Message Threads**: Basic thread-based messaging with single or multi-user support.
- **Blockchain Ledger**: Proprietary blockchain to log encrypted messages, signed with SPHINCS+.
- **DHT Peer Discovery**: Kademlia-based decentralized node discovery for blockchain.
- **User Management**:
  - Cryptographic pseudonym login with SPHINCS+ key pairs.
  - Email verification for self-registration using Gmail SMTP.
  - Admin panel to create, edit, delete users, and manage public keys.
- **Web Framework**:
  - Flask with Gunicorn WSGI server and Nginx reverse proxy.
  - MySQL database for user and message storage.
  - HTTPS with Let's Encrypt.
- **Key Generation**: Provided `keygen.py` for SPHINCS+ key pair generation across platforms (MacBook, Windows, iPhone, Android).

### Changed
- N/A (initial release).

### Fixed
- N/A (initial release).

[1.0.1]: https://github.com/NetworkNerd1337/zixt/releases/tag/v1.0.1