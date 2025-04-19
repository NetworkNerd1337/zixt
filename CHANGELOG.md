# Zixt Changelog

All notable changes to the Zixt secure messaging application are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes at this time.

## [1.0.2] - 2025-04-19

### Added
- **Zero Knowledge Proofs (ZKPs)**:
  - Implemented zk-SNARKs for private user authentication and anonymous message metadata using `circom` and `snarkjs`.
  - Added `user_public_key_hash` table and `zkp_proof` column in `message` table to store proofs.
  - Enabled privacy-preserving login and messaging, hiding usernames, sender details, and timestamps.
  - Updated blockchain to log ZKP proofs instead of plaintext metadata.
- **ZKP Dependencies**:
  - Added `nodejs`, `npm`, `circom`, and `snarkjs` for circuit definition and proof generation/verification.
  - Included `web3` Python package for ZKP integration.
- **Circuit Files**:
  - Added `auth.circom` and `message.circom` for authentication and message proofs.
  - Generated `.wasm` and `.zkey` files for client-side proof generation.
- **DHT Security with DTLS**:
  - Implemented DTLS (Datagram TLS) for encrypting Kademlia DHT traffic over UDP port 8468, protecting block metadata and preventing eavesdropping.
  - Added DTLS certificate generation and configuration for secure peer discovery and block propagation.
  - Updated `app/dht.py` to use a `DTLSServer` class with SSL context.
  - Modified `app/blockchain.py` to integrate with DTLS-enabled DHT.

### Changed
- Updated `routes.py` to verify ZKP proofs for login and message sending.
- Modified `models.py` and `setup.sql` to support ZKP storage.
- Enhanced `script.js` for client-side proof generation with `snarkjs`.
- Updated `blockchain.py` to include ZKP proofs and use DTLS-enabled DHT.
- Changed `liboqs-python` installation to use source from GitHub instead of PyPI `oqs==0.10.1` to resolve `ImportError`.

### Fixed
- Resolved OpenSSL dependency issue in `liboqs` build by ensuring `libssl-dev` is installed.
- Fixed Gunicorn user setup to use dedicated `zixtuser` for production security.

## [1.0.1] - 2025-04-16

### Added
- Initial release with post-quantum cryptography (Kyber1024, SPHINCS+, AES-256-GCM, SHA3-512).
- Real-time messaging with SocketIO/Redis.
- File attachments (≤15MB, images/documents).
- Proprietary blockchain with Kademlia DHT.
- User management with email verification and admin panel.
- Security headers, CSRF protection, key rotation, and PFS.
- Dedicated Gunicorn user (`zixtuser`).
- Detailed admin user setup with interactive/script options.

### Changed
- N/A (initial release).

### Fixed
- N/A (initial release).

[Unreleased]: https://github.com/NetworkNerd1337/zixt/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/NetworkNerd1337/zixt/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/NetworkNerd1337/zixt/releases/tag/v1.0.1
