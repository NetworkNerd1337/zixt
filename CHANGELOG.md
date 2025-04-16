# Zixt Changelog

All notable changes to the Zixt application are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes at this time.

## [1.0.3] - 2025-04-16

### Added
- **Security Headers**: Implemented Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security (HSTS), and Referrer-Policy for enhanced web security.
- **CSRF Protection**: Integrated Flask-WTF for CSRF token validation on all forms.
- **Key Rotation**: Added SPHINCS+ key rotation every 30 days with 90-day key history storage in `user_key_history` table.
- **Perfect Forward Secrecy (PFS)**: Enabled ephemeral Kyber1024 keys per message and TLS ECDHE ciphers in Nginx for PFS.

### Changed
- Updated `routes.py` to include CSRF-protected forms and key rotation endpoint (`/rotate_key`).
- Modified `crypto.py` to support ephemeral Kyber keys and key rotation logic.
- Enhanced Nginx configuration to enforce HTTPS and include security headers.
- Updated `models.py` to add `user_key_history` table for key rotation.

### Fixed
- Ensured SocketIO messages are validated server-side to prevent unauthorized broadcasts.
- Improved error handling for file decryption failures in `/download` endpoint.

## [1.0.2] - 2025-04-10

### Added
- **Real-Time Messaging**: Integrated Flask-SocketIO with Redis for real-time message updates without browser refresh.
- **File Attachments**: Supported one optional file per message (images: PNG, JPEG, GIF, BMP; documents: PDF, TXT, DOC, DOCX; ≤15MB), with inline image display and document hyperlinks.
- **Multi-User Threads**: Enabled threads with multiple participants, with creator-only add/remove user capabilities.
- **Thread Management**: Added user-specific thread deletion (soft delete via `ThreadParticipant.deleted`), preserving threads for other users.
- **Input Validation**: Implemented Bleach sanitization for message content to prevent XSS.

### Changed
- Updated `dashboard.html` to include a right-sidebar thread list and real-time messaging interface.
- Modified `routes.py` to handle SocketIO events (`send_message`, `thread_update`) and file uploads.
- Enhanced `models.py` to include `ThreadParticipant` table for multi-user thread associations.
- Updated `crypto.py` to encrypt files with AES-256-GCM using Kyber-derived keys.
- Added `script.js` for client-side SocketIO logic.
- Updated `requirements.txt` to include `flask-socketio`, `redis`, `bleach`, and `eventlet`.

### Fixed
- Corrected thread participant checks to prevent unauthorized access.
- Ensured file upload restrictions (size, type) are enforced server-side.

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

[Unreleased]: https://github.com/NetworkNerd1337/zixt/compare/v1.0.3...HEAD
[1.0.1]: https://github.com/NetworkNerd1337/zixt/releases/tag/v1.0.1