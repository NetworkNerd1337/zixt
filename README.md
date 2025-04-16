# Zixt: Secure Post-Quantum Messaging Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Ubuntu 24.04](https://img.shields.io/badge/OS-Ubuntu%2024.04-orange.svg)](https://ubuntu.com/)

**Zixt** is a secure, real-time messaging application designed for privacy and future-proof security. Built with **post-quantum cryptography** (Kyber1024, SPHINCS+), it ensures your messages and identity are protected against both classical and quantum attacks. Zixt features multi-user message threads, file attachments, a proprietary blockchain ledger with DHT peer discovery, robust user management, and a scalable architecture using Flask, SocketIO, Redis, Gunicorn, Nginx, and MySQL. Deploy it on **Ubuntu 24.04** with HTTPS via Let's Encrypt for a fully secure experience.

## 🌟 Features

- **Post-Quantum Encryption**:
  - **Kyber1024 (ML-KEM)**: Quantum-resistant key encapsulation for messages and files with perfect forward secrecy.
  - **SPHINCS+**: Secure digital signatures for authentication and blockchain integrity.
  - **AES-256-GCM**: Symmetric encryption for content, derived via HKDF-SHA3-256.
  - **SHA3-512**: Strongest hashing for passwords and tokens.

- **Real-Time Messaging**:
  - Multi-user threads with text and file attachments (images/documents, ≤15MB).
  - Real-time updates using **SocketIO** and **Redis** for seamless communication.
  - Input sanitization with Bleach to prevent XSS.

- **Blockchain Ledger**:
  - Proprietary blockchain to log encrypted messages, signed with SPHINCS+.
  - Decentralized peer discovery via **Kademlia DHT**.

- **User Management**:
  - Cryptographic pseudonym login with SPHINCS+ key pairs.
  - Email verification for self-registration.
  - Admin panel to create, edit, delete users, and manage public keys.
  - Key rotation every 30 days with 90-day key history.

- **Security Enhancements**:
  - **CSRF protection** with Flask-WTF.
  - **Security headers**: CSP, HSTS, X-Frame-Options, and more.
  - **Perfect Forward Secrecy** via ephemeral Kyber keys and TLS ECDHE ciphers.
  - HTTPS with **Let's Encrypt**.

- **Scalable Architecture**:
  - Flask web framework with Gunicorn WSGI server.
  - Nginx reverse proxy for performance and security.
  - MySQL for reliable data storage.

## 📋 Prerequisites

- **Operating System**: Ubuntu 24.04 LTS
- **Hardware**: Minimum 2GB RAM, 20GB disk space
- **Network**: Internet access, domain name (or IP), ports 80, 443, 8468 open
- **Software**:
  - Python 3.10 or higher
  - MySQL 8.0+
  - Nginx
  - Redis
  - Git
  - Build tools (cmake, ninja)

## 🛠️ Installation

Follow these steps to set up Zixt on Ubuntu 24.04.

### Step 1: Update System

```bash
sudo apt update && sudo apt upgrade -y
```