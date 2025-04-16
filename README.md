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
### Step 2: Install Dependencies

Install required system packages:
```bash
sudo apt install -y python3 python3-pip python3-venv mysql-server nginx redis-server certbot python3-certbot-nginx build-essential libssl-dev libffi-dev python3-dev cmake ninja-build git
```
### Step 3: Secure MySQL

Configure MySQL with a secure root password:
```bash
sudo mysql_secure_installation
```
_Pro Tip: This triggers a generic security configuration for the MySQL installation. This is not a substitute for professionally securing your MySQL installation, however, this is a good start._

### Step 4: Install Redis

Ensure Redis is running:
```bash
sudo systemctl enable redis
sudo systemctl start redis
redis-cli ping  # Should return "PONG"
```

### Step 5: Install liboqs for Post-Quantum Cryptography

Zixt relies on liboqs for Kyber1024 and SPHINCS+.

* Clone and Build liboqs:
```bash
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja ..
ninja
sudo ninja install
```

* Install liboqs-python:
```bash
pip install oqs
```

### Step 6: Set Up Zixt Application

* Clone Repository:
```bash
git clone https://github.com/networknerd1337/zixt
```

* Create Virtual Environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

* Install Python Dependencies:
```bash
pip install -r requirements.txt
```
_Pro Tip: You may encounter issues when attempting to install the whole requirements file and may need to troubleshoot if any of the installations don't complete. Please ensure all requirements are fully installed._

* Create Uploads Folder:

For secure file storage:
```bash
mkdir -p app/uploads
chmod 750 app/uploads
chown $(whoami):www-data app/uploads
```

* Configure MySQL Database:

Apply the schema:
```bash
sudo mysql -u root -p < setup.sql
```

* Set Up Admin User:

Generate a SPHINCS+ key pair and password hash:
```bash
from app.crypto import Crypto
import base64
crypto = Crypto()
pub, priv = crypto.generate_user_keypair()
print("Public Key:", base64.b64encode(pub).decode())
print("Password Hash:", crypto.hash_password('your_admin_password'))
```
  * This code:

    * Imports the Crypto class from app.crypto.
    * Generates a SPHINCS+ key pair (public and private keys).
    * Hashes a password using SHA3-512.
    * Prints the Base64-encoded public key and hashed password for use in the MySQL admin user setup.

  * Execution Context:

    * The code cannot be run directly from the command line without being placed in a Python environment that has access to the app.crypto module, which is part of the Zixt application.
    * It does not need to be saved as a standalone .py file and run from the CLI unless you prefer that approach for convenience.
    * The most straightforward ways to execute it are:
      * Interactively in a Python shell within the Zixt project environment.
      * As a temporary script saved in a .py file and run from the CLI.
      * Using a one-off command in the project directory with the virtual environment activated.

_Given the dependency on app.crypto, the code must be executed in the context of the Zixt project directory with the virtual environment activated to ensure the module is importable._

Enter into the MySQL DB environment:
```bash
mysql -u root -p
```

Insert the admin user into the database with the public key and hash that you just generated:
```bash
INSERT INTO user (username, email, public_key, password_hash, is_admin, is_verified)
VALUES ('admin', 'admin@yourdomain.com', '<base64_public_key>', '<sha3_512_hashed_password>', TRUE, TRUE);
```

* Configure Email Service:

Configure the SMTP settings in config.py appropriately for your SMTP provider or service. This is used for the user email verification system.
```bash
SMTP_SERVER = 'smtp.yourdomain.com'
SMTP_PORT = 465
SENDER_EMAIL = 'your.email@yourdomain.com'
SENDER_PASSWORD = 'your-smtp-password'
```
