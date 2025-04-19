# Zixt: Quantum-Secure Messaging Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Ubuntu 24.04](https://img.shields.io/badge/OS-Ubuntu%2024.04-orange.svg)](https://ubuntu.com/)

**Zixt** is a state-of-the-art, web-based messaging application engineered for unparalleled security and privacy. Built with **post-quantum cryptography** (Kyber1024, SPHINCS+), **zero-knowledge proofs (zk-SNARKs)**, and **encrypted DHT**, Zixt protects communications and metadata against classical and quantum threats. It offers real-time multi-user message threads, secure file sharing, a proprietary blockchain ledger, and robust user management, running on **Ubuntu 24.04** with Flask, SocketIO, Redis, Gunicorn, Nginx, and MySQL, secured by Let's Encrypt HTTPS.

**Current Version**: See [VERSION.md](VERSION.md).  
**Release Notes**: Check [CHANGELOG.md](CHANGELOG.md).

## 🌟 Features

- **Post-Quantum Cryptography**:
  - **Kyber1024 (ML-KEM)**: Quantum-resistant key encapsulation with perfect forward secrecy (PFS).
  - **SPHINCS+ (SLH-DSA)**: Quantum-secure digital signatures for authentication and blockchain integrity.
  - **AES-256-GCM**: Symmetric encryption with HKDF-SHA3-256-derived keys.
  - **SHA3-512**: Robust hashing for passwords and verification tokens.

- **Zero-Knowledge Proofs (ZKPs)**:
  - zk-SNARKs for private user authentication and anonymous message metadata, protecting usernames, sender details, and timestamps.
  - Privacy-preserving blockchain logging with hidden metadata.

- **Encrypted Distributed Hash Table (DHT)**:
  - Kademlia DHT with DTLS (Datagram TLS) for secure peer discovery and block propagation, encrypting all traffic to prevent metadata exposure.

- **Real-Time Messaging**:
  - Multi-user threads for one-on-one or group chats, updated instantly via SocketIO and Redis.
  - Secure file attachments (images: PNG, JPEG, GIF, BMP; documents: PDF, TXT, DOC, DOCX; ≤15MB) with inline image display.
  - Input sanitization with Bleach to prevent XSS attacks.

- **Blockchain Ledger**:
  - Proprietary blockchain to log encrypted messages, signed with SPHINCS+ and protected by ZKP proofs.
  - Decentralized peer discovery via encrypted DHT.

- **User Management**:
  - Cryptographic pseudonym login with SPHINCS+ key pairs and ZKP proofs.
  - Self-registration with email verification via SMTP.
  - Admin panel for creating, editing, and deleting users, and managing public keys.
  - Key rotation every 30 days with 90-day key history.

- **Security Enhancements**:
  - CSRF protection with Flask-WTF.
  - Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
  - Perfect Forward Secrecy via ephemeral Kyber keys and TLS ECDHE ciphers.
  - HTTPS enforced with Let's Encrypt.

- **Scalable Architecture**:
  - Flask web framework with Gunicorn WSGI server.
  - Nginx reverse proxy for performance and security.
  - MySQL database for reliable storage.

## 📋 Prerequisites

- **Operating System**: Ubuntu 24.04 LTS
- **Hardware**: Minimum 2GB RAM, 20GB disk space
- **Network**: Internet access, domain name (or IP), ports 80, 443, 8468 (UDP) open
- **Software**:
  - Python 3.10 or higher
  - MySQL 8.0+
  - Nginx
  - Redis
  - Git
  - Node.js, npm
  - Build tools (cmake, ninja)
  - OpenSSL for DTLS certificates

## 🛠️ Installation

Follow these steps to deploy Zixt on Ubuntu 24.04. Refer to [VERSION.md](VERSION.md) for the current version.

### Step 1: Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Dependencies

Install system packages required for Zixt:

```bash
sudo apt install -y python3 python3-pip python3-venv mysql-server nginx redis-server certbot python3-certbot-nginx build-essential libssl-dev libffi-dev python3-dev cmake ninja-build git nodejs npm
```

### Step 3: Secure MySQL

Set a secure root password and configure MySQL:

```bash
sudo mysql_secure_installation
```

### Step 4: Configure Redis

Ensure Redis is running:

```bash
sudo systemctl enable redis
sudo systemctl start redis
redis-cli ping  # Should return "PONG"
```

### Step 5: Install liboqs for Post-Quantum Cryptography

Zixt uses `liboqs` for Kyber1024 and SPHINCS+.

1. **Install Build Dependencies**:

```bash
sudo apt install -y build-essential cmake ninja-build libssl-dev
```

2. **Clone and Build liboqs**:

```bash
git clone --branch 0.10.1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DOQS_ALGS_ENABLED=ALL -DOPENSSL_ROOT_DIR=/usr -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/x86_64-linux-gnu/libcrypto.so ..
ninja
sudo ninja install
```

3. **Update Library Path**:

```bash
sudo ldconfig
ldconfig -p | grep liboqs
```

If `liboqs.so` is not listed (e.g., `/usr/local/lib/liboqs.so`):

```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
```

4. **Install liboqs-python from Source**:

Due to potential issues with the PyPI package, install `oqs-python` from source:

```bash
cd /path/to/zixt
source venv/bin/activate
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
cd .. && rm -rf liboqs-python
```

5. **Verify Installation**:

```bash
python -c "from oqs import KeyEncapsulation, Signature; print(KeyEncapsulation('Kyber1024')); print(Signature('SPHINCS+-SHAKE-256f-simple'))"
```

Expected output shows object references. If this fails, check [liboqs-python GitHub](https://github.com/open-quantum-safe/liboqs-python) or reinstall.

### Step 6: Install ZKP Dependencies

Zixt uses zk-SNARKs for metadata privacy, requiring `circom` and `snarkjs`.

1. **Install Node.js and npm**:

```bash
sudo apt install -y nodejs npm
```

2. **Install `circom`**:

```bash
npm install -g circom
```

3. **Install `snarkjs`**:

```bash
cd /path/to/zixt
npm init -y
npm install snarkjs
```

4. **Verify Installation**:

```bash
circom --version
node -e "require('snarkjs')"
```

Ensure no errors. If issues arise, consult [circom](https://docs.circom.io) or [snarkjs](https://github.com/iden3/snarkjs) documentation.

### Step 7: Set Up Zixt Application

1. **Clone Repository**:

```bash
git clone https://github.com/NetworkNerd1337/zixt.git
cd zixt
```

2. **Create Virtual Environment**:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install Python Dependencies**:

```bash
pip install -r requirements.txt
```

4. **Create Uploads and Certs Folders**:

```bash
mkdir -p app/uploads certs
```

5. **Generate DTLS Certificates**:

Zixt uses DTLS for secure DHT communication:

```bash
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=zixt"
sudo chown zixtuser:zixtuser certs/server.crt certs/server.key
sudo chmod 600 certs/server.key
```

6. **Configure MySQL Database**:

Apply the database schema:

```bash
sudo mysql -u root -p < setup.sql
```

7. **Generate ZKP Circuits**:

Generate circuit files for zk-SNARKs:

```bash
cd app/circuits
circom auth.circom --r1cs --wasm --sym
circom message.circom --r1cs --wasm --sym
snarkjs powersoftau new bn128 12 pot12_0000.ptau
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v
snarkjs groth16 setup auth.r1cs pot12_0001.ptau auth_0000.zkey
snarkjs zkey contribute auth_0000.zkey auth_0001.zkey --name="Second contribution" -v
snarkjs groth16 setup message.r1cs pot12_0001.ptau message_0000.zkey
snarkjs zkey contribute message_0000.zkey message_0001.zkey --name="Second contribution" -v
cp auth.wasm auth_0001.zkey message.wasm message_0001.zkey ../../static/circuits/
```

8. **Set Up Admin User**:

Generate a SPHINCS+ key pair and password hash for the admin user.

- Navigate to the Zixt directory:

```bash
cd /path/to/zixt
```

- Activate the virtual environment:

```bash
source venv/bin/activate
```

- Start a Python shell:

```bash
python
```

- Run the following code:

```python
from app.crypto import Crypto
import base64
crypto = Crypto()
pub, priv = crypto.generate_user_keypair()
print("Public Key:", base64.b64encode(pub).decode())
print("Password Hash:", crypto.hash_password('your_admin_password'))
print("Private Key (Save Securely):", base64.b64encode(priv).decode())
```

Replace `'your_admin_password'` with a secure password (e.g., `'MySecurePass123!'`). Copy the **Public Key**, **Password Hash**, and **Private Key** (store the private key securely, e.g., in a password manager, for admin login).

Exit the shell:

```python
exit()
```

Alternatively, save as a script:

```bash
nano generate_admin_keys.py
```

Add:

```python
from app.crypto import Crypto
import base64
crypto = Crypto()
pub, priv = crypto.generate_user_keypair()
print("Public Key:", base64.b64encode(pub).decode())
print("Password Hash:", crypto.hash_password('your_admin_password'))
print("Private Key (Save Securely):", base64.b64encode(priv).decode())
```

Run:

```bash
python generate_admin_keys.py
```

Delete after use:

```bash
rm generate_admin_keys.py
```

- Insert the admin user into MySQL:

```bash
mysql -u root -p
```

Run:

```sql
INSERT INTO user (username, email, public_key, password_hash, is_admin, is_verified)
VALUES ('admin', 'admin@yourdomain.com', '<base64_public_key>', '<sha3_512_hash>', TRUE, TRUE);
INSERT INTO user_public_key_hash (user_id, public_key_hash)
VALUES (LAST_INSERT_ID(), '<sha3_512_public_key_hash>');
```

Compute `<sha3_512_public_key_hash>`:

```python
import hashlib
print(hashlib.sha3_512(base64.b64decode('<base64_public_key>')).hexdigest())
```

Verify:

```sql
SELECT username, email, is_admin, is_verified FROM user;
EXIT;
```

9. **Configure Email Service**:

Zixt uses SMTP for email verification. Gmail is recommended, but other providers are supported.

- **Set Up Gmail SMTP**:

  - Ensure a Gmail account (e.g., `your.email@gmail.com`).
  - Enable **2-Step Verification**:
    - Go to [Google Account > Security > 2-Step Verification](https://myaccount.google.com/security).
    - Enable using a phone number or authenticator app.
  - Generate an **App Password**:
    - Navigate to [App Passwords](https://myaccount.google.com/security).
    - Select **App** > **Mail**, **Device** > **Other (Custom Name)**, enter `Zixt`.
    - Copy the 16-character password (e.g., `abcd efgh ijkl mnop`).
    - Store securely (shown only once).

- **Update `config.py`**:

Edit:

```bash
nano /path/to/zixt/config.py
```

Set:

```python
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465
SENDER_EMAIL = 'your.email@gmail.com'
SENDER_PASSWORD = 'your_app_password'
```

Replace `your.email@gmail.com` and `your_app_password` (no spaces). Save and exit.

- **Alternative SMTP Providers** (Optional):

Use providers like SendGrid, Postmark, or Amazon SES:
  - Example for SendGrid:
    - **SMTP Server**: `smtp.sendgrid.net`
    - **SMTP Port**: 465 (SSL)
    - **Sender Email**: Your verified email
    - **Sender Password**: API key
  - Update `config.py` accordingly.
  - For TLS on port 587, modify `app/email.py`:

```python
with smtplib.SMTP(smtp_server, smtp_port) as server:
    server.starttls()
    server.login(self.sender_email, self.sender_password)
    server.sendmail(self.sender_email, recipient_email, msg.as_string())
```

- **Test Email Configuration** (Optional):

Create:

```bash
nano /path/to/zixt/test_email.py
```

Add:

```python
from app.email import EmailService
email_service = EmailService(
    smtp_server='smtp.gmail.com',
    smtp_port=465,
    sender_email='your.email@gmail.com',
    sender_password='your_app_password'
)
success = email_service.send_verification_email('test@example.com', 'TestUser', 'test-token')
print("Email sent successfully!" if success else "Email sending failed.")
```

Run:

```bash
source venv/bin/activate
python test_email.py
```

Delete:

```bash
rm test_email.py
```

Ensure port 465 is open:

```bash
sudo ufw allow 465
```

### Step 8: Configure Gunicorn

Gunicorn runs Zixt as a WSGI server with a dedicated user for security.

1. **Create Dedicated User**:

```bash
sudo adduser --system --group --no-create-home zixtuser
```

2. **Set File Permissions**:

```bash
sudo chown -R zixtuser:zixtuser /path/to/zixt
sudo chown zixtuser:www-data /path/to/zixt/app/uploads
sudo chmod 770 /path/to/zixt/app/uploads
sudo chown -R zixtuser:zixtuser /path/to/zixt/venv
sudo chmod -R u+rwx /path/to/zixt/venv
sudo chown zixtuser:zixtuser /path/to/zixt/certs/server.crt /path/to/zixt/certs/server.key
sudo chmod 600 /path/to/zixt/certs/server.key
```

Replace `/path/to/zixt` with the actual path.

3. **Create Gunicorn Service**:

```bash
sudo nano /etc/systemd/system/zixt.service
```

Add:

```ini
[Unit]
Description=Zixt Gunicorn Service
After=network.target

[Service]
User=zixtuser
Group=www-data
WorkingDirectory=/path/to/zixt
Environment="PATH=/path/to/zixt/venv/bin"
ExecStart=/path/to/zixt/venv/bin/gunicorn --workers 4 --bind 0.0.0.0:8000 --worker-class eventlet wsgi:app

[Install]
WantedBy=multi-user.target
```

Replace `/path/to/zixt`.

4. **Enable and Start Service**:

```bash
sudo systemctl daemon-reload
sudo systemctl enable zixt
sudo systemctl start zixt
```

5. **Verify Service**:

```bash
sudo systemctl status zixt
```

Ensure Gunicorn runs as `zixtuser`:

```bash
ps aux | grep gunicorn
```

**Note**: For development, you may use your own user account instead of `zixtuser`, but this is not recommended for production due to security risks.

### Step 9: Configure Nginx

1. **Create Configuration**:

```bash
sudo nano /etc/nginx/sites-available/zixt
```

Add:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'; img-src 'self' data:; connect-src 'self' ws://localhost:8000 wss://yourdomain.com";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy strict-origin-when-cross-origin;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Replace `yourdomain.com`.

2. **Enable Configuration**:

```bash
sudo ln -s /etc/nginx/sites-available/zixt /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 10: Set Up Let's Encrypt

1. **Obtain Certificate**:

```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

2. **Test Auto-Renewal**:

```bash
sudo certbot renew --dry-run
```

### Step 11: Start Blockchain Node

Run the blockchain node with encrypted DHT:

```bash
source venv/bin/activate
python -m app.blockchain
```

To connect to other nodes:

```python
from app.blockchain import Blockchain
import asyncio
blockchain = Blockchain()
bootstrap_nodes = [("192.168.1.100", 8468)]
asyncio.run(blockchain.start_dht(bootstrap_nodes))
```

Ensure port 8468 is open for UDP:

```bash
sudo ufw allow 8468/udp
```

## 🔑 Key Generation

Zixt uses SPHINCS+ for secure authentication. Generate key pairs for registration and login.

### General Steps

1. **Run Keygen Script**:

```bash
cd /path/to/zixt
source venv/bin/activate
python scripts/keygen.py
```

This creates:
- `zixt_public_key.txt`: Public key for registration.
- `zixt_private_key.txt`: Private key for signing (store securely).

2. **Save Keys**:

- Secure `zixt_private_key.txt` (e.g., encrypted USB, password manager).
- Use `zixt_public_key.txt` during registration.

### Platform-Specific Instructions

#### MacBook

1. Install dependencies:

```bash
brew install python3
cd /path/to/zixt
source venv/bin/activate
pip install oqs==0.10.1
```

2. Run:

```bash
python3 scripts/keygen.py
```

#### Windows

1. Install Python from [python.org](https://www.python.org/downloads/), ensure `pip` is included.
2. Install oqs:

```bash
cd /path/to/zixt
.\venv\Scripts\activate
pip install oqs==0.10.1
```

3. Run:

```bash
python scripts\keygen.py
```

#### iPhone

1. Use **Pythonista** (App Store), transfer `keygen.py` via iCloud.
2. Alternative: Generate keys on another device and transfer securely.

#### Android

1. Install **Termux** (F-Droid):

```bash
pkg install python
cd /path/to/zixt
source venv/bin/activate
pip install oqs==0.10.1
```

2. Run:

```bash
python scripts/keygen.py
```

## 🚀 Usage

Zixt provides a secure, browser-based messaging platform with ZKP-enhanced privacy. Below are detailed instructions with examples.

### 1. Register a User

1. **Generate Keys**:

```bash
cd /path/to/zixt
source venv/bin/activate
python scripts/keygen.py
```

Output:
```
Public Key (Base64): <your_public_key>
Private Key (Base64): <your_private_key>
Keys saved to zixt_public_key.txt and zixt_private_key.txt
```

2. **Register**:

- Open `https://yourdomain.com/register` in a browser.
- Enter:
  - **Username**: e.g., `alice`
  - **Email**: e.g., `alice@example.com`
  - **Public Key**: Paste `<your_public_key>` from `zixt_public_key.txt`.
  - **Password**: Choose a strong password.
- Submit the form.

3. **Verify Email**:

- Check your email for a verification link.
- Click the link to activate your account.

**Example**:
- Alice registers with username `alice`, email `alice@example.com`, and her SPHINCS+ public key.
- She verifies her email and proceeds to log in.

### 2. Log In

1. **Generate Public Key Hash and ZKP Proof**:

Compute the SHA3-512 hash of your public key and generate a ZKP proof client-side (handled by `script.js` in the login form). For manual testing:

```python
import hashlib
public_key = base64.b64decode('<your_public_key>')
public_key_hash = hashlib.sha3_512(public_key).hexdigest()
print("Public Key Hash:", public_key_hash)
```

The ZKP proof requires JavaScript execution in the browser, using `snarkjs` to generate a proof for the `auth.circom` circuit.

2. **Log In**:

- Go to `https://yourdomain.com/login`.
- Enter:
  - **Public Key Hash**: `<public_key_hash>` from above.
  - **ZKP Proof**: Generated by the login form (JSON format).
  - **Private Key**: Paste `<your_private_key>` (for decryption).
- Click "Login".

**Example**:
- Alice enters her public key hash, browser-generated ZKP proof, and private key, then logs in successfully.

### 3. Create and Manage Message Threads

1. **Create a Thread**:

- On the dashboard (`https://yourdomain.com`), enter:
  - **Thread Name**: e.g., `Project Discussion`
  - **Usernames**: e.g., `bob,carol` (comma-separated).
- Click "Create Thread".

2. **Add Users** (Creator Only):

- In the thread view, enter a username (e.g., `dave`).
- Click "Add".

3. **Remove Users** (Creator Only):

- Click "Remove" next to a participant’s name (e.g., `carol`).

4. **Delete Thread**:

- In the thread list (right sidebar), click "Delete" next to a thread.
- This removes it from your view only; others retain their copy.

**Example**:
- Alice creates a thread named "Project Discussion" with Bob and Carol.
- She adds Dave later and removes Carol.
- Bob deletes the thread from his view, but Alice and Dave still see it.

### 4. Send Messages

1. **Select a Thread**:

- Click a thread from the right sidebar (e.g., "Project Discussion").

2. **Send a Message**:

- Type in the text area (e.g., "Let’s meet tomorrow").
- Optionally attach a file:
  - **Image**: PNG, JPEG, GIF, BMP (displays inline).
  - **Document**: PDF, TXT, DOC, DOCX (appears as a link).
  - Maximum 15MB.
- Click "Send".
- Messages appear instantly for all participants via SocketIO, with a ZKP proof ensuring metadata privacy.

3. **Download Files**:

- Click document links to download decrypted files.
- Images load inline automatically.

**Example**:
- Alice sends "Check this out" with a `plan.pdf` attachment.
- Bob sees the message instantly and clicks the link to download `plan.pdf`.
- Carol sends a `logo.png`, which displays inline in the thread.

### 5. Admin Tasks

1. **Access Admin Panel**:

- Log in as an admin (e.g., `admin`).
- Click "Admin" in the navigation bar.

2. **Manage Users**:

- **Create**: Add a new user with username, email, public key, password, and admin status.
- **Edit**: Update username, email, public key, or admin status.
- **Delete**: Remove a user (except yourself).

**Example**:
- Admin creates user `eve` with email `eve@example.com` and makes her an admin.
- Admin updates Bob’s public key after rotation.
- Admin deletes Carol’s account.

### 6. Key Rotation

1. **Rotate Key**:

- Click "Rotate Key" in the navigation bar.
- Save the new private key displayed (store securely).

2. **Update Login**:

- Use the new private key for future logins.

**Example**:
- Alice rotates her key, saves the new private key, and uses it to generate a new signature for login.

### 7. Run Additional Blockchain Nodes

To join the decentralized network with encrypted DHT:

```bash
cd /path/to/zixt
source venv/bin/activate
python -m app.blockchain
```

Connect to a bootstrap node:

```python
from app.blockchain import Blockchain
import asyncio
blockchain = Blockchain()
bootstrap_nodes = [("192.168.1.100", 8468)]
asyncio.run(blockchain.start_dht(bootstrap_nodes))
```

**Example**:
- Alice runs a node on her server, connecting to Bob’s node at `192.168.1.100:8468` over DTLS.

## 🛡️ Security Guarantees

Zixt is designed with state-of-the-art security:

- **Post-Quantum Cryptography**:
  - Kyber1024 and AES-256-GCM for quantum-resistant encryption with PFS.
  - SPHINCS+ for secure authentication and blockchain signatures.
  - SHA3-512 for robust hashing.

- **Zero-Knowledge Proofs**:
  - zk-SNARKs hide user identities and message metadata, ensuring privacy even in the database and blockchain.

- **Encrypted DHT**:
  - DTLS secures Kademlia DHT traffic, protecting block metadata and preventing eavesdropping.

- **Blockchain**:
  - Immutable ledger with SPHINCS+ signatures and ZKP proofs.
  - Decentralized peer discovery via encrypted DHT.

- **Web Security**:
  - CSRF protection with Flask-WTF.
  - Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
  - HTTPS with Let’s Encrypt and ECDHE ciphers for TLS PFS.

- **Key Management**:
  - SPHINCS+ key rotation every 30 days, with 90-day history.
  - Ephemeral Kyber keys per message.

## 🐛 Troubleshooting

- **Database Issues**:
  - Verify schema: `mysql -u root -p -e "USE zixt_db; DESCRIBE user;"`.
  - Check logs: `sudo tail -f /var/log/mysql/error.log`.

- **SocketIO/Real-Time**:
  - Ensure Redis: `sudo systemctl status redis`.
  - Verify Gunicorn: `ps aux | grep gunicorn`.

- **File Uploads**:
  - Check permissions: `ls -ld app/uploads`.
  - Ensure ≤15MB and correct file types.

- **Email**:
  - Test SMTP: `telnet smtp.gmail.com 465`.
  - Use [Mailtrap](https://mailtrap.io/) for debugging.

- **Nginx**:
  - Validate config: `sudo nginx -t`.
  - Check logs: `sudo tail -f /var/log/nginx/error.log`.

- **DHT**:
  - Ensure port 8468 (UDP) is open: `sudo ufw allow 8468/udp`.
  - Verify DTLS certificates: `ls -l certs/server.crt certs/server.key`.
  - Check connectivity: `netstat -tuln | grep 8468`.

- **ZKP**:
  - Verify circuit files: `ls app/circuits/*.wasm app/circuits/*.zkey`.
  - Check `snarkjs`: `node -e "require('snarkjs')"`.

## 📚 References

- [liboqs](https://openquantumsafe.org)
- [Flask](https://flask.palletsprojects.com)
- [Flask-SocketIO](https://flask-socketio.readthedocs.io)
- [Redis](https://redis.io/docs)
- [Kademlia DHT](https://github.com/bmuller/kademlia)
- [circom](https://docs.circom.io)
- [snarkjs](https://github.com/iden3/snarkjs)
- [OpenSSL DTLS](https://www.openssl.org/docs/man3.0/man7/dtls.html)
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers)
- [Let's Encrypt](https://letsencrypt.org)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Want to join our team of security-minded developers who want to change the world? Please open an issue or submit a pull request with improvements and lets talk!

## 📧 Contact

For questions or support, contact [inquries@zixt.app](mailto:inquries@zixt.app) or open an issue on GitHub.

---

*Zixt: Secure today, safe tomorrow.*
