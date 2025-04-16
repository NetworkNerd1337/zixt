```markdown
# Zixt: Quantum-Secure Messaging Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Ubuntu 24.04](https://img.shields.io/badge/OS-Ubuntu%2024.04-orange.svg)](https://ubuntu.com/)

**Zixt** is a cutting-edge, web-based messaging application engineered for unparalleled security and privacy. Leveraging **post-quantum cryptography** (Kyber1024 and SPHINCS+), Zixt ensures your communications are protected against both classical and quantum threats. It offers real-time multi-user message threads, secure file sharing, a proprietary blockchain ledger, and robust user management, all running on **Ubuntu 24.04** with Flask, SocketIO, Redis, Gunicorn, Nginx, and MySQL, secured by Let's Encrypt HTTPS.

**Current Version**: See [VERSION.md](VERSION.md) for details.  
**Release Notes**: Check [CHANGELOG.md](CHANGELOG.md) for version history.

## 🌟 Features

- **Post-Quantum Cryptography**:
  - **Kyber1024 (ML-KEM)**: Quantum-resistant key encapsulation with perfect forward secrecy (PFS).
  - **SPHINCS+ (SLH-DSA)**: Quantum-secure digital signatures for authentication and blockchain integrity.
  - **AES-256-GCM**: Symmetric encryption with HKDF-SHA3-256-derived keys.
  - **SHA3-512**: Strong hashing for passwords and tokens.

- **Real-Time Messaging**:
  - Multi-user threads for one-on-one or group chats, updated instantly via **SocketIO** and **Redis**.
  - File attachments (images: PNG, JPEG, GIF, BMP; documents: PDF, TXT, DOC, DOCX; ≤15MB) with inline image display and document links.
  - Input sanitization with Bleach to prevent XSS.

- **Blockchain Ledger**:
  - Proprietary blockchain to log encrypted messages, signed with SPHINCS+.
  - Decentralized peer discovery using **Kademlia DHT**.

- **User Management**:
  - Cryptographic pseudonym login with SPHINCS+ key pairs.
  - Self-registration with email verification via SMTP.
  - Admin panel for creating, editing, deleting users, and managing public keys.
  - Key rotation every 30 days, with 90-day key history.

- **Security Enhancements**:
  - **CSRF protection** with Flask-WTF.
  - **Security headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
  - **Perfect Forward Secrecy** via ephemeral Kyber keys and TLS ECDHE ciphers.
  - HTTPS enforced with **Let's Encrypt**.

- **Scalable Architecture**:
  - Flask web framework with Gunicorn WSGI server.
  - Nginx reverse proxy for performance and security.
  - MySQL database for reliable storage.

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

Follow these steps to deploy Zixt on Ubuntu 24.04. Refer to [VERSION.md](VERSION.md) for the current version.

### Step 1: Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Dependencies

Install system packages required for Zixt:

```bash
sudo apt install -y python3 python3-pip python3-venv mysql-server nginx redis-server certbot python3-certbot-nginx build-essential libssl-dev libffi-dev python3-dev cmake ninja-build git
```

### Step 3: Secure MySQL

Set a root password and secure the installation:

```bash
sudo mysql_secure_installation
```

### Step 4: Configure Redis

Ensure Redis is active:

```bash
sudo systemctl enable redis
sudo systemctl start redis
redis-cli ping  # Should return "PONG"
```

### Step 5: Set Up Zixt Application

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

4. **Create Uploads Folder**:

For secure file storage:

```bash
mkdir -p app/uploads
```

5. **Configure MySQL Database**:

Apply the schema:

```bash
sudo mysql -u root -p < setup.sql
```

6. **Set Up Admin User**:

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

- Run:

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

Exit:

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
```

Replace `<base64_public_key>` and `<sha3_512_hash>` with the copied values. Verify:

```sql
SELECT username, email, is_admin, is_verified FROM user;
EXIT;
```

7. **Configure Email Service**:

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
# In EmailService.send_verification_email
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

### Step 6: Configure Gunicorn

Gunicorn runs Zixt as a WSGI server. For security, use a dedicated, non-root user.

1. **Create a Dedicated User**:

```bash
sudo adduser --system --group --no-create-home zixtuser
```

This creates a system user `zixtuser` with minimal privileges.

2. **Set File Permissions**:

Allow `zixtuser` to access the application and share `app/uploads` with Nginx (`www-data`):

```bash
sudo chown -R zixtuser:zixtuser /path/to/zixt
sudo chown zixtuser:www-data /path/to/zixt/app/uploads
sudo chmod 770 /path/to/zixt/app/uploads
sudo chown -R zixtuser:zixtuser /path/to/zixt/venv
sudo chmod -R u+rwx /path/to/zixt/venv
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

Check Gunicorn runs as `zixtuser`:

```bash
ps aux | grep gunicorn
```

**Note**: For development, you may use your own user account instead of `zixtuser`, but this is not recommended for production due to security risks.

### Step 7: Configure Nginx

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

### Step 8: Set Up Let's Encrypt

1. **Obtain Certificate**:

```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

2. **Test Auto-Renewal**:

```bash
sudo certbot renew --dry-run
```

### Step 9: Start Blockchain Node

Run:

```bash
python -m app.blockchain
```

Connect to other nodes:

```python
from app.blockchain import Blockchain
import asyncio
blockchain = Blockchain()
bootstrap_nodes = [("bootstrap.node.ip", 8468)]
asyncio.run(blockchain.start_dht(bootstrap_nodes))
```

## 🔑 Key Generation

Zixt uses SPHINCS+ for authentication.

### General Steps

1. **Run Keygen Script**:

```bash
python scripts/keygen.py
```

Creates:
- `zixt_public_key.txt`: Public key.
- `zixt_private_key.txt`: Private key (store securely).

2. **Save Keys**:

Secure `zixt_private_key.txt` (e.g., password manager).

### Platform-Specific

#### MacBook

```bash
brew install python3
pip3 install oqs
python3 scripts/keygen.py
```

#### Windows

Install Python from [python.org](https://www.python.org/downloads/).

```bash
pip install oqs
python scripts\keygen.py
```

#### iPhone

Use **Pythonista** or generate keys on another device.

#### Android

Install **Termux** (F-Droid):

```bash
pkg install python
pip install oqs
python scripts/keygen.py
```

## 🚀 Usage

### 1. Register a User

1. **Generate Keys**:

```bash
python scripts/keygen.py
```

Output:
```
Public Key (Base64): <your_public_key>
Private Key (Base64): <your_private_key>
```

2. **Register**:

- Visit `https://yourdomain.com/register`.
- Enter:
  - Username: `alice`
  - Email: `alice@example.com`
  - Public Key: `<your_public_key>`
  - Password: Strong password
- Verify email via the sent link.

### 2. Log In

1. **Generate Signature**:

```python
from oqs import Signature
import base64
sig = Signature("SPHINCS+-SHAKE-256f-simple")
sig.import_secret_key(base64.b64decode("<your_private_key>"))
signature = sig.sign("alice".encode())
print(base64.b64encode(signature).decode())
```

2. **Log In**:

- Go to `https://yourdomain.com/login`.
- Enter username, signature, and private key.

### 3. Message Threads

1. **Create Thread**:

- On dashboard, enter:
  - Thread Name: `Team Sync`
  - Usernames: `bob,carol`
- Click "Create Thread".

2. **Manage Thread**:

- Add user: `dave`
- Remove user: `carol`
- Delete thread (your view only).

### 4. Send Messages

- Select thread.
- Type: "Meeting at 3 PM".
- Attach file (≤15MB).
- Click "Send".

### 5. Admin Tasks

- Log in as `admin`.
- Create/edit/delete users via Admin panel.

### 6. Key Rotation

- Click "Rotate Key".
- Save new private key.

### 7. Blockchain Nodes

```bash
python -m app.blockchain
```

## 🛡️ Security Guarantees

- **Encryption**: Kyber1024, AES-256-GCM, PFS.
- **Authentication**: SPHINCS+ signatures.
- **Hashing**: SHA3-512.
- **Blockchain**: SPHINCS+-signed blocks, DHT.
- **Web Security**: CSRF, headers, HTTPS.

## 🐛 Troubleshooting

- **Database**: `sudo tail -f /var/log/mysql/error.log`.
- **SocketIO**: `sudo systemctl status redis`.
- **Files**: `ls -ld app/uploads`.
- **Email**: `telnet smtp.gmail.com 465`.
- **Nginx**: `sudo nginx -t`.

## 📚 References

- [liboqs](https://openquantumsafe.org)
- [Flask](https://flask.palletsprojects.com)
- [SocketIO](https://flask-socketio.readthedocs.io)
- [Redis](https://redis.io/docs)
- [Kademlia](https://github.com/bmuller/kademlia)
- [OWASP](https://owasp.org/www-project-secure-headers)
- [Let's Encrypt](https://letsencrypt.org)

## 📜 License

MIT License. See [LICENSE](LICENSE).

## 🤝 Contributing

Open issues/pull requests on [GitHub](https://github.com/NetworkNerd1337/zixt).

## 📧 Contact

[inquries@zixt.app](mailto:inquries@zixt.app) or GitHub issues for the Zixt repo.

---

*Zixt: Secure today, safe tomorrow.*
```
