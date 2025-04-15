from oqs import KeyEncapsulation, Signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib
from datetime import datetime, timedelta


class Crypto:
    def __init__(self):
        self.kem = KeyEncapsulation("Kyber1024")
        self.sig = Signature("SPHINCS+-SHAKE-256f-simple")
        self.backend = default_backend()
        self.key_rotation_interval = timedelta(days=30)

    def generate_user_keypair(self):
        public_key = self.sig.generate_keypair()
        private_key = self.sig.export_secret_key()
        return public_key, private_key

    def verify_user(self, public_key, signature, message):
        return self.sig.verify(message, signature, public_key)

    def rotate_user_key(self, user):
        from .models import UserKeyHistory
        old_public_key = user.public_key
        old_private_key = None  # Assume secure storage elsewhere
        new_public_key, new_private_key = self.generate_user_keypair()

        key_history = UserKeyHistory(
            user_id=user.id,
            public_key=old_public_key,
            private_key=old_private_key,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=90)
        )
        user.public_key = new_public_key
        return new_public_key, new_private_key, key_history

    def encapsulate_key(self):
        public_key = self.kem.generate_keypair()
        private_key = self.kem.export_secret_key()
        return public_key, private_key

    def encapsulate_shared_secret(self, recipient_public_key):
        ciphertext, shared_secret = self.kem.encap_secret(recipient_public_key)
        return ciphertext, shared_secret

    def decapsulate_key(self, ciphertext, private_key):
        self.kem.import_secret_key(private_key)
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret

    def encrypt_data(self, data, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=b"zixt-encryption",
            backend=self.backend
        )
        key = hkdf.derive(shared_secret)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_data(self, ciphertext, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=b"zixt-encryption",
            backend=self.backend
        )
        key = hkdf.derive(shared_secret)
        ciphertext = base64.b64decode(ciphertext)
        nonce = ciphertext[:12]
        ciphertext = ciphertext[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext

    def hash_password(self, password):
        return hashlib.sha3_512(password.encode()).hexdigest()