from oqs import Signature
import base64

def generate_keypair():
    sig = Signature("SPHINCS+-SHAKE-256f-simple")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return base64.b64encode(public_key).decode(), base64.b64encode(private_key).decode()

if __name__ == "__main__":
    pub, priv = generate_keypair()
    print(f"Public Key (Base64): {pub}")
    print(f"Private Key (Base64): {priv}")
    with open("zixt_public_key.txt", "w") as f:
        f.write(pub)
    with open("zixt_private_key.txt", "w") as f:
        f.write(priv)
    print("Keys saved to zixt_public_key.txt and zixt_private_key.txt")
