from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class KeyManager:
    def __init__(self):
        self.stanko_private_key = None
        self.stanko_public_key = None
        self.marko_public_key = None

    def generate_keys(self):
        self.stanko_private_key = ec.generate_private_key(ec.SECP256K1())
        self.stanko_public_key = self.stanko_private_key.public_key()

    def verify_public_key(self, public_key_pem):
        try:
            self.marko_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            return True
        except Exception:
            return False

    def reset_keys(self):
        self.stanko_private_key = None
        self.stanko_public_key = None
        self.marko_public_key = None
