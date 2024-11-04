from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class MessageManager:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def sign_message(self, message):
        if self.key_manager.stanko_private_key:
            signature = self.key_manager.stanko_private_key.sign(
                message.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return signature.hex()
        return None

    def verify_signature(self, message, signature):
        try:
            self.key_manager.marko_public_key.verify(
                bytes.fromhex(signature),
                message.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False