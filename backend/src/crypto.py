import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESTunnel:
    """
    Thin AES-GCM wrapper with random 12-byte nonce prepended to ciphertext.
    Key must be 16/24/32 bytes.
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, plaintext, None)
        return nonce + ct  # store nonce prefix

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 13:
            raise ValueError("Ciphertext too short")
        nonce, ct = data[:12], data[12:]
        return AESGCM(self._key).decrypt(nonce, ct, None)