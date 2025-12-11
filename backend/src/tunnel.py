import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shared.crypto_params import AES_KEY_BYTES, AES_NONCE_BYTES
from shared.utils import encode_frame, decode_frames

class AESTunnel:
    def __init__(self, key: bytes):
        if len(key) != AES_KEY_BYTES:
            raise ValueError("Key must be 32 bytes")
        self.key = key
        self.aes = AESGCM(key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(AES_NONCE_BYTES)
        ct = self.aes.encrypt(nonce, plaintext, aad)
        return nonce + ct

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        nonce = blob[:AES_NONCE_BYTES]
        ct = blob[AES_NONCE_BYTES:]
        return self.aes.decrypt(nonce, ct, aad)

def wrap_frame(tunnel: AESTunnel, payload: bytes) -> bytes:
    return encode_frame(tunnel.encrypt(payload))

def unwrap_frames(tunnel: AESTunnel, buf: bytearray):
    frames = decode_frames(buf)
    return [tunnel.decrypt(f) for f in frames]
