import os
import json
import base64
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shared.utils import encode_frame, decode_frames

HS_PROTO_ID = b"vpn-simple/hs/x25519+ed25519+hkdf-sha256 v1"


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def _derive_key(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


async def client_handshake(reader, writer, edge_pubkey: bytes) -> bytes:
    """
    Perform a one-way authenticated handshake (server-auth) and return a 32-byte session key.
    Messages are length-prefixed JSON frames sent in plaintext via the relay.
    Flow:
      C -> E: HS1 { c_eph, c_nonce, proto }
      E -> C: HS2 { e_eph, e_nonce, sig }
    Where sig = Ed25519.sign(edge_sk, transcript), transcript = proto || c_eph || e_eph || c_nonce || e_nonce
    """
    c_eph_sk = x25519.X25519PrivateKey.generate()
    c_eph_pk = c_eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    c_nonce = os.urandom(16)

    hs1 = {
        "type": "hs1",
        "proto": HS_PROTO_ID.decode(),
        "c_eph": _b64e(c_eph_pk),
        "c_nonce": _b64e(c_nonce),
    }
    writer.write(encode_frame(json.dumps(hs1).encode()))
    await writer.drain()

    # Read HS2
    buf = bytearray()
    while True:
        data = await reader.read(4096)
        if not data:
            raise ConnectionError("Handshake aborted")
        buf.extend(data)
        frames = decode_frames(buf)
        if frames:
            msg = json.loads(frames[0].decode())
            if msg.get("type") != "hs2":
                raise ConnectionError("Unexpected frame during handshake")
            e_eph = _b64d(msg["e_eph"])  # 32 bytes
            e_nonce = _b64d(msg["e_nonce"])  # 16 bytes
            sig = _b64d(msg["sig"])  # 64 bytes
            break

    # Verify signature
    transcript = HS_PROTO_ID + c_eph_pk + e_eph + c_nonce + e_nonce
    ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(edge_pubkey)
    ed_pub.verify(sig, transcript)

    # Derive key
    shared = c_eph_sk.exchange(x25519.X25519PublicKey.from_public_bytes(e_eph))
    session_key = _derive_key(shared, salt=c_nonce + e_nonce, info=HS_PROTO_ID)
    return session_key


async def edge_handshake(reader, writer, edge_sk_bytes: bytes) -> bytes:
    """
    Edge side of the handshake. Returns 32-byte session key.
    """
    # Read HS1
    buf = bytearray()
    while True:
        data = await reader.read(4096)
        if not data:
            raise ConnectionError("Handshake aborted")
        buf.extend(data)
        frames = decode_frames(buf)
        if frames:
            msg = json.loads(frames[0].decode())
            if msg.get("type") != "hs1":
                raise ConnectionError("Unexpected frame during handshake")
            if msg.get("proto") != HS_PROTO_ID.decode():
                raise ConnectionError("Protocol mismatch")
            c_eph = _b64d(msg["c_eph"])  # 32 bytes
            c_nonce = _b64d(msg["c_nonce"])  # 16 bytes
            break

    # Prepare response
    e_eph_sk = x25519.X25519PrivateKey.generate()
    e_eph_pk = e_eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    e_nonce = os.urandom(16)

    transcript = HS_PROTO_ID + c_eph + e_eph_pk + c_nonce + e_nonce
    ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(edge_sk_bytes)
    sig = ed_sk.sign(transcript)

    hs2 = {
        "type": "hs2",
        "e_eph": _b64e(e_eph_pk),
        "e_nonce": _b64e(e_nonce),
        "sig": _b64e(sig),
    }
    writer.write(encode_frame(json.dumps(hs2).encode()))
    await writer.drain()

    # Derive key
    shared = e_eph_sk.exchange(x25519.X25519PublicKey.from_public_bytes(c_eph))
    session_key = _derive_key(shared, salt=c_nonce + e_nonce, info=HS_PROTO_ID)
    return session_key
