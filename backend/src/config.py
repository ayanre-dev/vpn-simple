import os

class Config:
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "443"))
    ROLE = os.getenv("ROLE", "relay")  # relay | edge
    RELAY_HOST = os.getenv("RELAY_HOST", "127.0.0.1")
    RELAY_PORT = int(os.getenv("RELAY_PORT", PORT))
    SHARED_KEY_FILE = os.getenv("SHARED_KEY_FILE", r"../../shared.key")
    UPSTREAM_DNS = os.getenv("UPSTREAM_DNS", "1.1.1.1")
    CONTROL_API_PORT = int(os.getenv("CONTROL_API_PORT", "8443"))
    TLS_CERT = os.getenv("TLS_CERT")
    TLS_KEY = os.getenv("TLS_KEY")

def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        key = f.read().strip()
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    return key
