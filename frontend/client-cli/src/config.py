import os

RELAY_HOST = os.getenv("RELAY_HOST", "127.0.0.1")
RELAY_PORT = int(os.getenv("RELAY_PORT", "443"))
SHARED_KEY_FILE = os.getenv("SHARED_KEY_FILE", "./shared.key")
DNS_QUERY = os.getenv("DNS_QUERY", "example.com")
