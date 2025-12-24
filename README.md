# vpn-simple
Bootstrap with ./bootstrap.sh

## Optional: Authenticated Key Exchange (no shared.key)

You can enable a per-connection session key using an Ed25519-authenticated X25519 handshake (Noise-like). This removes the need to distribute a symmetric `shared.key` and provides forward secrecy.

- Server auth: Edge signs the handshake with its Ed25519 private key; clients verify using the pinned Ed25519 public key.
- Key derivation: X25519 ECDH + HKDF-SHA256 → 32-byte AES-GCM key.

### Generate keys (Python)

```bash
python - <<'PY'
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()
open('edge_sk.bin','wb').write(sk.private_bytes(Encoding.Raw, PublicFormat.Raw, None))
open('edge_pk.bin','wb').write(pk.public_bytes(Encoding.Raw, PublicFormat.Raw))
print('Wrote edge_sk.bin (32B) and edge_pk.bin (32B)')
PY
```

### Run with handshake

- Edge: set `EDGE_SK_FILE` to the path of `edge_sk.bin`.
- Client (CLI or control API): set `EDGE_PUBKEY_FILE` to the path of `edge_pk.bin`.

When these env vars are set, the client and edge perform the handshake automatically and derive a fresh AES-GCM key per connection. If unset, the system falls back to the existing `shared.key` PSK.

### Important: Run Chrome Through PowerShell (Required)

# You MUST launch Google Chrome using the following command in PowerShell.
# Only then will the browser traffic pass through our SOCKS5 proxy and be captured by our code and logs.

If you open Chrome normally, traffic will *NOT* be routed through the proxy.

# PowerShell Command (Run Exactly As Below)
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server="socks5://127.0.0.1:1080" --user-data-dir="$env:TEMP\chrome-vpn-profile" --no-first-run "https://www.whatismyip.com"

# Why This Is Necessary
- Forces Chrome to use our SOCKS5 proxy (127.0.0.1:1080)
- Ensures all browser traffic goes through our VPN logic
- Allows proper logging, monitoring, and verification
- Uses a separate Chrome profile to avoid conflicts with existing sessions
