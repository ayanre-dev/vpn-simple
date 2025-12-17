$env:ROLE = "edge"
$env:RELAY_HOST = "127.0.0.1"
$env:RELAY_PORT = "8443"
$env:UPSTREAM_DNS = "1.1.1.1"
$env:SHARED_KEY_FILE = Resolve-Path "$PSScriptRoot/../shared.key"
$env:PYTHONPATH = "$PSScriptRoot/.."

# Optional authenticated handshake: generate or use Ed25519 keypair
$skPath = Join-Path $PSScriptRoot "edge_sk.bin"
$pkPath = Join-Path $PSScriptRoot "edge_pk.bin"

function New-EdgeKeypair {
	param(
		[string]$Sk, [string]$Pk
	)
	Write-Host "Generating Ed25519 keypair for handshake..."
	$code = @"
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import sys
sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()
open(sys.argv[1],"wb").write(sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
open(sys.argv[2],"wb").write(pk.public_bytes(Encoding.Raw, PublicFormat.Raw))
print("OK")
"@
	$tmp = Join-Path $env:TEMP "edge_keygen.py"
	Set-Content -Path $tmp -Value $code -Encoding ASCII
	& python $tmp $Sk $Pk
	Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path $skPath) -or -not (Test-Path $pkPath)) {
	try {
		New-EdgeKeypair -Sk $skPath -Pk $pkPath | Out-Null
		Write-Host "Wrote: $skPath and $pkPath"
	}
	catch {
		Write-Warning "Failed to generate Ed25519 keys (is Python+cryptography installed?)."
		Write-Warning "Continuing without handshake; falling back to SHARED_KEY_FILE."
	}
}

if (Test-Path $skPath) {
	$env:EDGE_SK_FILE = (Resolve-Path $skPath)
	Write-Host "Using EDGE_SK_FILE=$($env:EDGE_SK_FILE)"
}

Write-Host "Starting Edge Node..."
python -m backend.src.server