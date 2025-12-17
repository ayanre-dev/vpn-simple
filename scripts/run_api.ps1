

Write-Host "Starting Control API (Client Daemon)..."
$env:RELAY_HOST="127.0.0.1"
$env:RELAY_PORT="8443"
$env:SHARED_KEY_FILE = "C:\Users\hp\Desktop\vpn-simple\shared.key"
$env:DNS_LISTEN_HOST="127.0.0.1"
$env:DNS_LISTEN_PORT="53530"
$env:SOCKS_LISTEN_HOST="127.0.0.1"
$env:SOCKS_LISTEN_PORT="1080"
$env:PYTHONPATH = "$PSScriptRoot/.."

# If an edge public key exists locally, prefer handshake automatically
$localEdgePk = Join-Path $PSScriptRoot "edge_pk.bin"
if (-not $env:EDGE_PUBKEY_FILE -and (Test-Path $localEdgePk)) {
	$env:EDGE_PUBKEY_FILE = (Resolve-Path $localEdgePk)
	Write-Host "Using EDGE_PUBKEY_FILE=$($env:EDGE_PUBKEY_FILE)"
}
uvicorn backend.src.control_api:app --host 127.0.0.1 --port 8000