

Write-Host "Starting Control API (Client Daemon)..."
$env:RELAY_HOST="127.0.0.1"
$env:RELAY_PORT="8443"
$env:SHARED_KEY_FILE="F:\Users\DELL\Documents\GitHub\vpn-simple\shared.key"
$env:DNS_LISTEN_HOST="127.0.0.1"
$env:DNS_LISTEN_PORT="53530"
$env:SOCKS_LISTEN_HOST="127.0.0.1"
$env:SOCKS_LISTEN_PORT="1080"
$env:PYTHONPATH = "$PSScriptRoot/.."
uvicorn backend.src.control_api:app --host 127.0.0.1 --port 8000