$env:ROLE = "edge"
$env:RELAY_HOST = "127.0.0.1"
$env:RELAY_PORT = "8443"
$env:UPSTREAM_DNS = "1.1.1.1"
$env:SHARED_KEY_FILE = Resolve-Path "$PSScriptRoot/../shared.key"
$env:PYTHONPATH = "$PSScriptRoot/.."

Write-Host "Starting Edge Node..."
python -m backend.src.server