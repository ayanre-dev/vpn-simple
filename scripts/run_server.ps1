$env:ROLE = "relay"
$env:RELAY_HOST = "0.0.0.0"
$env:RELAY_PORT = "8443"              # use 443 on VPS if you can
$env:SHARED_KEY_FILE = "shared.key"
$env:PYTHONPATH = "$PSScriptRoot/.."

Write-Host "Starting Server..."
python -m backend.src.server