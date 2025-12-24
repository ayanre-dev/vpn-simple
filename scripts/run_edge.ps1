$env:ROLE = "edge"
$env:RELAY_HOST = "127.0.0.1"    # change to your VPS/domain
$env:RELAY_PORT = "8443"         # must match relay
$env:UPSTREAM_DNS = "1.1.1.1"    # use campus resolver if you want “inside eduroam” DNS
$env:SHARED_KEY_FILE = "shared.key"
$env:PYTHONPATH = "$PSScriptRoot/.."

Write-Host "Starting Edge Node..."
python -m backend.src.server