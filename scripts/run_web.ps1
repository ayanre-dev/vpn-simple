Set-Location "$PSScriptRoot/../frontend/web-ui"

if (-not (Test-Path "node_modules")) {
    Write-Host "Installing dependencies..."
    npm install
}

Write-Host "Starting Web UI..."
$env:VITE_API_BASE = "http://127.0.0.1:8000"
npm run dev -- --host 0.0.0.0 --port 4173