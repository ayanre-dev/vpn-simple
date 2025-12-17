Write-Host "Starting VPN System..."

# Start Server in a new process
Start-Process powershell -ArgumentList "-NoExit", "-File", "$PSScriptRoot/run_server.ps1"
Write-Host "Server started in new window."

# Start Edge Node in a new process
Start-Process powershell -ArgumentList "-NoExit", "-File", "$PSScriptRoot/run_edge.ps1"
Write-Host "Edge Node started in new window."

# Start Control API in a new process
Start-Process powershell -ArgumentList "-NoExit", "-File", "$PSScriptRoot/run_api.ps1"
Write-Host "Control API started in new window."

# Start Web UI in a new process
Start-Process powershell -ArgumentList "-NoExit", "-File", "$PSScriptRoot/run_web.ps1"
Write-Host "Web UI started in new window."

Write-Host "To run the client, open a new terminal and run: .\scripts\run_client.ps1"