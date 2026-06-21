Write-Host "Installing SentinelAI Agent..."
pip install -r requirements.txt
Copy-Item config.yaml "$env:USERPROFILE\.sentinel-agent\config.yaml" -Force
Write-Host "Run: python agent.py --test"