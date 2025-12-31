# Test SSH connection via proxy
Write-Host "=== Testing SSH Connection via Proxy ===" -ForegroundColor Cyan

$env:SSH_AUTH_SOCK = "\\.\pipe\ssh-agent-proxy"
Write-Host "SSH_AUTH_SOCK = $env:SSH_AUTH_SOCK"

Write-Host "`nTesting SSH connection to GitHub..." -ForegroundColor Yellow
& "C:\Windows\System32\OpenSSH\ssh.exe" -T git@github.com 2>&1

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
