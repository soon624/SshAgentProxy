# Test SSH Agent Proxy
Write-Host "=== Testing SSH Agent Proxy ===" -ForegroundColor Cyan

# Check which ssh-add is being used
Write-Host "`n0. Checking ssh-add locations:" -ForegroundColor Yellow
Write-Host "   Default ssh-add: $(Get-Command ssh-add -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)"
Write-Host "   Windows ssh-add: C:\Windows\System32\OpenSSH\ssh-add.exe"

# List available pipes
Write-Host "`n1. Checking available SSH-related pipes:" -ForegroundColor Yellow
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -like '*ssh*' -or $_.Name -like '*agent*' } | ForEach-Object { Write-Host "   - $($_.Name)" }

# Test with proxy using Windows native ssh-add
Write-Host "`n2. Testing proxy pipe with Windows native ssh-add.exe:" -ForegroundColor Yellow
$env:SSH_AUTH_SOCK = "\\.\pipe\ssh-agent-proxy"
Write-Host "   SSH_AUTH_SOCK = $env:SSH_AUTH_SOCK"

try {
    $result = & "C:\Windows\System32\OpenSSH\ssh-add.exe" -l 2>&1
    Write-Host "   Result: $result"
} catch {
    Write-Host "   Error: $_" -ForegroundColor Red
}

# Test with default pipe using Windows native ssh-add
Write-Host "`n3. Testing default pipe with Windows native ssh-add.exe:" -ForegroundColor Yellow
$env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
Write-Host "   SSH_AUTH_SOCK = $env:SSH_AUTH_SOCK"

try {
    $result = & "C:\Windows\System32\OpenSSH\ssh-add.exe" -l 2>&1
    Write-Host "   Result: $result"
} catch {
    Write-Host "   Error: $_" -ForegroundColor Red
}

# Test without SSH_AUTH_SOCK (default behavior)
Write-Host "`n4. Testing Windows ssh-add.exe without SSH_AUTH_SOCK:" -ForegroundColor Yellow
Remove-Item Env:\SSH_AUTH_SOCK -ErrorAction SilentlyContinue
Write-Host "   SSH_AUTH_SOCK = (not set)"

try {
    $result = & "C:\Windows\System32\OpenSSH\ssh-add.exe" -l 2>&1
    Write-Host "   Result: $result"
} catch {
    Write-Host "   Error: $_" -ForegroundColor Red
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
