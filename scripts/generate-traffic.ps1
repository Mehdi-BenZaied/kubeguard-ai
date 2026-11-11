# Run from the repository root, while the API is running.
# PowerShell 5.1 and PowerShell 7 compatible.
$base = "http://127.0.0.1:8000/work"

Write-Host "Generating 12 healthy requests..." -ForegroundColor Green
for ($i = 1; $i -le 12; $i++) {
    $null = Invoke-WebRequest -Uri "$base`?delay_ms=50" -UseBasicParsing
}

Write-Host "Generating 8 slow requests..." -ForegroundColor Yellow
for ($i = 1; $i -le 8; $i++) {
    $null = Invoke-WebRequest -Uri "$base`?delay_ms=1000" -UseBasicParsing
}

Write-Host "Generating 4 intentional HTTP 503 errors..." -ForegroundColor Red
for ($i = 1; $i -le 4; $i++) {
    try {
        $null = Invoke-WebRequest -Uri "$base`?delay_ms=50&fail=true" -UseBasicParsing
    } catch {
        Write-Host "Expected HTTP 503 (simulated failure)"
    }
}

Write-Host "Finished: 12 normal + 8 slow + 4 failures." -ForegroundColor Cyan
