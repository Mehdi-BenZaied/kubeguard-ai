
$ErrorActionPreference = "Stop"

$python = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
$syncScript = Join-Path $PSScriptRoot "sync_kubeguard_episodes.py"
$private = Join-Path $env:LOCALAPPDATA "KubeGuardAI\private"
$log = Join-Path $private "scheduled-sync.log"

if (-not (Test-Path -LiteralPath $private -PathType Container)) {
    throw "KubeGuard private directory is missing."
}

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Python executable not found."
}

# Keep a bounded local log history.
if ((Test-Path -LiteralPath $log) -and
    (Get-Item -LiteralPath $log).Length -gt 1048576) {
    Move-Item -LiteralPath $log -Destination "$log.1" -Force
}

Add-Content -LiteralPath $log -Value "`n[$(Get-Date -Format o)] Scheduled sync started"

try {
    & $python $syncScript *>> $log
    $code = $LASTEXITCODE

    if ($code -ne 0) {
        Add-Content -LiteralPath $log -Value "Sync failed: exit code $code"
        exit $code
    }

    Add-Content -LiteralPath $log -Value "Sync completed successfully"
    exit 0
}
catch {
    Add-Content -LiteralPath $log -Value "Sync error: $($_.Exception.Message)"
    exit 1
}
