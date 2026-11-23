
$ErrorActionPreference = "Stop"

$python = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
$analyzer = Join-Path $PSScriptRoot "analyze_synced_kubeguard_episodes.py"

$private = Join-Path $env:LOCALAPPDATA "KubeGuardAI\private"
$log = Join-Path $private "scheduled-analysis.log"

if (-not (Test-Path -LiteralPath $private -PathType Container)) {
    throw "KubeGuard private directory is missing."
}

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Python executable not found."
}

if (-not (Test-Path -LiteralPath $analyzer -PathType Leaf)) {
    throw "KubeGuard analyzer not found."
}

# Rotate the log if it exceeds 1 MiB.
if ((Test-Path -LiteralPath $log) -and
    (Get-Item -LiteralPath $log).Length -gt 1048576) {
    Move-Item -LiteralPath $log -Destination "$log.1" -Force
}

Add-Content -LiteralPath $log -Value "`n[$(Get-Date -Format o)] Scheduled AI analysis started"

try {
    # The Python analyzer independently validates cached episodes,
    # skips existing reports and analyzes at most one new episode.
    & $python $analyzer *>> $log

    $code = $LASTEXITCODE

    if ($code -ne 0) {
        Add-Content -LiteralPath $log -Value "AI analysis failed: exit code $code"
        exit $code
    }

    Add-Content -LiteralPath $log -Value "AI analysis completed successfully"
    exit 0
}
catch {
    Add-Content -LiteralPath $log -Value "AI analysis error: $($_.Exception.Message)"
    exit 1
}
