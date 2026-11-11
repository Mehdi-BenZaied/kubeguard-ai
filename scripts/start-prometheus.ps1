# Run from the project root. Requires Prometheus native Windows release.
# Example folder: tools/prometheus-3.13.5.windows-amd64/prometheus.exe
$executables = @(Get-ChildItem -Path ".\tools" -Filter "prometheus.exe" -Recurse -ErrorAction SilentlyContinue)
if ($executables.Count -eq 0) {
    Write-Error "prometheus.exe was not found. Download and extract the Windows ZIP from https://prometheus.io/download/ into ./tools/."
    exit 1
}
$exe = $executables[0].FullName
New-Item -ItemType Directory -Path ".\data\prometheus" -Force | Out-Null
Write-Host "Running $exe" -ForegroundColor Cyan
& $exe '--config.file=prometheus/prometheus.yml' '--storage.tsdb.path=data/prometheus' '--web.listen-address=127.0.0.1:9090'
