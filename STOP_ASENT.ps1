# STOP_ASENT.ps1 - Stop ASENT backend running on port 8000
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[ASENT] Stopping any process listening on port 8000..." -ForegroundColor Cyan

$conns = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($conns) {
    $pids = $conns.OwningProcess | Select-Object -Unique
    foreach ($p in $pids) {
        if ($p -gt 0) {
            Write-Host "[ASENT] Terminating process ID $p..." -ForegroundColor Yellow
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[ASENT] Stopped." -ForegroundColor Green
} else {
    Write-Host "[ASENT] No process running on port 8000." -ForegroundColor Yellow
}
